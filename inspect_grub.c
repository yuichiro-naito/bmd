#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#if __FreeBSD_version >= 1400095
#include <sys/queue_mergesort.h>
#endif
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "conf.h"
#include "inspect.h"
#include "vm.h"

struct proc_pipe {
	pid_t pid;
	char *vm_name;
	char *mapfile;
	int fd;
	char *buf;
	size_t size;
	size_t nread;
};

struct disk_info {
	SLIST_ENTRY(disk_info) next;
	char *orig_name;
	char *disk_name;
	char *part_name;
	char *slice_name;
	int part_index;
	int slice_index;
};

SLIST_HEAD(disk_info_head, disk_info);

#define NEWLINE  "\r"
#define PROMPT   "grub> "

static struct disk_info *
create_disk_info()
{
	return calloc(1, sizeof(struct disk_info));
}

static void
free_disk_info(struct disk_info *di)
{
	if (di == NULL)
		return;
	free(di->orig_name);
	free(di->disk_name);
	free(di->part_name);
	free(di->slice_name);
	free(di);
}

static void
free_disk_info_list(struct disk_info_head *head)
{
	struct disk_info *di, *din;
	SLIST_FOREACH_SAFE(di, head, next, din)
		free_disk_info(di);
}

static int
pp_poll_read(struct proc_pipe *pp, int timeout)
{
	int rc;
	struct pollfd pfd = {
		.fd = pp->fd,
		.events = POLLIN
	};

	while ((rc = poll(&pfd, 1, timeout)) < 0)
		if (errno != EAGAIN && errno != EINTR)
			break;
	return rc;
}

static int
strip_csi(char *str, size_t size)
{
	char *p, *q, *r, *e;

	p = q = str;
	e = str + size;
	while (p < e) {
		if (p[0] == '\e' && p + 1 < e && p[1] == '[') {
			for (r = p + 2; (r < e) && (isnumber(*r) || *r == ';');
			     r++);
			if (r == e)
				break;
			switch(*r) {
			case 'A':
			case 'B':
			case 'C':
			case 'D':
			case 'E':
			case 'F':
			case 'G':
			case 'H':
			case 'I':
			case 'J':
			case 'K':
			case 'M':
			case 'S':
			case 'T':
			case 'f':
			case 'h':
			case 'i':
			case 'l':
			case 'm':
			case 'n':
			case 's':
			case 'u':
				p = r + 1;
				continue;
			}
		}
		*q++ = *p++;
	}
	return q - str;
}

static int
pp_read(struct proc_pipe *pp)
{
	int rc;
	ssize_t n;

	if (pp->nread < pp->size) {
		if ((rc = pp_poll_read(pp, 1000)) < 0)
			return -1;
		if (rc == 0)
			goto ret;
		while ((n = read(pp->fd, &pp->buf[pp->nread],
				 pp->size - pp->nread)) < 0)
			if (errno != EAGAIN && errno != EINTR)
				break;
		if (n < 0)
			return -1;
		if (n == 0)
			goto ret;
		pp->nread = strip_csi(pp->buf, pp->nread + n);
	}

ret:
	return pp->nread;
}

static int
strip_newline(char *str)
{
	char *p, *q;

	p = q = str;
	while (*p != '\0') {
		switch (*p) {
		case '\r':
		case '\n':
			p++;
			break;
		default:
			*q++ = *p++;
		}
	}
	*q = '\0';

	return q - str;
}

static int
pp_expect(struct proc_pipe *pp, const char *expect, char *buf, size_t size)
{
	int rc, n;
	char *p;
retry:
	if ((rc = pp_read(pp)) < 0)
		return -1;

	if (rc == 0)
		return 0;

	if (strnstr(pp->buf, "Error", pp->nread))
		return -1;

	if ((p = strnstr(pp->buf, expect, pp->nread)) == NULL) {
		/* Invalid buffer read size */
		if (pp->nread > pp->size)
			return -1;
		if (pp->nread == pp->size) {
			n = pp->size / 2;
			memcpy(pp->buf, &pp->buf[n], n);
			pp->nread = n;
		}
		goto retry;
	}

	if (buf != NULL && size > 0) {
		n = p - pp->buf;
		if (n > size - 1) {
			n = size - 1;
			memcpy(buf, pp->buf, n);
			buf[n] = '\0';
			memcpy(pp->buf, p, pp->nread - n);
			pp->nread -= n;
			return strip_newline(buf);
		} else {
			memcpy(buf, pp->buf, n);
			buf[n] = '\0';
		}
	}

	p += strlen(expect);
	n = p - pp->buf;
	memcpy(pp->buf, p, pp->nread - n);
	pp->nread -= n;

	return buf ? strip_newline(buf) : n;
}

static struct proc_pipe *
pp_create(void)
{
	struct proc_pipe *ret;

	if ((ret = calloc(1, sizeof(struct proc_pipe))) == NULL)
		return NULL;
	ret->size = 4 * 1024;
	if ((ret->buf = calloc(1, ret->size)) == NULL) {
		free(ret);
		return NULL;
	}
	return ret;
}

static void
pp_close(struct proc_pipe *pp)
{
	int status;
	close(pp->fd);
	wait4(pp->pid, &status, WEXITED, NULL);
	sysctlbyname("hw.vmm.destroy", NULL, 0, pp->vm_name,
		     strlen(pp->vm_name));
}

#define pp_printf(p, fmt, ...)  dprintf((p)->fd, fmt, __VA_ARGS__)

static void
pp_free(struct proc_pipe *pp)
{
	if (pp == NULL)
		return;
	free(pp->buf);
	free(pp->vm_name);
	if (pp->mapfile) {
		unlink(pp->mapfile);
		free(pp->mapfile);
	}
	free(pp);
}

static int
spawn_grub(struct proc_pipe *pp)
{
	pid_t pid;
	int i, pfd[2];
	char *argv[8];

	if (pipe2(pfd, O_CLOEXEC | O_NONBLOCK) < 0)
		return -1;

	if ((pid = fork()) < 0)
		goto err;
	if (pid == 0) {
		close(pfd[0]);
		setenv("TERM", "xterm", 1);
		i = 0;
		argv[i++] = "grub-bhyve";
		argv[i++] = "-n";
		argv[i++] = "-e";
		argv[i++] = "-m";
		argv[i++] = pp->mapfile;
		argv[i++] = pp->vm_name;
		argv[i++] = NULL;

		dup2(pfd[1], 0);
		dup2(pfd[1], 1);
		dup2(pfd[1], 2);

		execv(LOCALBASE"/sbin/grub-bhyve", argv);
		exit(1);
	}
	pp->pid = pid;
	pp->fd = pfd[0];
	close(pfd[1]);
	return 0;

err:
	close(pfd[0]);
	close(pfd[1]);
	return -1;
}

#if __FreeBSD_version < 1400071
static int
compare_disk_info(void *thunk __unused, const void *l, const void *r)
#else
static int
compare_disk_info(const void *l, const void *r, void *thunk __unused)
#endif
{
	const struct disk_info *a, *b;
	int c;

	a = *(const struct disk_info **)l;
	b = *(const struct disk_info **)r;

	if (a->disk_name == NULL && b->disk_name == NULL)
		return 0;
	if (a->disk_name == NULL)
		return 1;
	if (b->disk_name == NULL)
		return -1;
	if ((c = strcmp(a->disk_name, b->disk_name)) != 0)
		return c;

	if (a->part_name == NULL && b->part_name == NULL)
		return 0;
	if (a->part_name == NULL)
		return 1;
	if (b->part_name == NULL)
		return -1;
	if ((c = strcmp(a->part_name, b->part_name)) != 0)
		return c;
	if ((c = a->part_index - b->part_index) != 0)
		return c;

	if (a->slice_name == NULL && b->slice_name == NULL)
		return 0;
	if (a->slice_name == NULL)
		return 1;
	if (b->slice_name == NULL)
		return -1;
	if ((c = strcmp(a->slice_name, b->slice_name)) != 0)
		return c;
	return a->slice_index - b->slice_index;
}

#if __FreeBSD_version < 1400095
static void
sort_disk_info_list(struct disk_info_head *list, int nlist)
{
	int i;
	struct disk_info *di, *array[nlist];

	if (nlist == 0)
		return;

	i = 0;
	SLIST_FOREACH(di, list, next)
		array[i++] = di;

#if __FreeBSD_version < 1400071
	qsort_r(array, nlist, sizeof(struct disk_info *), NULL, compare_disk_info);
#else
	qsort_r(array, nlist, sizeof(struct disk_info *), compare_disk_info, NULL);
#endif
	for (i = 0; i < nlist - 1; i++)
		SLIST_NEXT(array[i], next) = array[i + 1];
	SLIST_NEXT(array[nlist - 1], next) = NULL;

	SLIST_FIRST(list) = array[0];
}
#endif

static int
parse_disks(char *line, struct disk_info_head *list, int nlist)
{
	struct disk_info *di;
	char *s, *e, *n, t;
	char *token;

	/*
	 * example:
	 *
	 *  (hd0,openbsd12)
	 *  (hd0,gpt2,bsd1)
	 *   ^            ^
	 *   |            |
	 *   s ==>        e
	 */

	e = line;
	while (*e != '\0') {
		for (; *e != '(' && *e != '\0'; e++);
		if (*e == '\0' || e[1] == '\0')
			break;
		e++;
		s = e;
		for (; *e != ')'  && *e != '\0'; e++);
		if (*e == '\0')
			break;

		t = *e;
		if ((di = create_disk_info()) == NULL)
			return -1;
		*e = '\0';
		if ((di->orig_name = strdup(s)) == NULL)
			goto err;

		if ((token = strsep(&s, ",")) == NULL)
			goto next;
		if ((di->disk_name = strdup(token)) == NULL)
			goto err;
		if ((token = strsep(&s, ",")) == NULL)
			goto next;
		for (n = token; !(isnumber(*n)) && *n != '\0'; n++);
		if ((di->part_name = strndup(token, n - token)) == NULL)
			goto err;
		di->part_index = strtol(n, NULL, 10);
		if ((token = strsep(&s, ",")) == NULL)
			goto next;
		for (n = token; !(isnumber(*n)) && *n != '\0'; n++);
		if ((di->slice_name = strndup(token, n - token)) == NULL)
			goto err;
		di->slice_index = strtol(n, NULL, 10);

	next:
		SLIST_INSERT_HEAD(list, di, next);
		nlist++;
		*e = t;
	}

#if __FreeBSD_version >= 1400095
	SLIST_MERGESORT(list, NULL, compare_disk_info, disk_info, next);
#else
	sort_disk_info_list(list, nlist);
#endif
	return 0;
err:
	free_disk_info(di);
	return -1;
}

static bool
look_for_filename(char *buf, const char *name)
{
	char *p;
	if ((p = strstr(buf, name)) == NULL)
		return false;

	if (p != buf && p[-1] != ' ')
		return false;

	p += strlen(name);
	if (*p != '\0' && *p != ' ' && *p != '\r' && *p != '\n')
		return false;

	return true;
}

static char *
get_diskname(const char *kernel, struct disk_info *di)
{
	char *dn;

	if (strcmp(kernel, NETBSD_KERNEL) == 0) {
		if (asprintf(&dn, "dk0%c", 'a' + di->part_index - 1) < 0)
			return NULL;
		return dn;
	}

	if (di->part_name && strcmp(di->part_name, "openbsd") == 0) {
		if (asprintf(&dn, "sd0%c", 'a' + di->part_index - 1) < 0)
			return NULL;
		return dn;
	}

	if (di->slice_name == NULL)
		return strdup("sd0a");

	if (asprintf(&dn, "sd0%c", 'a' + di->slice_index - 1) < 0)
		return NULL;

	return dn;
}

int
inspect_with_grub(struct inspection *ins)
{
	char buf[1024], *dn;
	struct disk_info_head list;
	struct disk_info *di;
	struct proc_pipe *pp;
	const static struct {
		const char *kernel;
		const char *method;
	} *p, kernels[] = {
		{OPENBSD_UPGRADE_KERNEL, "kopenbsd"},
		{OPENBSD_KERNEL, "kopenbsd"},
		{NETBSD_KERNEL, "knetbsd"},
	};

	if ((pp = pp_create()) == NULL)
		return -1;

	if (write_mapfile(ins->conf, &pp->mapfile) < 0 ||
	    asprintf(&pp->vm_name, "ins-%s", ins->conf->name) < 0 ||
	    spawn_grub(pp) < 0)
		goto err2;

	SLIST_INIT(&list);

	if (pp_expect(pp, PROMPT, NULL, 0) < 0 ||
	    pp_printf(pp, "%s\n", "ls") < 0 ||
	    pp_expect(pp, NEWLINE, NULL, 0) < 0 ||
	    pp_expect(pp, PROMPT, buf, sizeof(buf)) < 0 ||
	    parse_disks(buf, &list, 0) < 0)
		goto err;

	SLIST_FOREACH(di, &list, next) {
		if (strcmp(di->disk_name, "hd0") ||
		    (di->part_name &&
		     strcmp(di->part_name, "openbsd") &&
		     strcmp(di->part_name, "gpt")))
			continue;
		if (pp_printf(pp, "ls (%s)/\n", di->orig_name) < 0 ||
		    pp_expect(pp, NEWLINE, NULL, 0) < 0 ||
		    pp_expect(pp, PROMPT, buf, sizeof(buf)) < 0)
			goto err;

		ARRAY_FOREACH(p, kernels) {
			if (!look_for_filename(buf, p->kernel))
				continue;
			if ((dn = get_diskname(p->kernel, di)) == NULL)
				goto err;
			if (asprintf(&ins->load_cmd,
				     "%s%s -h com0 -r %s (%s)/%s"
				     "\nboot\n",
				     p->method,
				     ins->single_user ? " -s" : "",
				     dn,
				     di->orig_name, p->kernel) < 0) {
				free(dn);
				goto err;
			}
			free(dn);
			goto loop_end;
		}
	}
loop_end:
	if (pp_printf(pp, "%s\n", "exit") < 0 ||
	    pp_expect(pp, NEWLINE, NULL, 0) < 0)
		goto err;

	free_disk_info_list(&list);
	pp_close(pp);
	pp_free(pp);
	return 0;
err:
	free_disk_info_list(&list);
	pp_printf(pp, "%s\n", "exit");
	pp_close(pp);
err2:
	pp_free(pp);
	return -1;
}
