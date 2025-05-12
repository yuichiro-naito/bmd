/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Yuichiro Naito
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <netinet/in.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bmd.h"
#include "inspect.h"
#include "log.h"
#include "server.h"
#include "vm.h"

static int
usage(int argc __unused, char *argv[])
{
	printf(
	    "usage: %s [-f config_file] <subcommand>\n"
	    "  boot [-c] <name>         : boot VM\n"
	    "  install [-c] <name>      : install VM from ISO image\n"
	    "  shutdown <name>          : ACPI shutdown VM\n"
	    "  poweroff <name>          : poweroff VM\n"
	    "  reset <name>             : reset VM\n"
	    "  console <name>           : connect to com1 port\n"
	    "  com[1-4] <name>          : connect to com[1-4] port\n"
	    "  showconsole <name>       : show console\n"
	    "  showvgaport <name>       : show vgaport\n"
	    "  showconfig [<name>]      : show VM config\n"
	    "  inspect <name>           : inspect and print installcmd & loadcmd\n"
	    "  run [-i] [-s] <name>     : directly run with serial console\n"
	    "  list [-r] [-s <colname>] : list VM name & status\n",
	    argv[0]);
	return 1;
}

struct vm_conf_entry *
lookup_vm_conf(const char *name)
{
	struct vm_conf_entry *conf_ent, *cen, *ret = NULL;
	struct vm_conf_list list = LIST_HEAD_INITIALIZER();

	if (load_config_file(&list, false) < 0) {
		printf("failed to load VM config files\n");
		return NULL;
	}

	LIST_FOREACH_SAFE(conf_ent, &list, next, cen)
		if (strcmp(conf_ent->conf.name, name) == 0)
			ret = conf_ent;
		else
			free_vm_conf_entry(conf_ent);
	if (ret)
		LIST_NEXT(ret, next) = NULL;
	return ret;
}

static int
do_inspect(char *name)
{
	int i;
	struct vm_conf_entry *conf_ent;
	struct vm_conf *conf;
	char *p, *q;
	const bool flags[2] = { true, false };
	const char *types[2] = { "installcmd", "loadcmd" };
	sigset_t nmask, omask;

	if ((conf_ent = lookup_vm_conf(name)) == NULL) {
		printf("no such VM %s\n", name);
		return 1;
	}
	conf = &conf_ent->conf;

	sigemptyset(&nmask);
	sigaddset(&nmask, SIGPIPE);
	sigprocmask(SIG_BLOCK, &nmask, &omask);

	for (i = 0; i < 2; i++) {
		set_install(conf, flags[i]);
		q = p = inspect(conf);
		if (p == NULL) {
			printf("%s = (null)\n", types[i]);
		} else {
			printf("%s = ", types[i]);
			while (*p != '\0') {
				switch (*p) {
				case '\n':
					putchar('\\');
					putchar('n');
					break;
				default:
					putchar(*p);
				}
				p++;
			}
			putchar('\n');
		}
		free(q);
	}

	free_vm_conf_entry(conf_ent);
	free_id_list();
	return 0;
}

static int
recv_size(int sock, uint32_t *sz, int *fd)
{
	int rc;
	uint32_t t;
	size_t n = 0;
	bool fd_set = false;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char buf[4];

	memset(&msg, 0, sizeof(msg));
	memset(&iov, 0, sizeof(iov));

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_controllen = CMSG_SPACE(sizeof(int));
	msg.msg_control = calloc(1, msg.msg_controllen);
	if (msg.msg_control == NULL)
		return -1;

retry:
	iov.iov_base = buf + n;
	iov.iov_len = sizeof(buf) - n;
	while ((rc = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC)) < 0)
		if (errno != EINTR && errno != EAGAIN)
			break;

	if (rc <= 0)
		goto ret;
	n += rc;

	if (fd && !fd_set) {
		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg && cmsg->cmsg_level == SOL_SOCKET &&
		    cmsg->cmsg_type == SCM_RIGHTS)
			memcpy(fd, CMSG_DATA(cmsg), sizeof(int));
		else
			*fd = -1;
		fd_set = true;
	}

	if (n < sizeof(buf))
		goto retry;

	if (sz) {
		memcpy(&t, buf, sizeof(uint32_t));
		*sz = ntohl(t);
	}
	rc = n;
ret:
	free(msg.msg_control);
	return rc;
}

static nvlist_t *
send_recv(nvlist_t *cmd)
{
	int s, fd = -1, rc;
	nvlist_t *res = NULL;
	uint32_t sz;

	if ((s = connect_to_server(gl_conf)) < 0) {
		printf("cannot connect to %s\n", gl_conf->cmd_socket_path);
		return NULL;
	}

	sz = htonl(nvlist_size(cmd));
	while ((rc = send(s, &sz, sizeof(sz), 0)) < 0)
		if (errno != EINTR)
			break;
	if (rc <= 0) {
		printf("cannot send to bmd\n");
		goto end;
	}
	if (nvlist_send(s, cmd) < 0) {
		printf("cannot send to bmd\n");
		goto end;
	}

	if (recv_size(s, &sz, &fd) < 0) {
		printf("server doen't return the size of message\n");
		goto end;
	}

	if ((res = nvlist_recv(s, 0)) == NULL) {
		printf("server returns null\n");
		goto end;
	}

	if (fd != -1)
		nvlist_add_number(res, FD_KEY, fd);

end:
	close(s);
	return res;
}

#define NVGET(v, key) nvlist_get_string(*((nvlist_t *const *)v), #key)

static int
cmp_by_id(const void *a, const void *b)
{
	return strtol(NVGET(a, id), NULL, 10) - strtol(NVGET(b, id), NULL, 10);
}

static int
cmp_by_id_r(const void *a, const void *b)
{
	return strtol(NVGET(b, id), NULL, 10) - strtol(NVGET(a, id), NULL, 10);
}

static int
cmp_by_name(const void *a, const void *b)
{
	return strcmp(NVGET(a, name), NVGET(b, name));
}

static int
cmp_by_name_r(const void *a, const void *b)
{
	return strcmp(NVGET(b, name), NVGET(a, name));
}

static int
cmp_by_ncpu(const void *a, const void *b)
{
	return strtol(NVGET(a, ncpu), NULL, 10) -
	    strtol(NVGET(b, ncpu), NULL, 10);
}

static int
cmp_by_ncpu_r(const void *a, const void *b)
{
	return strtol(NVGET(b, ncpu), NULL, 10) -
	    strtol(NVGET(a, ncpu), NULL, 10);
}

static long
calc_memsize(const char *ms)
{
	long n;
	char *p;

	n = strtol(ms, &p, 10);
	switch (*p) {
	case 'k':
	case 'K':
		return n * 1024;
	case 'm':
	case 'M':
		return n * 1024 * 1024;
	case 'g':
	case 'G':
		return n * 1024 * 1024 * 1024;
	case 't':
	case 'T':
		return n * 1024 * 1024 * 1024 * 1024;
	}
	return n;
}

static int
cmp_by_memory(const void *a, const void *b)
{
	long la, lb;
	la = calc_memsize(NVGET(a, memory));
	lb = calc_memsize(NVGET(b, memory));
	return (la > lb) ? 1 : (la == lb) ? 0 : -1;
}

static int
cmp_by_memory_r(const void *a, const void *b)
{
	long la, lb;
	la = calc_memsize(NVGET(a, memory));
	lb = calc_memsize(NVGET(b, memory));
	return (lb > la) ? 1 : (lb == la) ? 0 : -1;
}

static int
cmp_by_loader(const void *a, const void *b)
{
	return strcmp(NVGET(a, loader), NVGET(b, loader));
}

static int
cmp_by_loader_r(const void *a, const void *b)
{
	return strcmp(NVGET(b, loader), NVGET(a, loader));
}

static int
cmp_by_state(const void *a, const void *b)
{
	return strcmp(NVGET(a, state), NVGET(b, state));
}

static int
cmp_by_state_r(const void *a, const void *b)
{
	return strcmp(NVGET(b, state), NVGET(a, state));
}

static int
cmp_by_owner(const void *a, const void *b)
{
	return strcmp(NVGET(a, owner), NVGET(b, owner));
}

static int
cmp_by_owner_r(const void *a, const void *b)
{
	return strcmp(NVGET(b, owner), NVGET(a, owner));
}

#undef NVGET

static struct compar_entry {
	const char *name;
	int (*compar)(const void *, const void *);
	int (*compar_r)(const void *, const void *);
} compar_list[] = { { "id", cmp_by_id, cmp_by_id_r },
	{ "name", cmp_by_name, cmp_by_name_r },
	{ "ncpu", cmp_by_ncpu, cmp_by_ncpu_r },
	{ "memory", cmp_by_memory, cmp_by_memory_r },
	{ "loader", cmp_by_loader, cmp_by_loader_r },
	{ "state", cmp_by_state, cmp_by_state_r },
	{ "owner", cmp_by_owner, cmp_by_owner_r } };

static int
do_list(int col, bool reverse)
{
	int ret = 0;
	nvlist_t **l, *cmd, *res = NULL;
	size_t i, count;
	const static char *fmt = "%4s%20s%5s%7s%10s%12s%12s\n";
	const nvlist_t *const *list;

	cmd = nvlist_create(0);
	nvlist_add_string(cmd, "command", "list");

	if ((res = send_recv(cmd)) == NULL) {
		ret = 1;
		goto end;
	}

	if (nvlist_get_bool(res, "error")) {
		printf("%s\n", nvlist_get_string(res, "reason"));
		goto end;
	}

	printf(fmt, "id", "name", "ncpu", "memory", "loader", "state", "owner");
	printf(fmt, "---", "-------------------", "----", "------", "---------",
	    "-----------", "----------");

	if (!nvlist_exists(res, "vm_list"))
		goto end;

	list = nvlist_get_nvlist_array(res, "vm_list", &count);
	if ((l = malloc(sizeof(nvlist_t *) * count)) == NULL) {
		fprintf(stderr, "failed to allocate memory\n");
		ret = 1;
		goto end;
	}
	memcpy(l, list, sizeof(nvlist_t *) * count);
	qsort(l, count, sizeof(nvlist_t *),
	    reverse ? compar_list[col].compar_r : compar_list[col].compar);
	for (i = 0; i < count; i++) {
		printf(fmt, nvlist_get_string(l[i], "id"),
		    nvlist_get_string(l[i], "name"),
		    nvlist_get_string(l[i], "ncpu"),
		    nvlist_get_string(l[i], "memory"),
		    nvlist_get_string(l[i], "loader"),
		    nvlist_get_string(l[i], "state"),
		    nvlist_get_string(l[i], "owner"));
	}
	free(l);

end:
	nvlist_destroy(cmd);
	nvlist_destroy(res);
	free_global_vars();
	free_gl_conf();
	return ret;
}

/*
 * attach console
 */
static int
do_console(const char *name, const char *port)
{
	int fd, ret = 0;
	nvlist_t *cmd, *res = NULL;

	cmd = nvlist_create(0);
	nvlist_add_string(cmd, "command", "showconsole");
	nvlist_add_string(cmd, "port", port ? port : "com1");
	nvlist_add_string(cmd, "name", name);
	nvlist_add_number(cmd, "sigtrigger_pid", getpid());
	nvlist_add_number(cmd, "sigtrigger_num", SIGHUP);

	if ((res = send_recv(cmd)) == NULL) {
		ret = 1;
		goto end;
	}

	if (nvlist_get_bool(res, "error")) {
		ret = 1;
		printf("%s\n", nvlist_get_string(res, "reason"));
		goto end;
	}

	if (nvlist_exists_number(res, FD_KEY)) {
		fd = nvlist_take_number(res, FD_KEY);
		if (attach_console(fd) < 0) {
			fprintf(stderr, "failed to setup console\n");
			ret = 1;
		}
		close(fd);
	} else {
		fprintf(stderr, "failed to open console\n");
		ret = 1;
	}

end:
	nvlist_destroy(cmd);
	nvlist_destroy(res);
	free_global_vars();
	free_gl_conf();
	return ret;
}

/*
 * boot_style= 0: showconsole, 1: boot, 2: install
 */
static int
do_boot_console(const char *name, unsigned int boot_style, bool console,
    bool show)
{
	int ret;
	nvlist_t *cmd, *res = NULL;
	const char *cons = NULL;
	const static char *command[] = { "showconsole", "boot", "install" };

	if (boot_style > nitems(command))
		return 1;

	cmd = nvlist_create(0);
	nvlist_add_string(cmd, "command", command[boot_style]);
	nvlist_add_string(cmd, "name", name);
	nvlist_add_string(cmd, "port", "com1");

	if ((res = send_recv(cmd)) == NULL) {
		ret = 1;
		goto end;
	}

	if (nvlist_get_bool(res, "error")) {
		ret = 1;
		printf("%s\n", nvlist_get_string(res, "reason"));
		goto end;
	}

	if (nvlist_exists_string(res, "console"))
		cons = nvlist_get_string(res, "console");

	if (nvlist_exists_number(res, FD_KEY))
		close(nvlist_take_number(res, FD_KEY));

	if (show)
		printf("%s\n", cons ? cons : "no console");

	if (console)
		do_console(name, NULL);

	ret = 0;
end:
	nvlist_destroy(cmd);
	nvlist_destroy(res);
	free_global_vars();
	free_gl_conf();
	return ret;
}

static int
do_show_vgaport(const char *name)
{
	int ret;
	nvlist_t *cmd, *res = NULL;
	const char *vgaport = NULL;

	cmd = nvlist_create(0);
	nvlist_add_string(cmd, "command", "showvgaport");
	nvlist_add_string(cmd, "name", name);

	if ((res = send_recv(cmd)) == NULL) {
		ret = 1;
		goto end;
	}

	if (nvlist_get_bool(res, "error")) {
		ret = 1;
		printf("%s\n", nvlist_get_string(res, "reason"));
		goto end;
	}

	if (nvlist_exists_string(res, "vgaport"))
		vgaport = nvlist_get_string(res, "vgaport");

	printf("%s\n", vgaport);
	ret = 0;
end:
	nvlist_destroy(cmd);
	nvlist_destroy(res);
	free_global_vars();
	free_gl_conf();
	return ret;
}

static int
do_showconfig(const char *name)
{
	struct vm_conf_entry *conf_ent, *cen;
	struct vm_conf_list list = LIST_HEAD_INITIALIZER();
	int count = 0;

	LOG_OPEN_PERROR();

	if (load_config_file(&list, false) < 0) {
		printf("failed to load VM config files\n");
		return 1;
	}

	LIST_FOREACH_SAFE(conf_ent, &list, next, cen) {
		if (name == NULL || strcmp(conf_ent->conf.name, name) == 0) {
			if (count)
				fputs("\n", stdout);
			dump_vm_conf(&conf_ent->conf, stdout);
			count++;
		}
		free_vm_conf_entry(conf_ent);
	}

	remove_plugins();
	free_id_list();
	free_parser_objects();
	free_global_vars();
	free_gl_conf();

	return 0;
}

static int
sub_boot_install(int argc, char *argv[])
{
	char c, *name;
	bool console = false;
	int boot_style = strcmp(argv[0], "install") == 0 ? 2 : 1;

	while ((c = getopt(argc, argv, "c")) != -1) {
		switch (c) {
		case 'c':
			console = true;
			break;
		default:
			return 2;
		}
	}

	if ((name = argv[optind]) == NULL)
		return 2;
	return do_boot_console(name, boot_style, console, false);
}

static int
sub_send_recv(int argc, char *argv[])
{
	int ret;
	nvlist_t *cmd, *res;

	if (argc < 2)
		return 2;

	cmd = nvlist_create(0);
	nvlist_add_string(cmd, "command",
	    strcmp(argv[0], "stop") == 0 ? "shutdown" : argv[0]);
	nvlist_add_string(cmd, "name", argv[1]);

	if ((res = send_recv(cmd)) == NULL) {
		ret = 1;
		goto end;
	}

	if (nvlist_get_bool(res, "error")) {
		ret = 1;
		printf("%s\n", nvlist_get_string(res, "reason"));
		goto end;
	}
	ret = 0;
end:
	nvlist_destroy(cmd);
	nvlist_destroy(res);
	return ret;
}

static int
sub_com(int argc, char *argv[])
{
	if (argc < 2)
		return 2;
	return do_console(argv[1], argv[0]);
}

static int
sub_console(int argc, char *argv[])
{
	if (argc < 2)
		return 2;
	return do_console(argv[1], NULL);
}

static int
sub_showconsole(int argc, char *argv[])
{
	if (argc < 2)
		return 2;
	return do_boot_console(argv[1], 0, false, true);
}

static int
sub_showvgaport(int argc, char *argv[])
{
	if (argc < 2)
		return 2;
	return do_show_vgaport(argv[1]);
}

static int
sub_showconfig(int argc, char *argv[])
{
	return do_showconfig(argc > 1 ? argv[1] : NULL);
}

static int
sub_inspect(int argc, char *argv[])
{
	if (argc < 2)
		return 2;
	return do_inspect(argv[1]);
}

static int
sub_run(int argc, char *argv[])
{
	char c, *name;
	bool install, single;
	install = single = false;
	while ((c = getopt(argc, argv, "is")) != -1) {
		switch (c) {
		case 'i':
			install = true;
			break;
		case 's':
			single = true;
			break;
		default:
			return 2;
		}
	}
	if ((name = argv[optind]) == NULL)
		return 2;
	return direct_run(name, install, single);
}

static int
sub_list(int argc, char *argv[])
{
	char c, *key = NULL;
	unsigned int i;
	bool r = false;
	while ((c = getopt(argc, argv, "rs:")) != -1) {
		switch (c) {
		case 'r':
			r = true;
			break;
		case 's':
			key = optarg;
			break;
		default:
			return 2;
		}
	}
	if (key == NULL)
		i = 0;
	else {
		for (i = 0; i < nitems(compar_list); i++)
			if (strcmp(key, compar_list[i].name) == 0)
				break;
		if (i == nitems(compar_list))
			i = 0;
	}
	return do_list(i, r);
}

/* Must be sorted by name */
static struct subcommand {
	const char *name;
	int (*func)(int, char *[]);
} subcommand_table[] = {
	{ "boot", sub_boot_install },
	{ "com1", sub_com },
	{ "com2", sub_com },
	{ "com3", sub_com },
	{ "com4", sub_com },
	{ "console", sub_console },
	{ "inspect", sub_inspect },
	{ "install", sub_boot_install },
	{ "list", sub_list },
	{ "poweroff", sub_send_recv },
	{ "reset", sub_send_recv },
	{ "run", sub_run },
	{ "showconfig", sub_showconfig },
	{ "showconsole", sub_showconsole },
	{ "showvgaport", sub_showvgaport },
	{ "shutdown", sub_send_recv },
	{ "start", sub_boot_install },
	{ "stop", sub_send_recv },
};

static int
compare_subcommand(const void *a, const void *b)
{
	const char *name = a;
	const struct subcommand *sbc = b;
	return strcasecmp(name, sbc->name);
}

int
control(int argc, char *argv[])
{
	int oargc, rc;
	char **oargv;
	struct subcommand *sbc;

	oargc = argc;
	oargv = argv;

	if (argc > 2 && strcmp(argv[1], "-f") == 0) {
		free(gl_conf->config_file);
		gl_conf->config_file = strdup(argv[2]);
		argv += 2;
		argc -= 2;
	}

	if (argc < 2)
		return usage(oargc, oargv);

	argv++;
	argc--;

	if (load_config_file(NULL, 1) < 0)
		fprintf(stderr, "failed to load %s. use default value\n",
		    gl_conf->config_file);

	sbc = bsearch(argv[0], subcommand_table, nitems(subcommand_table),
	    sizeof(subcommand_table[0]), compare_subcommand);
	if (sbc == NULL)
		return usage(oargc, oargv);

	rc = sbc->func(argc, argv);
	if (rc == 2)
		return usage(oargc, oargv);
	return rc;
}
