#include <sys/queue.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include "log.h"
#include "vm.h"
#include "server.h"
#include "bmd.h"
#include "inspect.h"

int control(int, char *[]);
struct vm_conf_entry *lookup_vm_conf(const char *);

static int
usage(int argc __unused, char *argv[])
{
	printf(
	    "usage: %s [-f config_file] <subcommand>\n"
	    "  boot [-c] <name>     : boot VM\n"
	    "  install [-c] <name>  : install VM from ISO image\n"
	    "  shutdown <name>      : ACPI shutdown VM\n"
	    "  poweroff <name>      : poweroff VM\n"
	    "  reset <name>         : reset VM\n"
	    "  console <name>       : connect to com port\n"
	    "  showcomport <name>   : show comport\n"
	    "  showvgaport <name>   : show vgaport\n"
	    "  showconfig [<name>]  : show VM config\n"
	    "  inspect <name>       : inspect and print installcmd & loadcmd\n"
	    "  run [-i] [-s] <name> : directly run with serial console\n"
	    "  list                 : list VM name & status\n",
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

	LIST_FOREACH_SAFE (conf_ent, &list, next, cen)
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
compare_by_name(const void *a, const void *b)
{
#define GETNAME(v) nvlist_get_string(*((nvlist_t *const *)v), "name")
	return strcmp(GETNAME(a), GETNAME(b));
#undef GETNAME
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
	int s, fd, rc;
	nvlist_t *res = NULL;
	uint32_t sz;

	if ((s = connect_to_server(gl_conf)) < 0) {
		printf("cannot connect to %s\n", gl_conf->cmd_sock_path);
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

static int
do_list(void)
{
	int ret = 0;
	nvlist_t **l, *cmd, *res = NULL;
	size_t i, count;
	const static char *fmt = "%20s%5s%7s%10s%12s%12s\n";
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

	printf(fmt, "name", "ncpu", "memory", "loader", "state", "owner");
	printf(fmt, "-------------------",
	       "----", "------", "---------", "-----------", "----------");

	if (!nvlist_exists(res, "vm_list"))
		goto end;

	list = nvlist_get_nvlist_array(res, "vm_list", &count);
	if ((l = malloc(sizeof(nvlist_t *) * count)) == NULL) {
		fprintf(stderr, "failed to allocate memory\n");
		ret = 1;
		goto end;
	}
	memcpy(l, list, sizeof(nvlist_t *) * count);
	qsort(l, count, sizeof(nvlist_t *), compare_by_name);
	for (i = 0; i < count; i++) {
		printf(fmt,
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
 * boot_style= 0: showcomport, 1: boot, 2: install
 */
static int
do_boot_console(const char *name, unsigned int boot_style, bool console, bool show)
{
	int fd, ret = 0;
	nvlist_t *cmd, *res = NULL;
	const char *comport = NULL;
	const static char *command[] = {"showcomport", "boot", "install"};

	if (boot_style > sizeof(command)/sizeof(command[0]))
		return -1;

	cmd = nvlist_create(0);
	nvlist_add_string(cmd, "command", command[boot_style]);
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

	if (nvlist_exists_string(res, "comport"))
		comport = nvlist_get_string(res, "comport");

	if (show)
		printf("%s\n", comport ? comport : "no com port");

	if (nvlist_exists_number(res, FD_KEY)) {
		fd = nvlist_take_number(res, FD_KEY);
		if (console && attach_console(fd) < 0) {
			fprintf(stderr, "failed to setup console\n");
			ret = 1;
		}
		close(fd);
	} else {
		if (console) {
			fprintf(stderr, "failed to open console\n");
			ret = 1;
		}
	}

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
	int ret = 0;
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

	LIST_FOREACH_SAFE (conf_ent, &list, next, cen) {
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
	free_global_vars();
	free_gl_conf();

	return 0;
}

int
control(int argc, char *argv[])
{
	int boot_style, ret = 0;
	nvlist_t *cmd, *res = NULL;

	if (argc < 2)
		return usage(argc, argv);

	if (argc > 2 && strcmp(argv[1], "-f") == 0) {
		free(gl_conf->config_file);
		gl_conf->config_file = strdup(argv[2]);
		argv += 2;
		argc += 2;
	}

	if (load_config_file(NULL, 1) < 0)
		fprintf(stderr, "failed to load %s. use default value\n",
			gl_conf->config_file);

	if (strcmp(argv[1], "list") == 0)
		return do_list();

	if (strcmp(argv[1], "showconfig") == 0)
		return do_showconfig(argv[2]);

	if (strcmp(argv[1], "showvgaport") == 0)
		return do_show_vgaport(argv[2]);

	if (argc == 3) {
		if (strcmp(argv[1], "inspect") == 0)
			return do_inspect(argv[2]);
		if (strcmp(argv[1], "console") == 0)
			return do_boot_console(argv[2], 0, true, false);
		if (strcmp(argv[1], "showcomport") == 0)
			return do_boot_console(argv[2], 0, false, true);
	}

	if (strcmp(argv[1], "boot") == 0 || strcmp(argv[1], "start") == 0)
		boot_style = 1;
	else if (strcmp(argv[1], "install") == 0)
		boot_style = 2;
	else
		boot_style = 0;

	if (boot_style > 0) {
		char c, *name;
		bool console = false;
		while ((c = getopt(argc - 1, argv + 1, "c")) != -1) {
			switch (c) {
			case 'c':
				console = true;
				break;
			default:
				return usage(argc, argv);
			}
		}
		if ((name = argv[optind + 1]) == NULL)
			return usage(argc, argv);
		return do_boot_console(name, boot_style, console, false);
	}

	if (strcmp(argv[1], "run") == 0) {
		char c, *name;
		bool install, single;
		install = single = false;
		while ((c = getopt(argc - 1, argv + 1, "is")) != -1) {
			switch (c) {
			case 'i':
				install = true;
				break;
			case 's':
				single = true;
				break;
			default:
				return usage(argc, argv);
			}
		}
		if ((name = argv[optind + 1]) == NULL)
			return usage(argc, argv);
		return direct_run(name, install, single);
	}

	if (argc == 3 && (strcmp(argv[1], "reset") == 0 ||
			  strcmp(argv[1], "poweroff") == 0 ||
			  strcmp(argv[1], "stop") == 0 ||
			  strcmp(argv[1], "shutdown") == 0)) {
		cmd = nvlist_create(0);
		nvlist_add_string(cmd, "command",
				  strcmp(argv[1], "stop") == 0 ?
				  "shutdown" : argv[1]);
		nvlist_add_string(cmd, "name", argv[2]);
	} else
		return usage(argc, argv);

	if ((res = send_recv(cmd)) == NULL) {
		ret = 1;
		goto end;
	}

	if (nvlist_get_bool(res, "error")) {
		ret = 1;
		printf("%s\n", nvlist_get_string(res, "reason"));
		goto end;
	}

end:
	nvlist_destroy(cmd);
	nvlist_destroy(res);
	return ret;
}
