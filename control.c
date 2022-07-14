#include <sys/queue.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/nv.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#include "vars.h"
#include "log.h"
#include "conf.h"
#include "parser.h"
#include "vm.h"
#include "server.h"
#include "bmd.h"
#include "inspect.h"

extern struct global_conf gl_conf;

int
usage(int argc, char *argv[])
{
	printf(
	    "usage: %s <subcommand>\n"
	    "  boot <name>          : boot VM\n"
	    "  install <name>       : install VM from ISO image\n"
	    "  shutdown <name>      : ACPI shutdown VM\n"
	    "  poweroff <name>      : poweroff VM\n"
	    "  reset <name>         : reset VM\n"
	    "  console <name>       : connect to com port\n"
	    "  inspect <name>       : inspect and print installcmd & loadcmd\n"
	    "  run [-i] [-s] <name> : directly run with serial console\n"
	    "  list                 : list VM name & status\n",
	    argv[0]);
	return 1;
}

static struct vm_conf_entry *
lookup_vm_conf(const char *name)
{
	struct vm_conf_entry *conf_ent, *cen, *ret = NULL;
	struct vm_conf_head vm_conf_list = LIST_HEAD_INITIALIZER();

	if (load_config_files(&vm_conf_list) < 0) {
		printf("failed to load VM config files\n");
		return NULL;
	}

	LIST_FOREACH_SAFE (conf_ent, &vm_conf_list, next, cen)
		if (strcmp(conf_ent->conf.name, name) == 0)
			ret = conf_ent;
		else
			free_vm_conf(&conf_ent->conf);

	return ret;
}

int
read_stdin(struct vm *vm)
{
	int n, rc;
	ssize_t size;
	char buf[4 * 1024];

	while ((size = read(0, buf, sizeof(buf))) < 0)
		if (errno != EINTR && errno != EAGAIN)
			break;
	if (size == 0)
		return 0;
	if (size > 0 && vm->infd != -1) {
		n = 0;
		while (n < size) {
			if ((rc = write(vm->infd, buf + n, size - n)) < 0)
				if (errno != EINTR && errno != EAGAIN)
					break;
			if (rc > 0)
				n += rc;
		}
	}

	return size;
}

int
direct_run(const char *name, bool install, bool single)
{
	int i, status;
	struct vm_conf *conf;
	struct vm_conf_entry *conf_ent;
	struct vm_entry *vm_ent;
	struct vm *vm;
	struct kevent ev, ev2[3];

	LOG_OPEN_PERROR();

	if ((gl_conf.kq = kqueue()) < 0) {
		ERR("%s\n", "can not open kqueue");
		return 1;
	}

	if (load_plugins() < 0)
		return 1;

	conf_ent = lookup_vm_conf(name);
	if (conf_ent == NULL) {
		ERR("no such VM %s\n", name);
		return 1;
	}

	conf = &conf_ent->conf;
	free(conf->comport);
	conf->comport = strdup("stdio");
	conf->install = install;
	set_single_user(conf, single);

	vm_ent = create_vm_entry(conf_ent);
	if (vm_ent == NULL) {
		free_vm_conf(conf);
		return 1;
	}
	vm = &vm_ent->vm;

	if (VM_START(vm_ent) < 0)
		goto err;
	i = 0;
	EV_SET(&ev2[i++], vm->pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT,
	       0, vm_ent);
	if (vm->state == LOAD && conf->loader_timeout >= 0)
		EV_SET(&ev2[i++], 1, EVFILT_TIMER, EV_ADD | EV_ONESHOT,
		       NOTE_SECONDS, vm->conf->loader_timeout, vm_ent);
	if (vm->infd != -1)
		EV_SET(&ev2[i++], 0, EVFILT_READ, EV_ADD, 0, 0, vm_ent);
	while (kevent(gl_conf.kq, ev2, i, NULL, 0, NULL) < 0)
		if (errno != EINTR) {
			ERR("failed to wait process (%s)\n", strerror(errno));
			VM_POWEROFF(vm_ent);
			goto err;
		}
	call_plugins(vm_ent);

wait:
	while (kevent(gl_conf.kq, NULL, 0, &ev, 1, NULL) < 0)
		if (errno != EINTR) {
			ERR("kevent failure (%s)\n", strerror(errno));
			VM_POWEROFF(vm_ent);
			goto err;
		}

	switch (ev.filter) {
	case EVFILT_READ:
		read_stdin(vm);
		goto wait;
	case EVFILT_PROC:
		if (waitpid(ev.ident, &status, 0) < 0)
			goto err;
		if (ev.ident != vm->pid)
			goto wait;
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
			break;
		goto err;
	case EVFILT_TIMER:
	default:
		VM_POWEROFF(vm_ent);
		goto err;
	}

	if (vm->state == LOAD) {
		if (VM_START(vm_ent) < 0)
			goto err;
		call_plugins(vm_ent);
		if (waitpid(vm->pid, &status, 0) < 0)
			goto err;
	}

	VM_CLEANUP(vm_ent);
	call_plugins(vm_ent);
	free_vm_entry(vm_ent);
	remove_plugins();
	return 0;
err:
	VM_CLEANUP(vm_ent);
	call_plugins(vm_ent);
	free_vm_entry(vm_ent);
	remove_plugins();
	return 1;
}

int
do_console(char *name)
{
	struct vm_conf_entry *conf_ent;
	struct vm_conf *conf;
	int i;
	char *port;

	if ((conf_ent = lookup_vm_conf(name)) == NULL) {
		printf("no such VM %s\n", name);
		return 1;
	}
	conf = &conf_ent->conf;

	/* A null modem device has at least 6 characters. */
	if (conf->comport == NULL ||
	    (i = strlen(conf->comport) - 1 ) < 5) {
		printf("VM %s doesn't have com port\n", name);
		return 1;
	}

	port = strdup(conf->comport);
	if (port == NULL) {
		printf("failed to allocate memory\n");
		return 1;
	}

	switch (port[i]) {
	case 'A':
		port[i] = 'B';
		break;
	case 'B':
		port[i] = 'A';
		break;
	default:
		break;
	}

	execlp("/usr/bin/cu", "cu", "-l", port, NULL);
	printf("failed to execute cu\n");
	return 1;
}

int
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

	free_vm_conf(&conf_ent->conf);
	return 0;
}

static int
compare_by_name(const void *a, const void *b)
{
#define GETNAME(v) nvlist_get_string(*((nvlist_t **)v), "name")
	return strcmp(GETNAME(a), GETNAME(b));
#undef GETNAME
}

int
control(int argc, char *argv[])
{
	int s, ret = 0;
	nvlist_t *cmd, *res = NULL;
	int32_t sz;

	if (argc < 2)
		return usage(argc, argv);

	if (argc == 3 && strcmp(argv[1], "console") == 0)
		return do_console(argv[2]);

	if (argc == 3 && strcmp(argv[1], "inspect") == 0)
		return do_inspect(argv[2]);

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

	cmd = nvlist_create(0);

	if (strcmp(argv[1], "start") == 0)
		argv[1] = "boot";
	else if (strcmp(argv[1], "stop") == 0)
		argv[1] = "shutdown";

	if (argc == 2 && strcmp(argv[1], "list") == 0) {
		nvlist_add_string(cmd, "command", argv[1]);
	} else if (argc == 3 && (strcmp(argv[1], "boot") == 0 ||
				 strcmp(argv[1], "install") == 0 ||
				 strcmp(argv[1], "reset") == 0 ||
				 strcmp(argv[1], "poweroff") == 0 ||
				 strcmp(argv[1], "shutdown") == 0)) {
		nvlist_add_string(cmd, "command", argv[1]);
		nvlist_add_string(cmd, "name", argv[2]);
	} else {
		return usage(argc, argv);
	}

	if ((s = connect_to_server(&gl_conf)) < 0) {
		printf("can not connect to %s\n", gl_conf.cmd_sock_path);
		return 1;
	}

	sz = htonl(nvlist_size(cmd));
retry:
	ret = send(s, &sz, sizeof(sz), 0);
	if (ret < 0) {
		if (errno == EINTR)
			goto retry;
		printf("can not send to bmd\n");
		goto end;
	}
	ret = nvlist_send(s, cmd);
	if (ret < 0) {
		printf("can not send to bmd\n");
		goto end;
	}

	res = nvlist_recv(s, 0);
	if (res == NULL) {
		printf("server returns null\n");
		goto end;
	}

	if (nvlist_get_bool(res, "error")) {
		printf("%s\n", nvlist_get_string(res, "reason"));
		goto end;
	}

	if (argc == 2 && strcmp(argv[1], "list") == 0) {
		size_t i, count;
		const struct nvlist *const *list;

#define FORMAT "%20s%5s%7s%10s%12s\n"

		printf(FORMAT, "name", "ncpu", "memory", "loader", "state");
		printf(FORMAT, "-------------------",
		       "----", "------", "---------", "-----------");

		list = nvlist_get_nvlist_array(res, "vm_list", &count);
		qsort((void *)list, count, sizeof(nvlist_t *), compare_by_name);
		for (i = 0; i < count; i++) {
			printf(FORMAT,
			       nvlist_get_string(list[i], "name"),
			       nvlist_get_string(list[i], "ncpu"),
			       nvlist_get_string(list[i], "memory"),
			       nvlist_get_string(list[i], "loader"),
			       nvlist_get_string(list[i], "state"));
		}
#undef FORMAT
	}

end:
	close(s);
	nvlist_destroy(cmd);
	nvlist_destroy(res);
	return ret;
}
