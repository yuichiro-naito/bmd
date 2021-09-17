#include <sys/queue.h>
#include <sys/wait.h>
#include <sys/nv.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include "vars.h"
#include "log.h"
#include "conf.h"
#include "parser.h"
#include "vm.h"
#include "command.h"
#include "bmd.h"

extern SLIST_HEAD(vm_conf_head, vm_conf_entry) vm_conf_list;
extern struct global_conf gl_conf;

int
usage(int argc, char *argv[])
{
	printf(
	    "usage: %s <subcommand>\n"
	    "  boot <name>          : boot VM\n"
	    "  install <name>       : install VM from ISO image\n"
	    "  shutdown <name>      : ACPI shutdown VM\n"
	    "  reload <name>        : reload VM\n"
	    "  console <name>       : connect to com port\n"
	    "  run [-i] [-s] <name> : directly run with serial console\n"
	    "  list                 : list VM name & status\n",
	    argv[0]);
	return 1;
}

struct vm_conf *
lookup_vm_conf(const char *name)
{
	struct vm_conf_entry *conf_ent;
	struct vm_conf *conf = NULL;

	if (load_config_files(&vm_conf_list) < 0) {
		printf("failed to load VM config files\n");
		return NULL;
	}

	SLIST_FOREACH (conf_ent, &vm_conf_list, next)
		if (strcmp(conf_ent->conf.name, name) == 0) {
			conf = &conf_ent->conf;
			break;
		}

	return conf;
}

int
direct_run(const char *name, bool install, bool single)
{
	int fd;
	int status;
	struct vm_conf *conf;
	struct vm_conf_entry *conf_ent;
	struct vm_entry *vm_ent;
	struct vm *vm;

	LOG_OPEN_PERROR();

	fd = open(gl_conf.plugin_dir, O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		ERR("can not open %s\n", gl_conf.plugin_dir);
		return 1;
	}
	gl_conf.plugin_fd = fd;

	if (load_plugins() < 0)
		return 1;

	conf = lookup_vm_conf(name);
	if (conf == NULL) {
		ERR("no such VM %s\n", name);
		return 1;
	}

	free(conf->comport);
	conf->comport = strdup("stdio");
	conf->install = install;
	set_single_user(conf, single);

	conf_ent = realloc(conf, sizeof(*conf_ent));
	if (conf_ent == NULL) {
		free_vm_conf(conf);
		return 1;
	}

	vm_ent = create_vm_entry(conf_ent);
	if (vm_ent == NULL) {
		free_vm_conf(conf);
		return 1;
	}
	vm = &vm_ent->vm;

	if (start_vm(vm) < 0)
		goto err;
	call_plugins(vm_ent);
	if (waitpid(vm->pid, &status, 0) < 0)
		goto err;

	if (vm->state == LOAD) {
		if (exec_bhyve(vm) < 0)
			goto err;
		call_plugins(vm_ent);
		if (waitpid(vm->pid, &status, 0) < 0)
			goto err;
	}

	cleanup_vm(vm);
	call_plugins(vm_ent);
	free_vm_entry(vm_ent);
	remove_plugins();
	return 0;
err:
	cleanup_vm(vm);
	call_plugins(vm_ent);
	free_vm_entry(vm_ent);
	remove_plugins();
	return 1;
}

int
do_console(char *name)
{
	struct vm_conf *conf = NULL;
	int i;
	char *port;

	if ((conf = lookup_vm_conf(name)) == NULL) {
		printf("no such VM %s\n", name);
		return 1;
	}

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
control(int argc, char *argv[])
{
	int s, ret = 0;
	nvlist_t *cmd, *res = NULL;

	if (argc < 2)
		return usage(argc, argv);

	if (argc == 3 && strcmp(argv[1], "console") == 0)
		return do_console(argv[2]);

	if (strcmp(argv[1], "run") == 0) {
		char c, *name;
		bool install, single;
		install = single = false;
		while ((c = getopt(argc-1, argv+1, "is")) != -1) {
			switch(c) {
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
		if ((name = argv[optind+1]) == NULL)
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
				 strcmp(argv[1], "reload") == 0 ||
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

	nvlist_send(s, cmd);

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
		list = nvlist_get_nvlist_array(res, "vm_list", &count);
		for (i = 0; i < count; i++) {
			printf("%20s %s\n", nvlist_get_string(list[i], "name"),
			    nvlist_get_string(list[i], "state"));
		}
	}

end:
	close(s);
	nvlist_destroy(cmd);
	nvlist_destroy(res);
	return ret;
}
