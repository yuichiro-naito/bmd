#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include "vars.h"
#include "tap.h"
#include "conf.h"
#include "parser.h"

SLIST_HEAD(, vm_conf) vm_conf_list = SLIST_HEAD_INITIALIZER();
SLIST_HEAD(, vm) vm_list = SLIST_HEAD_INITIALIZER();

char *config_directory = "./bhyved.d";

int
load_config_files()
{
	char *path;
	DIR *d;
	struct dirent *ent;
	struct vm_conf *conf;

	d = opendir(config_directory);
	if (d == NULL) {
		fprintf(stderr,"can not open %s\n", config_directory);
		return -1;
	}

	while ((ent = readdir(d)) != NULL) {
		if (ent->d_namlen > 0 &&
		    ent->d_name[0] == '.')
			continue;
		if (asprintf(&path, "%s/%s", config_directory, ent->d_name) < 0)
			continue;
		conf = parse_file(path);
		free(path);
		if (conf == NULL)
			continue;
		SLIST_INSERT_HEAD(&vm_conf_list, conf, next);
	}

	closedir(d);

	SLIST_FOREACH(conf, &vm_conf_list, next) {
		dump_vm_conf(conf);
	}

	return 0;
}

int
start_virtual_machines()
{
	struct vm_conf *conf;
	struct vm *vm;

	SLIST_FOREACH(conf, &vm_conf_list, next) {
		vm = malloc(sizeof(struct vm));
		vm->conf = conf;
		vm->state = STOP;
		vm->pid = -1;
		SLIST_INSERT_HEAD(&vm_list, vm, next);
	}
	return 0;
}

int
event_loop()
{
	return 0;
}

int
stop_virtual_machines()
{
	return 0;
}

int
bhyve_load(struct vm_conf *conf)
{
	pid_t pid;
	char *args[9];
	int status;

	args[0] = "/usr/sbin/bhyveload";
	args[1] = "-c";
	args[2] = conf->comport;
	args[3] = "-m";
	args[4] = conf->memory;
	args[5] = "-d";
	args[6] = STAILQ_FIRST(&conf->disks)->path;
	args[7] = conf->name;
	args[8] = NULL;

	pid = fork();
	if (pid > 0) {
	} else if (pid == 0) {
		execv(args[0],args);
		fprintf(stderr, "can not exec %s\n", args[0]);
		exit(1);
	} else {
		fprintf(stderr, "can not fork (%s)\n", strerror(errno));
		exit(1);
	}

	if (waitpid(pid, &status, 0) < 0) {
		fprintf(stderr, "wait error (%s)\n", strerror(errno));
		exit(1);
	}

	return 0;
}

int
remove_taps(struct vm_conf *conf)
{
	int s;
	struct net_conf *nc;

	s = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (s < 0)
		return -1;

	STAILQ_FOREACH(nc, &conf->nets, next)
		if (nc->tap != NULL) {
			destroy_tap(s, nc->tap);
			free(nc->tap);
			nc->tap = NULL;
		}

	close(s);
	return 0;
}

int
activate_taps(struct vm_conf *conf)
{
	int s;
	struct net_conf *nc;

	s = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (s < 0)
		return -1;
	STAILQ_FOREACH(nc, &conf->nets, next)
		activate_tap(s, nc->tap);
	close(s);
	return 0;
}

int
assign_taps(struct vm_conf *conf)
{
	int s;
	struct net_conf *nc;

	s = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (s < 0)
		return -1;

	STAILQ_FOREACH(nc, &conf->nets, next)
		if (create_tap(s, &nc->tap) < 0 ||
		    add_to_bridge(s, nc->bridge, nc->tap) < 0) {
			fprintf(stderr, "failed to create tap\n");
			remove_taps(conf);
			close(s);
			return -1;
		}

	close(s);
	return 0;
}

int
exec_bhyve(struct vm_conf *conf)
{
	struct disk_conf *dc;
	struct iso_conf *ic;
	struct net_conf *nc;
	pid_t pid;
	int i, pcid;
	char **args;

	args = malloc(sizeof(char*) *
		      (17
		       + conf->ndisks * 2
		       + conf->nisoes * 2
		       + conf->nnets * 2));
	if (args == NULL)
		return -1;

	i = 0;
	args[i++] = "/usr/sbin/bhyve";
	args[i++] = "-A";
	args[i++] = "-H";
	args[i++] = "-u";
	args[i++] = "-w";
	args[i++] = "-c";
	args[i++] = conf->ncpu;
	args[i++] = "-m";
	args[i++] = conf->memory;
	args[i++] = "-l";
	asprintf(&args[i++], "com1,%s", conf->comport);
	args[i++] = "-s";
	args[i++] = "0,hostbridge";
	args[i++] = "-s";
	args[i++] = "1,lpc";

	pcid = 2;
	STAILQ_FOREACH(dc, &conf->disks, next) {
		args[i++] = "-s";
		asprintf(&args[i++], "%d,%s,%s", pcid++, dc->type, dc->path);
	}
	STAILQ_FOREACH(ic, &conf->isoes, next) {
		args[i++] = "-s";
		asprintf(&args[i++], "%d,%s,%s", pcid++, ic->type, ic->path);
	}
	STAILQ_FOREACH(nc, &conf->nets, next) {
		args[i++] = "-s";
		asprintf(&args[i++], "%d,%s,%s", pcid++, nc->type, nc->tap);
	}
	args[i++] = conf->name;
	args[i++] = NULL;

	pid = fork();
	if (pid > 0) {
		free(args[10]);
		free(args);
		conf->pid = pid;
	} else if (pid == 0) {
		execv(args[0],args);
		fprintf(stderr, "can not exec %s\n", args[0]);
		exit(1);
	} else {
		fprintf(stderr, "can not fork (%s)\n", strerror(errno));
		exit(1);
	}

	return 0;
}

int
destroy_vm(struct vm_conf *conf)
{
	pid_t pid;
	int status;
	char *args[4];

	args[0]="/usr/sbin/bhyvectl";
	args[1]="--destroy";
	asprintf(&args[2], "--vm=%s", conf->name);
	args[3]=NULL;

	pid = fork();
	if (pid > 0) {
		free(args[2]);
	} else if (pid == 0) {
		execv(args[0],args);
		fprintf(stderr, "can not exec %s\n", args[0]);
		exit(1);
	} else {
		fprintf(stderr, "can not fork (%s)\n", strerror(errno));
		exit(1);
	}

	if (waitpid(pid, &status, 0) < 0) {
		fprintf(stderr, "wait error (%s)\n", strerror(errno));
		exit(1);
	}

	return 0;
}

struct vm_conf *dummy_conf()
{
	struct vm_conf *conf;

	conf = create_vm_conf("freebsd");
	if (conf == NULL) {
		fprintf(stderr, "can not create vm_conf\n");
		return NULL;
	}

	set_ncpu(conf, 2);
	set_memory_size(conf, "2048m");
	add_disk_conf(conf,
		      "virtio-blk",
		      "/dev/zvol/zpool/images/freebsd");
	add_iso_conf(conf,
		     "ahci-cd",
		     "/zpool/iso/FreeBSD-13.0-BETA2-amd64-disc1.iso");
	add_net_conf(conf,
		     "virtio-net",
		     "bridge0");

	return conf;
}

int
do_bhyve(struct vm_conf *conf)
{
	int status;

	if (assign_taps(conf) < 0)
		return -1;
reload:
	if (activate_taps(conf) < 0 ||
	    bhyve_load(conf) < 0 ||
	    exec_bhyve(conf) < 0)
		goto err;

	if (waitpid(conf->pid, &status, 0) < 0) {
		fprintf(stderr, "wait error (%s)\n", strerror(errno));
		exit(1);
	}

	if (WIFEXITED(status) && (WEXITSTATUS(status) == 0))
	    goto reload;

	remove_taps(conf);
	destroy_vm(conf);
	return 0;
err:
	remove_taps(conf);
	destroy_vm(conf);
	return -1;
}

int
main(int argc, char *argv[])
{
#if 0
	struct vm_conf *conf = parse_file("./freebsd");
	dump_vm_conf(conf);
	do_bhyve(conf);
	free_vm_conf(conf);
#endif
	if (load_config_files() < 0 ||
	    start_virtual_machines())
		return 1;

	event_loop();

	stop_virtual_machines();
	return 0;
}
