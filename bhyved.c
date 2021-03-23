#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#include "vars.h"
#include "tap.h"
#include "conf.h"
#include "parser.h"

struct vm_conf_entry {
	struct vm_conf conf;
	SLIST_ENTRY(vm_conf_entry) next;
};

struct vm_entry {
	struct vm vm;
	SLIST_ENTRY(vm_entry) next;
};

SLIST_HEAD(, vm_conf_entry) vm_conf_list = SLIST_HEAD_INITIALIZER();
SLIST_HEAD(, vm_entry) vm_list = SLIST_HEAD_INITIALIZER();

char *config_directory = "./conf.d";
int kq;

int
write_mapfile(struct vm *vm)
{
	int fd, i;
	char *fn;
	FILE *fp;
	struct disk_conf *dc;
	struct iso_conf *ic;
	struct vm_conf *conf;

	if (asprintf(&fn, "/tmp/bhyved.%s.%d.XXXXXX",
		     vm->conf->name, getpid()) < 0)
		return -1;

	fd = mkstemp(fn);
	if (fd < 0) {
		fprintf(stderr,"can't create mapfile\n");
		free(fn);
		return -1;
	}

	vm->mapfile = fn;

	fp = fdopen(fd, "w+");
	if (fp == NULL) {
		fprintf(stderr,"can't fdopen mapfile\n");
		unlink(fn);
		vm->mapfile = NULL;
		free(fn);
		return -1;
	}

	conf = vm->conf;

	i = 0;
	STAILQ_FOREACH(dc, &conf->disks, next)
		if (fprintf(fp, "(hd%d) %s\n", i++, dc->path) < 0)
			goto err;

	i = 0;
	STAILQ_FOREACH(ic, &conf->isoes, next)
		if (fprintf(fp, "(cd%d) %s\n", i++, ic->path) < 0)
			goto err;

	fclose(fp);
	return 0;
err:
	fprintf(stderr,"can't write mapfile\n");
	vm->mapfile = NULL;
	unlink(fn);
	free(fn);
	return -1;

}

pid_t
grub_load(struct vm *vm)
{
	int ifd[2];
	pid_t pid;
	char *args[9];
	struct vm_conf *conf = vm->conf;
	int len;
	char *cmd;

	if ((len = asprintf(&cmd, "%s\nboot\n", conf->loadcmd)) < 0)
		return -1;

	if (pipe(ifd) < 0) {
		free(cmd);
		return -1;
	}

	pid = fork();
	if (pid > 0) {
		close(ifd[1]);
		vm->infd = ifd[0];
		write(ifd[0], cmd, len+1);
		free(cmd);
	} else if (pid == 0) {
		args[0] = "/usr/local/sbin/grub-bhyve";
		args[1] = "-r";
		args[2] = "hdd0,msdos1";
		args[3] = "-M";
		args[4] = conf->memory;
		args[5] = "-m";
		args[6] = vm->mapfile;
		args[7] = conf->name;
		args[8] = NULL;

		close(ifd[0]);
		dup2(ifd[1], 0);
		execv(args[0],args);
		fprintf(stderr, "can not exec %s\n", args[0]);
		exit(1);
	} else {
		fprintf(stderr, "can not fork (%s)\n", strerror(errno));
		return -1;
	}

	return pid;
}

pid_t
bhyve_load(struct vm_conf *conf)
{
	pid_t pid;
	char *args[9];


	pid = fork();
	if (pid > 0) {
		return pid;
	} else if (pid == 0) {
		args[0] = "/usr/sbin/bhyveload";
		args[1] = "-c";
		args[2] = conf->comport;
		args[3] = "-m";
		args[4] = conf->memory;
		args[5] = "-d";
		args[6] = STAILQ_FIRST(&conf->disks)->path;
		args[7] = conf->name;
		args[8] = NULL;

		execv(args[0],args);
		fprintf(stderr, "can not exec %s\n", args[0]);
		exit(1);
	} else {
		fprintf(stderr, "can not fork (%s)\n", strerror(errno));
		return -1;
	}

	return pid;
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

char *
get_fbuf_option(int pcid, struct fbuf *fb)
{
	char *ret;
	if (asprintf(&ret, "%d,fbuf,tcp=%s:%d,w=%d,h=%d,vga=%s%s,password=%s",
		     pcid, fb->ipaddr, fb->port, fb->width, fb->height,
		     fb->vgaconf, fb->wait ? ",wait" : "",
		     fb->password) < 0)
		return NULL;
	return ret;
}

int
exec_bhyve(struct vm *vm)
{
	struct vm_conf *conf = vm->conf;
	struct disk_conf *dc;
	struct iso_conf *ic;
	struct net_conf *nc;
	pid_t pid;
	int pcid;
	char **args;
	char *buf = NULL;
	size_t buf_size;
	FILE *fp;
	char *p;

	pid = fork();
	if (pid > 0) {
		/* parent process */
		vm->pid = pid;
		vm->state = RUN;
		EV_SET(&vm->kevent, vm->pid, EVFILT_PROC, EV_ADD,
		       NOTE_EXIT, 0, vm);
		kevent(kq, &vm->kevent, 1, NULL, 0, NULL);
	} else if (pid == 0) {
		/* child process */
		fp = open_memstream(&buf, &buf_size);

		p = "/usr/sbin/bhyve";
		fwrite(&p, sizeof(char*), 1, fp);
		p = "-A";
		fwrite(&p, sizeof(char*), 1, fp);
		p = "-H";
		fwrite(&p, sizeof(char*), 1, fp);
		p = "-u";
		fwrite(&p, sizeof(char*), 1, fp);
		p = "-w";
		fwrite(&p, sizeof(char*), 1, fp);
		p = "-c";
		fwrite(&p, sizeof(char*), 1, fp);
		fwrite(&conf->ncpu, sizeof(char*), 1, fp);
		p = "-m";
		fwrite(&p, sizeof(char*), 1, fp);
		fwrite(&conf->memory, sizeof(char*), 1, fp);
		if (conf->comport != NULL) {
			p = "-l";
			fwrite(&p, sizeof(char*), 1, fp);
			asprintf(&p, "com1,%s", conf->comport);
			fwrite(&p, sizeof(char*), 1, fp);
		}

		if (strcasecmp(conf->loader, "uefi") == 0) {
			p = "-l";
			fwrite(&p, sizeof(char*), 1, fp);
			p = "bootrom,/usr/local/share/uefi-firmware/BHYVE_UEFI.fd";
			fwrite(&p, sizeof(char*), 1, fp);
		}
		p = "-s";
		fwrite(&p, sizeof(char*), 1, fp);
		p = "0,hostbridge";
		fwrite(&p, sizeof(char*), 1, fp);
		p = "-s";
		fwrite(&p, sizeof(char*), 1, fp);
		p = "1,lpc";
		fwrite(&p, sizeof(char*), 1, fp);

		pcid = 2;
		STAILQ_FOREACH(dc, &conf->disks, next) {
			p = "-s";
			fwrite(&p, sizeof(char*), 1, fp);
			asprintf(&p, "%d,%s,%s", pcid++, dc->type, dc->path);
			fwrite(&p, sizeof(char*), 1, fp);
		}
		STAILQ_FOREACH(ic, &conf->isoes, next) {
			p = "-s";
			fwrite(&p, sizeof(char*), 1, fp);
			asprintf(&p, "%d,%s,%s", pcid++, ic->type, ic->path);
			fwrite(&p, sizeof(char*), 1, fp);
		}
		STAILQ_FOREACH(nc, &conf->nets, next) {
			p = "-s";
			fwrite(&p, sizeof(char*), 1, fp);
			asprintf(&p, "%d,%s,%s", pcid++, nc->type, nc->tap);
			fwrite(&p, sizeof(char*), 1, fp);
		}
		if (conf->fbuf->enable) {
			p = "-s";
			fwrite(&p, sizeof(char*), 1, fp);
			p = get_fbuf_option(pcid++, conf->fbuf);
			fwrite(&p, sizeof(char*), 1, fp);
		}
		if (conf->mouse) {
			p = "-s";
			fwrite(&p, sizeof(char*), 1, fp);
			asprintf(&p, "%d,xhci,tablet", pcid++);
			fwrite(&p, sizeof(char*), 1, fp);
		}
		fwrite(&conf->name, sizeof(char*), 1, fp);
		p = NULL;
		fwrite(&p, sizeof(char*), 1, fp);

		fflush(fp);
		args = (char **)buf;
		execv(args[0], args);
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

	pid = fork();
	if (pid > 0) {
		if (waitpid(pid, &status, 0) < 0) {
			fprintf(stderr, "wait error (%s)\n", strerror(errno));
			return -1;
		}
	} else if (pid == 0) {
		args[0]="/usr/sbin/bhyvectl";
		args[1]="--destroy";
		asprintf(&args[2], "--vm=%s", conf->name);
		args[3]=NULL;

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
load_config_files()
{
	char *path;
	DIR *d;
	struct dirent *ent;
	struct vm_conf *conf;
	struct vm_conf_entry *conf_ent;

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
		conf_ent = realloc(conf, sizeof(*conf_ent));
		if (conf_ent == NULL) {
			free_vm_conf(conf);
			continue;
		}
		SLIST_INSERT_HEAD(&vm_conf_list, conf_ent, next);
	}

	closedir(d);

	SLIST_FOREACH(conf_ent, &vm_conf_list, next) {
		dump_vm_conf(&conf_ent->conf);
	}

	return 0;
}

int
start_vm(struct vm *vm)
{
	pid_t pid;
	struct vm_conf *conf = vm->conf;

	if (activate_taps(conf) < 0)
		return -1;

	if (strcasecmp(conf->loader, "bhyveload") == 0)
		pid = bhyve_load(conf);
	else if (strcasecmp(conf->loader, "grub") == 0) {
		if (write_mapfile(vm) < 0 ||
		    (pid = grub_load(vm)) < 0)
			pid = -1;
	} else if (strcasecmp(conf->loader, "uefi") == 0) {
		if (exec_bhyve(vm) < 0) {
			remove_taps(conf);
			return -1;
		}
		vm->state = RUN;
		EV_SET(&vm->kevent, vm->pid, EVFILT_PROC, EV_ADD,
		       NOTE_EXIT, 0, vm);
		kevent(kq, &vm->kevent, 1, NULL, 0, NULL);
		return 0;
	} else {
		pid = -1;
		fprintf(stderr, "unknown loader\n");
	}

	if (pid < 0) {
		remove_taps(conf);
		return -1;
	}
	vm->pid = pid;
	vm->state = LOAD;

	EV_SET(&vm->kevent, vm->pid, EVFILT_PROC, EV_ADD,
	       NOTE_EXIT, 0, vm);
	kevent(kq, &vm->kevent, 1, NULL, 0, NULL);

	return 0;
}

int
start_virtual_machines()
{
	struct vm_conf *conf;
	struct vm_conf_entry *conf_ent;
	struct vm *vm;
	struct vm_entry *vm_ent;
	struct kevent sigev[3];

	EV_SET(&sigev[0], SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&sigev[1], SIGINT,  EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&sigev[2], SIGHUP,  EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	if (kevent(kq, sigev, 3, NULL, 0, NULL) < 0)
		return -1;

	SLIST_FOREACH(conf_ent, &vm_conf_list, next) {
		vm_ent = calloc(1, sizeof(struct vm_entry));
		if (vm_ent == NULL)
			return -1;
		vm = &vm_ent->vm;
		conf = &conf_ent->conf;
		vm->conf = conf;
		vm->state = STOP;
		vm->pid = -1;
		vm->infd = -1;
		if (conf->boot != NO)
			if (assign_taps(conf) < 0 ||
			    start_vm(vm) < 0)
				fprintf(stderr, "fail to start %s\n", conf->name);
		SLIST_INSERT_HEAD(&vm_list, vm_ent, next);
	}

	return 0;
}

int
event_loop()
{
	struct kevent ev;
	struct vm *vm;
	int status;

wait:
	if (kevent(kq, NULL, 0, &ev, 1, NULL) < 0) {
		if (errno == EINTR) goto wait;
		return -1;
	}

	switch (ev.filter) {
	case EVFILT_PROC:
		vm = ev.udata;
		vm->kevent.flags = EV_DELETE;
		kevent(kq, &vm->kevent, 1, NULL, 0, NULL);
		if (waitpid(vm->pid, &status, 0) < 0) {
			fprintf(stderr, "wait error (%s)\n",
				strerror(errno));
		}
		switch (vm->state) {
		case STOP:
			break;
		case LOAD:
			if (vm->infd != -1) {
				close(vm->infd);
				vm->infd = -1;
			}
			exec_bhyve(vm);
			break;
		case RUN:
			if (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) {
				start_vm(vm);
				break;
			}
			remove_taps(vm->conf);
			destroy_vm(vm->conf);
			if (vm->mapfile) unlink(vm->mapfile);
			vm->state=TERMINATE;
			break;
		case TERMINATE:
			break;
		}
		break;
	case EVFILT_SIGNAL:
		switch (ev.ident) {
		case SIGTERM:
		case SIGINT:
			return 0;
		case SIGHUP:
			// do_reload();
			goto wait;
		}
		break;
	default:
		// unknown event
		return -1;
	}

	goto wait;

	return 0;
}

int
stop_virtual_machines()
{
	struct kevent ev;
	struct vm *vm;
	struct vm_entry *vm_entry;
	int status, count = 0;

	SLIST_FOREACH(vm_entry, &vm_list, next)
		vm = &vm_entry->vm;
		if (vm->state == RUN || vm->state == LOAD) {
			count++;
			kill(vm->pid, SIGTERM);
		}

	while (count > 0) {
		if (kevent(kq, NULL, 0, &ev, 1, NULL) < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		if (ev.filter == EVFILT_PROC) {
			vm = ev.udata;
			vm->kevent.flags = EV_DELETE;
			kevent(kq, &vm->kevent, 1, NULL, 0, NULL);
			if (waitpid(vm->pid, &status, 0) < 0) {
				fprintf(stderr, "wait error (%s)\n",
					strerror(errno));
			}
			remove_taps(vm->conf);
			destroy_vm(vm->conf);
			if (vm->mapfile) unlink(vm->mapfile);
			vm->state=TERMINATE;
			count--;
		}
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	sigset_t nmask, omask;

	sigemptyset(&nmask);
	sigaddset(&nmask, SIGTERM);
	sigaddset(&nmask, SIGINT);
	sigaddset(&nmask, SIGHUP);
	sigprocmask(SIG_BLOCK, &nmask, &omask);

	kq = kqueue();

	if (load_config_files() < 0 ||
	    start_virtual_machines())
		return 1;

	event_loop();

	stop_virtual_machines();
	close(kq);
	return 0;
}
