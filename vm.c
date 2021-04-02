#include <errno.h>
#include <sys/queue.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/event.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "vars.h"
#include "conf.h"
#include "tap.h"

extern struct global_conf gl_conf;

static char *
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

	free(vm->mapfile);
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
bhyve_load(struct vm *vm)
{
	pid_t pid;
	char *args[9];
	struct vm_conf *conf = vm->conf;

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
remove_taps(struct vm *vm)
{
	int s;
	struct net_conf *nc, *nnc;

	s = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (s < 0)
		return -1;

	STAILQ_FOREACH_SAFE(nc, &vm->taps, next, nnc) {
		if (nc->tap != NULL) {
			destroy_tap(s, nc->tap);
			free(nc->tap);
			nc->tap = NULL;
		}
		free(nc);
	}
	STAILQ_INIT(&vm->taps);

	close(s);
	return 0;
}

int
activate_taps(struct vm *vm)
{
	int s;
	struct net_conf *nc;

	s = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (s < 0)
		return -1;
	STAILQ_FOREACH(nc, &vm->taps, next)
		activate_tap(s, nc->tap);
	close(s);
	return 0;
}

int
assign_taps(struct vm *vm)
{
	int s, i;
	struct net_conf *nc, *nnc;
	char *desc;
	struct vm_conf *conf = vm->conf;

	STAILQ_FOREACH(nc, &conf->nets, next) {
		nnc = copy_net_conf(nc);
		if (nnc == NULL)
			goto err;
		STAILQ_INSERT_TAIL(&vm->taps, nnc, next);
	}

	s = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (s < 0)
		goto err;

	i = 0;
	STAILQ_FOREACH(nc, &vm->taps, next) {
		if (asprintf(&desc,"vm-%s-%d", conf->name, i++) < 0)
			continue;
		if (create_tap(s, &nc->tap) < 0 ||
		    set_tap_description(s, nc->tap, desc) < 0 ||
		    add_to_bridge(s, nc->bridge, nc->tap) < 0) {
			fprintf(stderr, "failed to create tap\n");
			free(desc);
			remove_taps(vm);
			close(s);
			return -1;
		}
		free(desc);
	}

	close(s);
	return 0;
err:
	STAILQ_FOREACH_SAFE(nc, &vm->taps, next, nnc)
		free_net_conf(nc);
	STAILQ_INIT(&vm->taps);
	return -1;
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
	struct kevent ev;

	pid = fork();
	if (pid > 0) {
		/* parent process */
		vm->pid = pid;
		vm->state = RUN;
		EV_SET(&ev, vm->pid, EVFILT_PROC, EV_ADD,
		       NOTE_EXIT, 0, vm);
		kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL);
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
		STAILQ_FOREACH(nc, &vm->taps, next) {
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
destroy_vm(struct vm *vm)
{
	pid_t pid;
	int status;
	char *args[4];
	struct vm_conf *conf = vm->conf;

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
start_vm(struct vm *vm)
{
	pid_t pid;
	struct vm_conf *conf = vm->conf;
	struct kevent ev;

	if (activate_taps(vm) < 0)
		return -1;

	if (strcasecmp(conf->loader, "bhyveload") == 0)
		pid = bhyve_load(vm);
	else if (strcasecmp(conf->loader, "grub") == 0) {
		if (write_mapfile(vm) < 0 ||
		    (pid = grub_load(vm)) < 0)
			pid = -1;
	} else if (strcasecmp(conf->loader, "uefi") == 0) {
		if (exec_bhyve(vm) < 0)
			return -1;
		vm->state = RUN;
		goto end;
	} else {
		pid = -1;
		fprintf(stderr, "unknown loader\n");
	}

	if (pid < 0)
		return -1;

	vm->pid = pid;
	vm->state = LOAD;

end:
	EV_SET(&ev, vm->pid, EVFILT_PROC, EV_ADD,
	       NOTE_EXIT, 0, vm);
	kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL);

	return 0;
}

void
cleanup_vm(struct vm *vm)
{
	remove_taps(vm);
	destroy_vm(vm);
	if (vm->mapfile) {
		unlink(vm->mapfile);
		free(vm->mapfile);
		vm->mapfile = NULL;
	}
	vm->state=TERMINATE;
}

