#include <errno.h>
#include <sys/queue.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/event.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "vars.h"
#include "conf.h"
#include "tap.h"
#include "log.h"
#include "vm.h"

extern struct global_conf gl_conf;

static int
redirect_to_null()
{
	int fd;

	fd = open("/dev/null", O_WRONLY);
	if (fd < 0) {
		ERR("can't open /dev/null (%s)\n", strerror(errno));
		return -1;
	}
	dup2(fd, 1);
	dup2(fd, 2);

	return 0;
}

static int
redirect_to_com(struct vm *vm)
{
	int fd;
	char *com;

	if ((com = vm->conf->comport) == NULL)
		com = "/dev/null";

	fd = open(com, O_WRONLY);
	if (fd < 0) {
		ERR("can't open %s (%s)\n", com, strerror(errno));
		return -1;
	}
	dup2(fd, 1);
	dup2(fd, 2);

	return 0;
}

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
		ERR("%s\n", "can't create mapfile");
		free(fn);
		return -1;
	}

	free(vm->mapfile);
	vm->mapfile = fn;

	fp = fdopen(fd, "w+");
	if (fp == NULL) {
		ERR("can't open mapfile (%s)\n", strerror(errno));
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
	ERR("can't write mapfile (%s)\n", strerror(errno));
	vm->mapfile = NULL;
	unlink(fn);
	free(fn);
	return -1;

}

int
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
		vm->pid = pid;
		vm->state = LOAD;
		close(ifd[1]);
		vm->infd = ifd[0];
		write(ifd[0], cmd, len+1);
		free(cmd);
	} else if (pid == 0) {
		redirect_to_com(vm);

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
		ERR("can not exec %s\n", args[0]);
		exit(1);
	} else {
		ERR("can't fork (%s)\n", strerror(errno));
		return -1;
	}

	return 0;
}

int
bhyve_load(struct vm *vm)
{
	pid_t pid;
	char *args[9];
	struct vm_conf *conf = vm->conf;

	pid = fork();
	if (pid > 0) {
		vm->pid = pid;
		vm->state = LOAD;
		return 0;
	} else if (pid == 0) {
		redirect_to_null();

		args[0] = "/usr/sbin/bhyveload";
		args[1] = "-c";
		args[2] = (conf->comport != NULL) ? conf->comport : "stdio";
		args[3] = "-m";
		args[4] = conf->memory;
		args[5] = "-d";
		args[6] = STAILQ_FIRST(&conf->disks)->path;
		args[7] = conf->name;
		args[8] = NULL;

		execv(args[0],args);
		ERR("can't exec %s\n", args[0]);
		exit(1);
	} else {
		ERR("can't fork (%s)\n", strerror(errno));
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
		if (activate_tap(s, nc->tap) < 0)
			ERR("failed to up %s\n", nc->tap);
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
			ERR("failed to create tap for %s\n", nc->bridge);
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
	ERR("%s\n", "failed to create tap");
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
		redirect_to_null();

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
		ERR("can not exec %s\n", args[0]);
		exit(1);
	} else {
		ERR("can not fork (%s)\n", strerror(errno));
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
			ERR("wait error (%s)\n", strerror(errno));
			return -1;
		}
	} else if (pid == 0) {
		args[0]="/usr/sbin/bhyvectl";
		args[1]="--destroy";
		asprintf(&args[2], "--vm=%s", conf->name);
		args[3]=NULL;

		execv(args[0],args);
		ERR("can not exec %s\n", args[0]);
		exit(1);
	} else {
		ERR("can not fork (%s)\n", strerror(errno));
		exit(1);
	}

	return 0;
}

int
start_vm(struct vm *vm)
{
	struct vm_conf *conf = vm->conf;
	struct kevent ev;

	if (activate_taps(vm) < 0)
		return -1;

	if (strcasecmp(conf->loader, "bhyveload") == 0) {
		if (bhyve_load(vm) < 0)
			return -1;
	} else if (strcasecmp(conf->loader, "grub") == 0) {
		if (write_mapfile(vm) < 0 ||
		    (grub_load(vm)) < 0)
			return -1;
	} else if (strcasecmp(conf->loader, "uefi") == 0) {
		if (exec_bhyve(vm) < 0)
			return -1;
	} else {
		ERR("unknown loader %s\n", conf->loader);
		return -1;
	}

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
