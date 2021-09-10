#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "conf.h"
#include "log.h"
#include "tap.h"
#include "vars.h"
#include "vm.h"

static int
redirect_to_com(struct vm *vm)
{
	int fd;
	char *com;

	if ((com = vm->conf->comport) == NULL)
		com = "/dev/null";

	fd = open(com, O_WRONLY | O_NONBLOCK);
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
		pcid, fb->ipaddr, fb->port, fb->width, fb->height, fb->vgaconf,
		fb->wait ? ",wait" : "", fb->password) < 0)
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

	if (asprintf(&fn, "/tmp/bmd.%s.%d.XXXXXX", vm->conf->name, getpid()) <
	    0)
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
	STAILQ_FOREACH (dc, &conf->disks, next)
		if (fprintf(fp, "(hd%d) %s\n", i++, dc->path) < 0)
			goto err;

	i = 0;
	STAILQ_FOREACH (ic, &conf->isoes, next)
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
	bool doredirect = (conf->comport == NULL) ||
	    (strcasecmp(conf->comport, "stdio") != 0);

	if ((len = asprintf(&cmd, "%s\nboot\n",
		 (conf->boot == INSTALL) ? conf->installcmd : conf->loadcmd)) <
	    0)
		return -1;

	if (pipe(ifd) < 0) {
		ERR("can not create pipe (%s)\n", strerror(errno));
		free(cmd);
		return -1;
	}

	pid = fork();
	if (pid > 0) {
		vm->pid = pid;
		vm->state = LOAD;
		close(ifd[1]);
		vm->infd = ifd[0];
		vm->outfd = -1;
		vm->errfd = -1;
		write(ifd[0], cmd, len + 1);
		free(cmd);
	} else if (pid == 0) {
		close(ifd[0]);
		dup2(ifd[1], 0);
		if (doredirect)
			redirect_to_com(vm);

		setenv("TERM", "vt100", 1);
		args[0] = "/usr/local/sbin/grub-bhyve";
		args[1] = "-r";
		args[2] = (conf->boot == INSTALL) ? "cd0" : "hdd0,msdos1";
		args[3] = "-M";
		args[4] = conf->memory;
		args[5] = "-m";
		args[6] = vm->mapfile;
		args[7] = conf->name;
		args[8] = NULL;

		execv(args[0], args);
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
	int outfd[2], errfd[2];
	struct vm_conf *conf = vm->conf;
	bool dopipe = (conf->comport == NULL) ||
	    (strcasecmp(conf->comport, "stdio") != 0);

	if (dopipe) {
		if (pipe(outfd) < 0) {
			ERR("can not create pipe (%s)\n", strerror(errno));
			return -1;
		}

		if (pipe(errfd) < 0) {
			close(outfd[0]);
			close(outfd[1]);
			ERR("can not create pipe (%s)\n", strerror(errno));
			return -1;
		}
	}

	pid = fork();
	if (pid > 0) {
		if (dopipe) {
			close(outfd[1]);
			close(errfd[1]);
			vm->outfd = outfd[0];
			vm->errfd = errfd[0];
		}
		vm->pid = pid;
		vm->state = LOAD;
		return 0;
	} else if (pid == 0) {
		if (dopipe) {
			close(outfd[0]);
			close(errfd[0]);
			dup2(outfd[1], 1);
			dup2(errfd[1], 2);
		}
		args[0] = "/usr/sbin/bhyveload";
		args[1] = "-c";
		args[2] = (conf->comport != NULL) ? conf->comport : "stdio";
		args[3] = "-m";
		args[4] = conf->memory;
		args[5] = "-d";
		args[6] = (conf->boot == INSTALL) ?
			  STAILQ_FIRST(&conf->isoes)->path :
			  STAILQ_FIRST(&conf->disks)->path;
		args[7] = conf->name;
		args[8] = NULL;

		execv(args[0], args);
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

	STAILQ_FOREACH_SAFE (nc, &vm->taps, next, nnc) {
		if (nc->tap != NULL)
			destroy_tap(s, nc->tap);
		free_net_conf(nc);
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
	STAILQ_FOREACH (nc, &vm->taps, next)
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

	STAILQ_FOREACH (nc, &conf->nets, next) {
		nnc = copy_net_conf(nc);
		if (nnc == NULL)
			goto err;
		STAILQ_INSERT_TAIL(&vm->taps, nnc, next);
	}

	s = socket(AF_LOCAL, SOCK_DGRAM, 0);
	if (s < 0)
		goto err;

	i = 0;
	STAILQ_FOREACH (nc, &vm->taps, next) {
		if (asprintf(&desc, "vm-%s-%d", conf->name, i++) < 0)
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
	STAILQ_FOREACH_SAFE (nc, &vm->taps, next, nnc)
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
	int outfd[2], errfd[2];
	char **args;
	char *buf = NULL;
	size_t buf_size;
	FILE *fp;
	bool dopipe = ((conf->comport == NULL) ||
	    (strcasecmp(conf->comport, "stdio") != 0));

	if (dopipe) {
		if (pipe(outfd) < 0) {
			ERR("can not create pipe (%s)\n", strerror(errno));
			return -1;
		}

		if (pipe(errfd) < 0) {
			close(outfd[0]);
			close(outfd[1]);
			ERR("can not create pipe (%s)\n", strerror(errno));
			return -1;
		}
	}

	pid = fork();
	if (pid > 0) {
		/* parent process */
		if (dopipe) {
			close(outfd[1]);
			close(errfd[1]);
			vm->outfd = outfd[0];
			vm->errfd = errfd[0];
		}
		vm->pid = pid;
		vm->state = RUN;
	} else if (pid == 0) {
		/* child process */
		if (dopipe) {
			close(outfd[0]);
			close(errfd[0]);
			dup2(outfd[1], 1);
			dup2(errfd[1], 2);
		}

		fp = open_memstream(&buf, &buf_size);
		if (fp == NULL) {
			ERR("can not open memstrem (%s)\n", strerror(errno));
			exit(1);
		}
		flockfile(fp);

#define WRITE_STR(str) \
	fwrite_unlocked(&(char *[]) { (str) }[0], sizeof(char *), 1, fp)

#define WRITE_FMT(fmt, ...)                                 \
	do {                                                \
		char *p;                                    \
		asprintf(&p, (fmt), __VA_ARGS__);           \
		fwrite_unlocked(&p, sizeof(char *), 1, fp); \
	} while (0)

		WRITE_STR("/usr/sbin/bhyve");
		WRITE_STR("-A");
		WRITE_STR("-H");
		WRITE_STR("-w");
		if (conf->utctime == true)
			WRITE_STR("-u");
		if (conf->wired_memory == true)
			WRITE_STR("-S");
		WRITE_STR("-c");
		WRITE_STR(conf->ncpu);
		WRITE_STR("-m");
		WRITE_STR(conf->memory);
		if (conf->comport != NULL) {
			WRITE_STR("-l");
			WRITE_FMT("com1,%s", conf->comport);
		}

		if (strcasecmp(conf->loader, "uefi") == 0) {
			WRITE_STR("-l");
			WRITE_STR(
			    "bootrom,/usr/local/share/uefi-firmware/BHYVE_UEFI.fd");
		}
		WRITE_STR("-s");
		WRITE_STR("0,hostbridge");
		WRITE_STR("-s");
		WRITE_STR("1,lpc");

		pcid = 2;
		STAILQ_FOREACH (dc, &conf->disks, next) {
			WRITE_STR("-s");
			WRITE_FMT("%d,%s,%s", pcid++, dc->type, dc->path);
		}
		STAILQ_FOREACH (ic, &conf->isoes, next) {
			WRITE_STR("-s");
			WRITE_FMT("%d,%s,%s", pcid++, ic->type, ic->path);
		}
		STAILQ_FOREACH (nc, &vm->taps, next) {
			WRITE_STR("-s");
			WRITE_FMT("%d,%s,%s", pcid++, nc->type, nc->tap);
		}
		if (conf->fbuf->enable) {
			WRITE_STR("-s");
			WRITE_STR(get_fbuf_option(pcid++, conf->fbuf));
		}
		if (conf->mouse) {
			WRITE_STR("-s");
			WRITE_FMT("%d,xhci,tablet", pcid++);
		}
		WRITE_STR(conf->name);
		WRITE_STR(NULL);

		funlockfile(fp);
		fclose(fp);
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
	char *name = vm->conf->name;
	return sysctlbyname("hw.vmm.destroy", NULL, 0, name, strlen(name));
}

int
start_vm(struct vm *vm)
{
	struct vm_conf *conf = vm->conf;

	if (STAILQ_FIRST(&vm->taps) == NULL && assign_taps(vm) < 0)
		return -1;

	if (activate_taps(vm) < 0)
		goto err;

	if (strcasecmp(conf->loader, "bhyveload") == 0) {
		if (bhyve_load(vm) < 0)
			goto err;
	} else if (strcasecmp(conf->loader, "grub") == 0) {
		if (write_mapfile(vm) < 0 || (grub_load(vm)) < 0)
			goto err;
	} else if (strcasecmp(conf->loader, "uefi") == 0) {
		if (exec_bhyve(vm) < 0)
			goto err;
	} else {
		ERR("unknown loader %s\n", conf->loader);
		goto err;
	}

	return 0;
err:
	remove_taps(vm);
	return -1;
}

void
cleanup_vm(struct vm *vm)
{
#define VM_CLOSE_FD(fd)                \
	do {                           \
		if (vm->fd != -1) {    \
			close(vm->fd); \
			vm->fd = -1;   \
		}                      \
	} while (0)

	VM_CLOSE_FD(infd);
	VM_CLOSE_FD(outfd);
	VM_CLOSE_FD(errfd);
	VM_CLOSE_FD(logfd);

	remove_taps(vm);
	destroy_vm(vm);
	if (vm->mapfile) {
		unlink(vm->mapfile);
		free(vm->mapfile);
		vm->mapfile = NULL;
	}
	vm->state = TERMINATE;
}
