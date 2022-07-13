#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/cpuset.h>

#include <machine/vmm.h>
#include <machine/vmm_dev.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
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
#include "inspect.h"

#define UEFI_CSM_FIRMWARE   LOCALBASE"/share/uefi-firmware/BHYVE_UEFI_CSM.fd"
#define UEFI_FIRMWARE       LOCALBASE"/share/uefi-firmware/BHYVE_UEFI.fd"
#define UEFI_FIRMWARE_VARS  LOCALBASE"/share/uefi-firmware/BHYVE_UEFI_VARS.fd"

#define WRITE_STR(fp, str) \
	fwrite_unlocked(&(char *[]) { (str) }[0], sizeof(char *), 1, (fp))

#define WRITE_FMT(fp, fmt, ...)                               \
	do {                                                  \
		char *p;                                      \
		asprintf(&p, (fmt), __VA_ARGS__);             \
		fwrite_unlocked(&p, sizeof(char *), 1, (fp)); \
	} while (0)

static int
redirect_to_com(struct vm *vm)
{
	int fd;
	char *com;

	if ((com = vm->conf->comport) == NULL)
		com = "/dev/null";

	while ((fd = open(com, O_WRONLY | O_NONBLOCK)) < 0)
		if (errno != EINTR)
			break;
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
write_mapfile(struct vm_conf *conf, char **mapfile)
{
	int fd, i;
	char *fn;
	FILE *fp;
	struct disk_conf *dc;
	struct iso_conf *ic;

	if (asprintf(&fn, "/tmp/bmd.%s.%d.XXXXXX", conf->name, getpid()) <
	    0)
		return -1;

	fd = mkstemp(fn);
	if (fd < 0) {
		ERR("%s\n", "can't create mapfile");
		free(fn);
		return -1;
	}

	if (*mapfile) {
		unlink(*mapfile);
		free(*mapfile);
	}
	*mapfile = fn;

	fp = fdopen(fd, "w+");
	if (fp == NULL) {
		ERR("can't open mapfile (%s)\n", strerror(errno));
		unlink(fn);
		*mapfile = NULL;
		free(fn);
		return -1;
	}

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
	fclose(fp);
	*mapfile = NULL;
	unlink(fn);
	free(fn);
	return -1;
}

#if __FreeBSD_version > 1400000
bool is_file(char *path);
static int
copy_uefi_vars(struct vm *vm)
{
	char *fn;
	int out, in;
	ssize_t n;
	off_t len = 0;
	struct stat st;
	const char *origin = UEFI_FIRMWARE_VARS;
	extern struct global_conf gl_conf;

	fn = vm->varsfile;
	if (fn == NULL && asprintf(&fn, "/%s/%s.vars", gl_conf.vars_dir,
				   vm->conf->name) < 0)
		return -1;

	vm->varsfile = fn;
	if (vm->conf->install == false && is_file(fn))
		return 0;

	while ((in = open(origin, O_RDONLY)) < 0)
		if (errno != EINTR)
			break;
	if (in < 0) {
		ERR("can not open %s\n", origin);
		return -1;
	}

	while ((out = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0)
		if (errno != EINTR)
			break;
	if (out < 0) {
		ERR("can't create %s\n", fn);
		close(in);
		return -1;
	}

	if (fstat(in, &st) < 0)
		goto err;

retry:
	while ((n = copy_file_range(in, &len, out, &len, st.st_size - len, 0)) < 0)
		if (errno != EINTR)
			goto err;
	if (n > 0) {
		len += n;
		if (len < st.st_size)
			goto retry;
	}

	close(in);
	close(out);
	return 0;
err:
	close(in);
	close(out);
	unlink(fn);
	return -1;
}
#else
static int
copy_uefi_vars(struct vm *vm)
{
	return 0;
}
#endif

static char *
create_load_command(struct vm_conf *conf, size_t *length)
{
	const char **p, *repl[] = { "kopenbsd ", "knetbsd " };
	size_t len = 0;
	char *cmd = NULL;
	char *t = (conf->install) ? conf->installcmd : conf->loadcmd;
	if (t == NULL)
		goto end;

	if (strcasecmp(t, "auto") == 0) {
		if ((cmd = inspect(conf)) == NULL) {
			ERR("%s inspection failed for VM %s\n",
			    conf->install ? "installcmd" : "loadcmd", conf->name);
			goto end;
		}
		len = strlen(cmd);
		goto end;
	}

	if (conf->single_user)
		ARRAY_FOREACH (p, repl) {
			len = strlen(*p);
			if (strncmp(t, *p, len) == 0) {
				len = asprintf(&cmd, "%s-s %s\nboot\n", *p,
				    t + len);
				goto end;
			}
		}
	len = asprintf(&cmd, "%s\nboot\n", t);

end:
	if (length)
		*length = len;

	return cmd;
}

static int
grub_load(struct vm *vm)
{
	int i, ifd[2];
	pid_t pid;
	char *args[9];
	struct vm_conf *conf = vm->conf;
	size_t len;
	char *cmd;
	bool doredirect = (conf->comport == NULL) ||
	    (strcasecmp(conf->comport, "stdio") != 0);

	cmd = create_load_command(conf, &len);

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
		if (cmd != NULL)
			write(ifd[0], cmd, len + 1);
		free(cmd);
	} else if (pid == 0) {
		close(ifd[0]);
		dup2(ifd[1], 0);
		if (doredirect)
			redirect_to_com(vm);

		setenv("TERM", "vt100", 1);
		i = 0;
		args[i++] = LOCALBASE"/sbin/grub-bhyve";
		args[i++] = "-r";
		if (conf->install)
			args[i++] = "cd0";
		else if (conf->grub_run_partition)
			asprintf(&args[i++], "hd0,%s",
				 conf->grub_run_partition);
		else
			args[i++] = "hd0,1";
		args[i++] = "-M";
		args[i++] = conf->memory;
		args[i++] = "-m";
		args[i++] = vm->mapfile;
		args[i++] = conf->name;
		args[i++] = NULL;

		execv(args[0], args);
		ERR("can not exec %s\n", args[0]);
		exit(1);
	} else {
		ERR("can't fork (%s)\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int
bhyve_load(struct vm *vm)
{
	pid_t pid;
	char *args[11];
	int i, outfd[2], errfd[2];
	struct vm_conf *conf = vm->conf;
	bool dopipe = (conf->comport == NULL) ||
	    (strcasecmp(conf->comport, "stdio") != 0);

	if (dopipe) {
		if (pipe(outfd) < 0) {
			ERR("can not create pipe (%s)\n", strerror(errno));
			return -1;
		}

		if (pipe(errfd) < 0) {
			ERR("can not create pipe (%s)\n", strerror(errno));
			close(outfd[0]);
			close(outfd[1]);
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
		i = 0;
		args[i++] = "/usr/sbin/bhyveload";
		if (conf->single_user) {
			args[i++] = "-e";
			args[i++] = "boot_single=YES";
		}
		args[i++] = "-c";
		args[i++] = (conf->comport != NULL) ? conf->comport : "stdio";
		args[i++] = "-m";
		args[i++] = conf->memory;
		args[i++] = "-d";
		args[i++] = (conf->install) ? STAILQ_FIRST(&conf->isoes)->path :
						    STAILQ_FIRST(&conf->disks)->path;
		args[i++] = conf->name;
		args[i++] = NULL;

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

	while ((s = socket(AF_LOCAL, SOCK_DGRAM, 0)) < 0)
		if (errno != EAGAIN && errno != EINTR)
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

	while ((s = socket(AF_LOCAL, SOCK_DGRAM, 0)) < 0)
		if (errno != EAGAIN && errno != EINTR)
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

	while ((s = socket(AF_LOCAL, SOCK_DGRAM, 0)) < 0)
		if (errno != EAGAIN && errno != EINTR)
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

static int
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
			ERR("can not create pipe (%s)\n", strerror(errno));
			close(outfd[0]);
			close(outfd[1]);
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

		WRITE_STR(fp, "/usr/sbin/bhyve");
		WRITE_STR(fp, "-A");
		WRITE_STR(fp, "-H");
		WRITE_STR(fp, "-w");
		if (conf->utctime == true)
			WRITE_STR(fp, "-u");
		if (conf->wired_memory == true)
			WRITE_STR(fp, "-S");
		if (conf->debug_port != NULL) {
			WRITE_STR(fp, "-G");
			WRITE_STR(fp, conf->debug_port);
		}
		WRITE_STR(fp, "-c");
		WRITE_STR(fp, conf->ncpu);
		WRITE_STR(fp, "-m");
		WRITE_STR(fp, conf->memory);
		if (conf->comport != NULL) {
			WRITE_STR(fp, "-l");
			WRITE_FMT(fp, "com1,%s", conf->comport);
		}

		if (conf->keymap != NULL) {
			WRITE_STR(fp, "-K");
			WRITE_STR(fp, conf->keymap);
		}
		if (strcasecmp(conf->loader, "uefi") == 0) {
			WRITE_STR(fp, "-l");
			if (vm->varsfile)
				WRITE_FMT(fp, "bootrom,"UEFI_FIRMWARE",%s",
					  vm->varsfile);
			else
				WRITE_STR(fp, "bootrom,"UEFI_FIRMWARE);

		} else if (strcasecmp(conf->loader, "csm") == 0) {
			WRITE_STR(fp, "-l");
			WRITE_STR(fp, "bootrom,"UEFI_CSM_FIRMWARE);
		}
		WRITE_STR(fp, "-s");
		switch (conf->hostbridge) {
		case NONE:
			break;
		case INTEL:
			WRITE_STR(fp, "0,hostbridge");
			break;
		case AMD:
			WRITE_STR(fp, "0,amd_hostbridge");
			break;
		}
		WRITE_STR(fp, "-s");
		WRITE_STR(fp, "1,lpc");

		pcid = 2;
		STAILQ_FOREACH (dc, &conf->disks, next) {
			WRITE_STR(fp, "-s");
			WRITE_FMT(fp, "%d,%s,%s", pcid++, dc->type, dc->path);
		}
		STAILQ_FOREACH (ic, &conf->isoes, next) {
			WRITE_STR(fp, "-s");
			WRITE_FMT(fp, "%d,%s,%s", pcid++, ic->type, ic->path);
		}
		STAILQ_FOREACH (nc, &vm->taps, next) {
			WRITE_STR(fp, "-s");
			WRITE_FMT(fp, "%d,%s,%s", pcid++, nc->type, nc->tap);
		}
		if (conf->fbuf->enable) {
			WRITE_STR(fp, "-s");
			WRITE_STR(fp, get_fbuf_option(pcid++, conf->fbuf));
		}
		if (conf->mouse) {
			WRITE_STR(fp, "-s");
			WRITE_FMT(fp, "%d,xhci,tablet", pcid++);
		}
		WRITE_STR(fp, conf->name);
		WRITE_STR(fp, NULL);

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

static int
destroy_bhyve(struct vm *vm)
{
	char *name = vm->conf->name;
	return sysctlbyname("hw.vmm.destroy", NULL, 0, name, strlen(name));
}

static int
suspend_bhyve(struct vm *vm, enum vm_suspend_how how)
{
	int rc, fd;
	char *path;
	struct vm_suspend vmsuspend;

	if ((asprintf(&path, "/dev/vmm/%s", vm->conf->name)) < 0)
		return -1;

	while ((fd = open(path, O_RDWR)) < 0)
		if (errno != EINTR)
			break;
	if (fd < 0) {
		free(path);
		return -1;
	}

	memset(&vmsuspend, 0, sizeof(vmsuspend));
	vmsuspend.how = how;
	rc = ioctl(fd, VM_SUSPEND, &vmsuspend);

	close(fd);
	free(path);
	return rc;
}

static int
reset_bhyve(struct vm *vm)
{
	return suspend_bhyve(vm, VM_SUSPEND_RESET);
}

static int
poweroff_bhyve(struct vm *vm)
{
	if (vm->state == LOAD)
		return kill(vm->pid, SIGKILL);
	return suspend_bhyve(vm, VM_SUSPEND_POWEROFF);
}

static int
acpi_poweroff_bhyve(struct vm *vm)
{
	return kill(vm->pid, SIGTERM);
}

static int
start_bhyve(struct vm *vm)
{
	struct vm_conf *conf = vm->conf;

	if (vm->state == LOAD)
		return exec_bhyve(vm);

	if (STAILQ_FIRST(&vm->taps) == NULL && assign_taps(vm) < 0)
		return -1;

	if (activate_taps(vm) < 0)
		goto err;

	if (strcasecmp(conf->loader, "bhyveload") == 0) {
		if (bhyve_load(vm) < 0)
			goto err;
	} else if (strcasecmp(conf->loader, "grub") == 0) {
		if (write_mapfile(vm->conf, &vm->mapfile) < 0 ||
		    grub_load(vm) < 0)
			goto err;
	} else if (strcasecmp(conf->loader, "uefi") == 0) {
		if (copy_uefi_vars(vm) < 0 || exec_bhyve(vm) < 0)
			goto err;
	} else if (strcasecmp(conf->loader, "csm") == 0) {
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

static void
cleanup_bhyve(struct vm *vm)
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
#undef VM_CLOSE_FD
	remove_taps(vm);
	destroy_bhyve(vm);
	if (vm->mapfile) {
		unlink(vm->mapfile);
		free(vm->mapfile);
		vm->mapfile = NULL;
	}
	vm->state = TERMINATE;
}

int
write_err_log(int fd, struct vm *vm)
{
	int n, rc;
	ssize_t size;
	char buf[4 * 1024];

	while ((size = read(fd, buf, sizeof(buf))) < 0)
		if (errno != EINTR && errno != EAGAIN)
			break;
	if (size == 0) {
		close(fd);
		if (vm->outfd == fd)
			vm->outfd = -1;
		if (vm->errfd == fd)
			vm->errfd = -1;
		return 0;
	} else if (size > 0 && vm->logfd != -1) {
		n = 0;
		while (n < size) {
			if ((rc = write(vm->logfd, buf + n, size - n)) < 0)
				if (errno != EINTR && errno != EAGAIN)
					break;
			if (rc > 0)
				n += rc;
		}
	}

	return size;
}

static int
exec_qemu(struct vm *vm)
{
	struct vm_conf *conf = vm->conf;
	struct disk_conf *dc;
	struct iso_conf *ic;
	struct net_conf *nc;
	pid_t pid;
	int infd[2], outfd[2], errfd[2];
	char **args;
	char *buf = NULL;
	size_t n, buf_size;
	ssize_t rc;
	FILE *fp;
	bool dopipe = ((conf->comport == NULL) ||
	    (strcasecmp(conf->comport, "stdio") != 0));

	if (dopipe) {
		if (pipe(infd) < 0) {
			ERR("can not create pipe (%s)\n", strerror(errno));
			return -1;
		}
		if (pipe(outfd) < 0) {
			ERR("can not create pipe (%s)\n", strerror(errno));
			close(infd[0]);
			close(infd[1]);
			return -1;
		}

		if (pipe(errfd) < 0) {
			ERR("can not create pipe (%s)\n", strerror(errno));
			close(infd[0]);
			close(infd[1]);
			close(outfd[0]);
			close(outfd[1]);
			return -1;
		}
	}

	pid = fork();
	if (pid > 0) {
		/* parent process */
		if (dopipe) {
			close(infd[1]);
			close(outfd[1]);
			close(errfd[1]);
			vm->infd = infd[0];
			vm->outfd = outfd[0];
			vm->errfd = errfd[0];
			if (conf->fbuf->enable) {
				buf_size = asprintf(&buf,
				    "set_password vnc %s\n",
				    conf->fbuf->password);
				n = 0;
				while (n < buf_size) {
					if ((rc = write(vm->infd, buf + n,
						 buf_size - n)) < 0)
						if (errno != EINTR &&
						    errno != EAGAIN)
							break;
					if (rc > 0)
						n += rc;
				}
				free(buf);
			}
		}
		vm->pid = pid;
		vm->state = RUN;
	} else if (pid == 0) {
		/* child process */
		if (dopipe) {
			close(infd[0]);
			close(outfd[0]);
			close(errfd[0]);
			dup2(infd[1], 0);
			dup2(outfd[1], 1);
			dup2(errfd[1], 2);
		}

		fp = open_memstream(&buf, &buf_size);
		if (fp == NULL) {
			ERR("can not open memstrem (%s)\n", strerror(errno));
			exit(1);
		}
		flockfile(fp);

		WRITE_FMT(fp, LOCALBASE"/bin/qemu-system-%s", conf->qemu_arch);
		WRITE_STR(fp, "-accel");
		WRITE_STR(fp, "tcg");
		if (conf->qemu_machine) {
			WRITE_STR(fp, "-machine");
			WRITE_STR(fp, conf->qemu_machine);
		}
		WRITE_STR(fp, "-rtc");
		if (conf->utctime == true)
			WRITE_STR(fp, "base=utc");
		else
			WRITE_STR(fp, "base=localtime");
		if (conf->debug_port != NULL) {
			WRITE_STR(fp, "-gdb");
			WRITE_FMT(fp, "tcp::%s", conf->debug_port);
		}
		WRITE_STR(fp, "-smp");
		WRITE_STR(fp, conf->ncpu);
		WRITE_STR(fp, "-m");
		WRITE_STR(fp, conf->memory);
		if (conf->comport == NULL) {
			WRITE_STR(fp, "-monitor");
			WRITE_STR(fp, "-stdio");
		} else if (strcasecmp(conf->comport, "stdio") == 0) {
			WRITE_STR(fp, "-chardev");
			WRITE_STR(fp, "stdio,mux=on,id=char0,signal=off");
			WRITE_STR(fp, "-mon");
			WRITE_STR(fp, "chardev=char0,mode=readline");
			WRITE_STR(fp, "-serial");
			WRITE_STR(fp, "chardev:char0");
		} else {
			WRITE_STR(fp, "-monitor");
			WRITE_STR(fp, "stdio");
			WRITE_STR(fp, "-chardev");
			WRITE_FMT(fp, "serial,path=%s,id=char0,signal=off",
			    conf->comport);
			WRITE_STR(fp, "-serial");
			WRITE_STR(fp, "chardev:char0");
		}

		WRITE_STR(fp, "-boot");
		WRITE_STR(fp, conf->install ? "d" : "c");

		int i = 0;
		STAILQ_FOREACH (dc, &conf->disks, next) {
			WRITE_STR(fp, "-blockdev");
			if (strncmp(dc->path, "/dev/", 4) == 0) {
				WRITE_FMT(fp,
				    "node-name=blk%d,driver=raw,file.driver=host_device,file.filename=%s",
				    i, dc->path);
			} else {
				WRITE_FMT(fp,
				    "node-name=blk%d,driver=file,filename=%s",
				    i++, dc->path);
			}
			WRITE_STR(fp, "-device");
			WRITE_FMT(fp, "%s,drive=blk%d", dc->type, i);
			i++;
		}
		ic = STAILQ_FIRST(&conf->isoes);
		if (ic != NULL) {
			WRITE_STR(fp, "-cdrom");
			WRITE_STR(fp, ic->path);
		}
		STAILQ_FOREACH (nc, &vm->taps, next) {
			WRITE_STR(fp, "-nic");
			WRITE_FMT(fp, "tap,ifname=%s", nc->tap);
		}
		if (conf->fbuf->enable) {
			struct fbuf *fb = conf->fbuf;
			WRITE_STR(fp, "-vga");
			WRITE_STR(fp, "std");
			WRITE_STR(fp, "-vnc");
			WRITE_FMT(fp, ":%d", fb->port - 5900);
		}
		if (conf->mouse) {
			WRITE_STR(fp, "-usb");
		}
		WRITE_STR(fp, "-name");
		WRITE_STR(fp, conf->name);
		WRITE_STR(fp, NULL);

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

static int
start_qemu(struct vm *vm)
{
	if (STAILQ_FIRST(&vm->taps) == NULL && assign_taps(vm) < 0)
		return -1;

	if (activate_taps(vm) < 0)
		goto err;

	if (exec_qemu(vm) < 0)
		goto err;

	return 0;
err:
	remove_taps(vm);
	return -1;
}

static void
cleanup_qemu(struct vm *vm)
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
#undef VM_CLOSE_FD
	remove_taps(vm);
	if (vm->mapfile) {
		unlink(vm->mapfile);
		free(vm->mapfile);
		vm->mapfile = NULL;
	}
	vm->state = TERMINATE;
}

static int
put_command(struct vm *vm, char *cmd)
{
	ssize_t rc;
	size_t len, n;

	if (vm->infd == -1)
		return 0;

	len = strlen(cmd);

	for (n = 0; n < len;) {
		if ((rc = write(vm->infd, cmd + n, len - n)) < 0)
			switch (errno) {
			case EINTR:
			case EAGAIN:
				continue;
			case EPIPE:
				close(vm->infd);
				vm->infd = -1;
				/* FALLTHROUGH */
			default:
				return -1;
			}
		n += rc;
	}

	return n;
}

static int
reset_qemu(struct vm *vm)
{
	return put_command(vm, "system_reset\n");
}

static int
poweroff_qemu(struct vm *vm)
{
	return put_command(vm, "quit\n");
}

static int
acpi_poweroff_qemu(struct vm *vm)
{
	return put_command(vm, "system_powerdown\n");
}

struct vm_methods method_list[] = {
	{ start_bhyve, reset_bhyve, poweroff_bhyve, acpi_poweroff_bhyve,
	  cleanup_bhyve },
	{ start_qemu, reset_qemu, poweroff_qemu, acpi_poweroff_qemu,
	  cleanup_qemu }
};
