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
#include "vm.h"
#include "inspect.h"

#define UEFI_CSM_FIRMWARE   LOCALBASE"/share/uefi-firmware/BHYVE_UEFI_CSM.fd"
#define UEFI_FIRMWARE       LOCALBASE"/share/uefi-firmware/BHYVE_UEFI.fd"
#define UEFI_FIRMWARE_VARS  LOCALBASE"/share/uefi-firmware/BHYVE_UEFI_VARS.fd"

static int
redirect_to_com(struct vm *vm, bool redirect_stdin)
{
	int fd, flag;
	const char *com;

	if ((com = vm->assigned_comport) == NULL)
		com = "/dev/null";

	flag = (redirect_stdin) ? O_RDWR : O_WRONLY;

	/*
	  Set O_NONBLOCK not to wait for peer connects to this nmdm.
	  The kernel sometimes fails to open with ENOENT, retry open it.
	  Basically the nmdm device is automatically created, I'm not sure why
	  ENOENT is returned.
	 */
	while ((fd = open(com, flag | O_NONBLOCK)) < 0)
		if (errno != EINTR && errno != ENOENT)
			break;
	if (fd < 0) {
		ERR("can't open %s (%s)\n", com, strerror(errno));
		return -1;
	}
	if (redirect_stdin)
		dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);

	return 0;
}

int
write_mapfile(struct vm_conf *conf, char **mapfile)
{
	int fd, i;
	char *fn;
	FILE *fp;
	struct disk_conf *dc;
	struct iso_conf *ic;

	if (asprintf(&fn, "/tmp/bmd.%s.%d.XXXXXX", conf->name, getpid()) < 0)
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

	if ((fp = fdopen(fd, "w+")) == NULL) {
		ERR("can't open mapfile (%s)\n", strerror(errno));
		goto err2;
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
err2:
	*mapfile = NULL;
	unlink(fn);
	free(fn);
	return -1;
}

#if __FreeBSD_version > 1400000
static int
copy_uefi_vars(struct vm *vm)
{
	char *fn;
	int out, in;
	ssize_t n;
	off_t len = 0;
	struct stat st;
	const char *origin = UEFI_FIRMWARE_VARS;
	extern struct global_conf *gl_conf;

	fn = vm->varsfile;
	if (fn == NULL && asprintf(&fn, "%s/%s.vars", gl_conf->vars_dir,
				   vm->conf->name) < 0)
		return -1;

	vm->varsfile = fn;
	if (vm->conf->install == false && is_file(fn))
		return 0;

	while ((in = open(origin, O_RDONLY)) < 0)
		if (errno != EINTR)
			break;
	if (in < 0) {
		ERR("cannot open %s\n", origin);
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
copy_uefi_vars(struct vm *vm __unused)
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

/*
 * split_args() separates an buffer that contains '\n' as the delimiter.
 * The results will be an array of pointers to portions of the buffer,
 * and the '\n' characters will be replaced with '\0'.  The array itself
 * will be allocated by malloc().
 */
char **
split_args(char *buf)
{
	char **ap0, **ap;
	char *p;
	int n;

	/* Scan '\n' in the buffer. */
	n = 0;
	p = buf;
	while ((p = strchr(p, '\n')) != NULL) {
		n++;
		p++;
	}

	/* The last component is always NULL. */
	ap0 = calloc(n + 1, sizeof(*ap0));
	if (ap0 == NULL)
		return (NULL);
	p = buf;
	for (ap = ap0; (*ap = strsep(&p, "\n")) != NULL; )
		if (**ap != '\0' && ++ap >= &ap0[n])
			break;

	return (ap0);
}

static int
grub_load(struct vm *vm)
{
	int ifd[2];
	pid_t pid;
	struct vm_conf *conf = vm->conf;
	size_t len;
	char *cmd;
	bool doredirect = (vm->assigned_comport == NULL) ||
	    (strcasecmp(vm->assigned_comport, "stdio") != 0);

	cmd = create_load_command(conf, &len);

	if (cmd != NULL && pipe(ifd) < 0) {
		ERR("cannot create pipe (%s)\n", strerror(errno));
		free(cmd);
		return -1;
	}

	pid = fork();
	if (pid > 0) {
		vm->pid = pid;
		vm->state = LOAD;
		if (cmd != NULL) {
			close(ifd[1]);
			vm->infd = ifd[0];
		} else
			vm->infd = -1;
		vm->outfd = -1;
		vm->errfd = -1;
		if (cmd != NULL) {
			write(ifd[0], cmd, len + 1);
			free(cmd);
		}
	} else if (pid == 0) {
		FILE *fp;
		char **argv, *bp;

		if (cmd != NULL) {
			close(ifd[0]);
			dup2(ifd[1], 0);
		}
		if (doredirect)
			redirect_to_com(vm, (cmd == NULL));

		fp = open_memstream(&bp, &len);
		if (fp == NULL) {
			ERR("cannot open memstream (%s)\n", strerror(errno));
			exit(1);
		}
		flockfile(fp);

		setenv("TERM", "vt100", 1);
		fprintf(fp, LOCALBASE"/sbin/grub-bhyve\n");
		if (conf->wired_memory == true)
			fprintf(fp, "-S\n");
		fprintf(fp, "-r\n");
		if (conf->install)
			fprintf(fp, "cd0\n");
		else if (conf->grub_run_partition)
			fprintf(fp, "hd0,%s\n", conf->grub_run_partition);
		else
			fprintf(fp, "hd0,1\n");
		fprintf(fp, "-M\n%s\n", conf->memory);
		fprintf(fp, "-m\n%s\n", vm->mapfile);
		fprintf(fp, "%s\n", conf->name);
		funlockfile(fp);
		fclose(fp);

		argv = split_args(bp);
		if (argv == NULL) {
			ERR("malloc: %s\n", strerror(errno));
			exit(1);
		}
		execv(argv[0], argv);
		ERR("cannot exec %s\n", argv[0]);
		exit(1);
	} else {
		ERR("cannot fork (%s)\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int
bhyve_load(struct vm *vm)
{
	pid_t pid;
	int outfd[2], errfd[2];
	struct bhyveload_env *be;
	struct vm_conf *conf = vm->conf;
	bool dopipe = (vm->assigned_comport == NULL) ||
	    (strcasecmp(vm->assigned_comport, "stdio") != 0);

	if (dopipe) {
		if (pipe(outfd) < 0) {
			ERR("cannot create pipe (%s)\n", strerror(errno));
			return (-1);
		}

		if (pipe(errfd) < 0) {
			ERR("cannot create pipe (%s)\n", strerror(errno));
			close(outfd[0]);
			close(outfd[1]);
			return (-1);
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
		char **argv;
		FILE *fp;
		char *bp;
		size_t len;

		if (dopipe) {
			close(outfd[0]);
			close(errfd[0]);
			dup2(outfd[1], 1);
			dup2(errfd[1], 2);
		}
		fp = open_memstream(&bp, &len);
		if (fp == NULL) {
			ERR("cannot open memstream (%s)\n", strerror(errno));
			exit(1);
		}
		flockfile(fp);

		fprintf(fp, "/usr/sbin/bhyveload\n");
		if (conf->wired_memory == true)
			fprintf(fp, "-S\n");
		if (conf->single_user)
			fprintf(fp, "-e\nboot_single=YES\n");
		STAILQ_FOREACH (be, &conf->bhyveload_envs, next)
			fprintf(fp, "-e\n%s\n", &be->env[0]);
		if (conf->bhyveload_loader)
			fprintf(fp, "-l\n%s\n", conf->bhyveload_loader);
		fprintf(fp, "-c\n%s\n", (vm->assigned_comport != NULL)
		    ? vm->assigned_comport
		    : "stdio");
		fprintf(fp, "-m\n%s\n", conf->memory);
		fprintf(fp, "-d\n%s\n", (conf->install)
		    ? STAILQ_FIRST(&conf->isoes)->path
		    : STAILQ_FIRST(&conf->disks)->path);
		fprintf(fp, "%s\n", conf->name);
		funlockfile(fp);
		fclose(fp);

		argv = split_args(bp);
		if (argv == NULL) {
			ERR("malloc %s\n", strerror(errno));
			exit(1);
		}
		execv(argv[0], argv);
		ERR("cannot exec %s\n", argv[0]);
		exit(1);
	} else {
		ERR("cannot fork (%s)\n", strerror(errno));
		if (dopipe) {
			close(outfd[0]);
			close(outfd[1]);
			close(errfd[0]);
			close(errfd[1]);
		}
		return (-1);
	}
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

	if (STAILQ_FIRST(&vm->taps) != NULL)
		return 0;

	STAILQ_FOREACH (nc, &conf->nets, next) {
		if ((nnc = copy_net_conf(nc)) == NULL)
			goto err;
		STAILQ_INSERT_TAIL(&vm->taps, nnc, next);
	}

	while ((s = socket(AF_LOCAL, SOCK_DGRAM, 0)) < 0)
		if (errno != EAGAIN && errno != EINTR)
			goto err;

	i = 0;
	STAILQ_FOREACH (nc, &vm->taps, next) {
		if (nc->bridge == NULL)
			continue;
		if (asprintf(&desc, "vm-%s-%d", conf->name, i++) < 0)
			continue;
		if (create_tap(s, &nc->tap) < 0 ||
		    set_tap_description(s, nc->tap, desc) < 0 ||
		    add_to_bridge(s, nc->bridge, nc->tap) < 0) {
			ERR("%s: failed to create tap for %s\n", conf->name,
			    nc->bridge);
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
	struct passthru_conf *pc;
	struct disk_conf *dc;
	struct iso_conf *ic;
	struct net_conf *nc;
	struct bhyve_env *be;
	struct cpu_pin *cp;
	pid_t pid;
	int pcid;
	int outfd[2], errfd[2];
	bool dopipe = ((vm->assigned_comport == NULL) ||
	    (strcasecmp(vm->assigned_comport, "stdio") != 0));

	if (dopipe) {
		if (pipe(outfd) < 0) {
			ERR("cannot create pipe (%s)\n", strerror(errno));
			return -1;
		}

		if (pipe(errfd) < 0) {
			ERR("cannot create pipe (%s)\n", strerror(errno));
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
		char **args;
		char *buf;
		size_t buf_size;
		FILE *fp;

		/* child process */
		if (dopipe) {
			close(outfd[0]);
			close(errfd[0]);
			dup2(outfd[1], 1);
			dup2(errfd[1], 2);
		}

		STAILQ_FOREACH (be, &conf->bhyve_envs, next)
			if (putenv(be->env) < 0)
				ERR("invalid environment: %s", be->env);

		fp = open_memstream(&buf, &buf_size);
		if (fp == NULL) {
			ERR("cannot open memstream (%s)\n", strerror(errno));
			exit(1);
		}
		flockfile(fp);

		fprintf(fp, "/usr/sbin/bhyve\n-A\n-H\n-w\n");
		if (conf->utctime == true)
			fprintf(fp, "-u\n");
		if (conf->wired_memory == true)
			fprintf(fp, "-S\n");
		if (conf->debug_port != NULL)
			fprintf(fp, "-G\n%s\n", conf->debug_port);

		fprintf(fp, "-c\ncpus=%d,sockets=%d,cores=%d,threads=%d\n",
			conf->ncpu, conf->ncpu_sockets, conf->ncpu_cores,
			conf->ncpu_threads);
		STAILQ_FOREACH (cp, &conf->cpu_pins, next)
			fprintf(fp, "-p\n%d:%d\n", cp->vcpu, cp->hostcpu);
		fprintf(fp, "-m\n%s\n", conf->memory);
		if (vm->assigned_comport != NULL)
			fprintf(fp, "-l\ncom1,%s\n", vm->assigned_comport);

		if (conf->keymap != NULL)
			fprintf(fp, "-K\n%s\n", conf->keymap);

		if (strcasecmp(conf->loader, "uefi") == 0) {
			fprintf(fp, "-l\nbootrom,%s", UEFI_FIRMWARE);
			if (vm->varsfile)
				fprintf(fp, ",%s", vm->varsfile);
			fprintf(fp, "\n");

		} else if (strcasecmp(conf->loader, "csm") == 0)
			fprintf(fp, "-l\nbootrom,%s\n", UEFI_CSM_FIRMWARE);

		if (conf->tpm_dev) {
			if (conf->tpm_version)
				fprintf(fp, "-l\ntpm,%s,%s,version=%s\n",
					conf->tpm_type,	conf->tpm_dev,
					conf->tpm_version);
			else
				fprintf(fp, "-l\ntpm,%s,%s\n",
					conf->tpm_type, conf->tpm_dev);
		}

		switch (conf->hostbridge) {
		case NONE:
			break;
		case INTEL:
			fprintf(fp, "-s\n0,hostbridge\n");
			break;
		case AMD:
			fprintf(fp, "-s\n0,amd_hostbridge\n");
			break;
		}
		fprintf(fp, "-s\n1,lpc\n");

		pcid = 2;
		STAILQ_FOREACH (dc, &conf->disks, next)
			fprintf(fp, "-s\n%d,%s,%s\n", pcid++, dc->type,
				dc->path);
		STAILQ_FOREACH (ic, &conf->isoes, next)
			fprintf(fp, "-s\n%d,%s,%s\n", pcid++, ic->type,
				ic->path);
		STAILQ_FOREACH (nc, &vm->taps, next) {
			if (nc->tap)
				fprintf(fp, "-s\n%d,%s,%s\n", pcid++, nc->type,
					nc->tap);
			else if (nc->vale)
				fprintf(fp, "-s\n%d,%s,%s:%s\n", pcid++,
					nc->type, nc->vale, nc->vale_port);
		}
		STAILQ_FOREACH (pc, &conf->passthrues, next)
			fprintf(fp, "-s\n%d,passthru,%s\n", pcid++, pc->devid);
		if (conf->fbuf->enable) {
			struct fbuf *fb = conf->fbuf;
			fprintf(fp, "-s\n%d,fbuf,tcp=%s:%d,w=%d,h=%d,vga=%s%s",
				pcid++, fb->ipaddr, fb->port, fb->width,
				fb->height, fb->vgaconf,
				fb->wait ? ",wait" : "");
			if (fb->password)
				fprintf(fp, ",password=%s", fb->password);
			fprintf(fp, "\n");
		}
		if (conf->mouse)
			fprintf(fp, "-s\n%d,xhci,tablet\n", pcid++);
		fprintf(fp, "%s\n", conf->name);

		funlockfile(fp);
		fclose(fp);
		args = split_args(buf);
		if (args == NULL) {
			ERR("malloc %s\n", strerror(errno));
			exit(1);
		}
		if (dopipe) {
			char **t;
			for (t = args; *t != NULL; t++)
				printf("%s ", *t);
			printf("\n");
			fflush(stdout);
		}
		execv(args[0], args);
		ERR("cannot exec %s\n", args[0]);
		exit(1);
	} else {
		ERR("cannot fork (%s)\n", strerror(errno));
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
reset_bhyve(struct vm *vm, nvlist_t *pl_conf __unused)
{
	return suspend_bhyve(vm, VM_SUSPEND_RESET);
}

static int
poweroff_bhyve(struct vm *vm, nvlist_t *pl_conf __unused)
{
	if (vm->state == LOAD)
		return kill(vm->pid, SIGKILL);
	return suspend_bhyve(vm, VM_SUSPEND_POWEROFF);
}

static int
acpi_poweroff_bhyve(struct vm *vm, nvlist_t *pl_conf __unused)
{
	return kill(vm->pid, SIGTERM);
}

static int
start_bhyve(struct vm *vm, nvlist_t *pl_conf __unused)
{
	struct vm_conf *conf = vm->conf;

	if (vm->state == LOAD)
		return exec_bhyve(vm);

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
	return -1;
}

static void
cleanup_bhyve(struct vm *vm, nvlist_t *pl_conf __unused)
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
	destroy_bhyve(vm);
	if (vm->mapfile) {
		unlink(vm->mapfile);
		free(vm->mapfile);
		vm->mapfile = NULL;
	}
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
			if (rc < 0)
				ERR("%s: failed to write err_logfile (%s)\n",
				    vm->conf->name, strerror(errno));
			if (rc <= 0) {
				close(vm->logfd);
				vm->logfd = -1;
				break;
			}
			n += rc;
		}
	}

	return size;
}

struct vm_method bhyve_method =
{"bhyve", start_bhyve, reset_bhyve, poweroff_bhyve, acpi_poweroff_bhyve,
	  cleanup_bhyve
};
