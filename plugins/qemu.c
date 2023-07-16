#include <sys/types.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "../bmd_plugin.h"

#define WRITE_STR(fp, str) \
	fwrite_unlocked(&(const char *[]) { (str) }[0], sizeof(char *), 1, (fp))

#define WRITE_FMT(fp, fmt, ...)                               \
	do {                                                  \
		char *p;                                      \
		asprintf(&p, (fmt), __VA_ARGS__);             \
		fwrite_unlocked(&p, sizeof(char *), 1, (fp)); \
	} while (0)

static PLUGIN_ENV *plugin_env;

static int
exec_qemu(struct vm *vm, nvlist_t *pl_conf)
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
	bool dopipe = ((vm->assigned_comport == NULL) ||
	    (strcasecmp(vm->assigned_comport, "stdio") != 0));

	if (dopipe) {
		if (pipe(infd) < 0) {
			return -1;
		}
		if (pipe(outfd) < 0) {
			close(infd[0]);
			close(infd[1]);
			return -1;
		}

		if (pipe(errfd) < 0) {
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
			exit(1);
		}
		flockfile(fp);

		WRITE_FMT(fp, LOCALBASE"/bin/qemu-system-%s",
			  nvlist_get_string(pl_conf, "qemu_arch"));
		WRITE_STR(fp, "-accel");
		WRITE_STR(fp, "tcg");
		if (nvlist_exists_string(pl_conf, "qemu_machine")) {
			const char *mac = nvlist_get_string(pl_conf, "qemu_machine");
			WRITE_STR(fp, "-machine");
			WRITE_STR(fp, mac);
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
		if (vm->assigned_comport == NULL) {
			WRITE_STR(fp, "-monitor");
			WRITE_STR(fp, "-stdio");
		} else if (strcasecmp(vm->assigned_comport, "stdio") == 0) {
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
			    vm->assigned_comport);
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
		exit(1);
	} else {
		exit(1);
	}

	return 0;
}

static int
start_qemu(struct vm *vm, nvlist_t *pl_conf)
{
	if (! nvlist_exists_string(pl_conf, "qemu_arch"))
		nvlist_add_string(pl_conf, "qemu_arch", "x86_64");

	if (plugin_env->assign_taps(vm) < 0)
		return -1;

	if (plugin_env->activate_taps(vm) < 0)
		goto err;

	if (exec_qemu(vm, pl_conf) < 0)
		goto err;

	return 0;
err:
	plugin_env->remove_taps(vm);
	return -1;
}

static void
cleanup_qemu(struct vm *vm, nvlist_t *pl_conf)
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
	plugin_env->remove_taps(vm);
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
reset_qemu(struct vm *vm, nvlist_t *pl_conf)
{
	return put_command(vm, "system_reset\n");
}

static int
poweroff_qemu(struct vm *vm, nvlist_t *pl_conf)
{
	return put_command(vm, "quit\n");
}

static int
acpi_poweroff_qemu(struct vm *vm, nvlist_t *pl_conf)
{
	return put_command(vm, "system_powerdown\n");
}

static int
qemu_initialize(PLUGIN_ENV *env)
{
	plugin_env = env;
	return 0;
}

static void
qemu_finalize()
{
}

static int
compare_archs(const void *a, const void *b)
{
	return strcasecmp((const char *)a, *(const char **)b);
}

static int
set_conf_value(nvlist_t *config, const char *key, const char *val)
{
	if (nvlist_exists_string(config, key))
		nvlist_free_string(config, key);

	nvlist_add_string(config, key, val);

	return nvlist_error(config) != 0 ? -1 : 0;
}

static int
parse_qemu_arch(nvlist_t *config, const char *key, const char *val)
{
	const char **p,
	    *archs[] = { "aarch64", "alpha", "arm", "cris", "hppa", "i386",
		    "lm32", "m68k", "microblaze", "microblazeel", "mips",
		    "mips64", "mips64el", "mipsel", "moxie", "nios2", "or1k",
		    "ppc", "ppc64", "riscv32", "riscv64", "rx", "s390x", "sh4",
		    "sh4eb", "sparc", "sparc64", "tricore", "unicore32",
		    "x86_64", "xtensa", "xtensaeb" };

	if ((p = bsearch(val, archs, sizeof(archs) / sizeof(archs[0]),
		 sizeof(archs[0]), compare_archs)) == NULL)
		return -1;

	return set_conf_value(config, key, *p);
}

static int
qemu_parse_config(nvlist_t *config, const char *key, const char *val)
{
	if (strcasecmp(key, "qemu_arch") == 0)
		return parse_qemu_arch(config, key, val);

	if (strcasecmp(key, "qemu_machine") == 0)
		return set_conf_value(config, key, val);

	return 1;
}

struct vm_method qemu_method = {
	"qemu",  start_qemu, reset_qemu, poweroff_qemu, acpi_poweroff_qemu,
	 cleanup_qemu
};

PLUGIN_DESC plugin_desc = {
	PLUGIN_VERSION, "qemu", qemu_initialize,
	qemu_finalize, NULL, qemu_parse_config, &qemu_method
};
