/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Yuichiro Naito
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <machine/vmm.h>
#include <machine/vmm_dev.h>
#if __FreeBSD_version > 1500026
#include <dev/vmm/vmm_dev.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "bmd_plugin.h"
#include "conf.h"
#include "log.h"
#include "vm.h"

#define MAX_PCI_BUS 256
#define MAX_PCI_SLOT 32
#define MAX_PCI_DEVICES (MAX_PCI_BUS * MAX_PCI_SLOT)

#define PCISLOT(a, fmt, s, ...)                                      \
	{                                                             \
		ARG_OPT(a, "-s", "%d:%d:0," fmt, (s) >> 5, (s) & 0x1f,	\
		    __VA_ARGS__);                                     \
		if (++s > MAX_PCI_DEVICES) {                          \
			ERR("too many PCI devices\n", NULL);          \
			exit(1);                                      \
		}                                                     \
	}

#define PCIWRITE(a, fmt, s, ...)                                      \
	{                                                             \
	        ARG_PUT(a, "-s");				      \
		ARG_WRITE(a, "%d:%d:0," fmt, (s) >> 5, (s) & 0x1f,    \
		    __VA_ARGS__);                                     \
		if (++s > MAX_PCI_DEVICES) {                          \
			ERR("too many PCI devices\n", NULL);          \
			exit(1);                                      \
		}                                                     \
	}

#define UEFI_CSM_FIRMWARE  LOCALBASE "/share/uefi-firmware/BHYVE_UEFI_CSM.fd"
#define UEFI_FIRMWARE	   LOCALBASE "/share/uefi-firmware/BHYVE_UEFI.fd"
#define UEFI_FIRMWARE_VARS LOCALBASE "/share/uefi-firmware/BHYVE_UEFI_VARS.fd"

#if __FreeBSD_version > 1400000
static bool
check_vars_file(const char *path)
{
	struct stat s;

	return (lstat(path, &s) == 0 && S_ISREG(s.st_mode) && s.st_size > 0);
}

static int
copy_uefi_vars(struct vm *vm)
{
	char *p, *tmp;
	int out, in, rc;
	ssize_t n;
	off_t len = 0;
	struct stat st;
	const char *fn, *origin = UEFI_FIRMWARE_VARS;
	struct vm_conf *conf = vm_get_conf(vm);

	if ((fn = get_varsfile(vm)) == NULL) {
		if (asprintf(&p, "%s/%s.vars", get_varsdir(), get_name(conf)) <
		    0)
			return -1;
		rc = set_varsfile(vm, p);
		free(p);
		if (rc < 0)
			return -1;
		fn = get_varsfile(vm);
	}

	if (is_install(conf) == false && check_vars_file(fn))
		return 0;

	while ((in = open(origin, O_RDONLY)) < 0)
		if (errno != EINTR)
			break;
	if (in < 0) {
		ERR("cannot open %s\n", origin);
		return -1;
	}

	if (asprintf(&tmp, "%s.XXXXXX", fn) < 0) {
		close(in);
		return -1;
	}

	if ((out = mkstemp(tmp)) < 0) {
		ERR("can't create %s\n", tmp);
		close(in);
		free(tmp);
		return -1;
	}

	if (fstat(in, &st) < 0)
		goto err;

retry:
	while (
	    (n = copy_file_range(in, &len, out, &len, st.st_size - len, 0)) < 0)
		if (errno != EINTR)
			goto err;
	if (n > 0) {
		len += n;
		if (len < st.st_size)
			goto retry;
	}

	close(in);
	close(out);

	if ((rc = rename(tmp, fn)) < 0) {
		ERR("can't create %s\n", fn);
		goto err2;
	}

	chmod(fn, 0644);
	return 0;
err:
	close(in);
	close(out);
err2:
	unlink(tmp);
	free(tmp);
	return -1;
}
#else
static int
copy_uefi_vars(struct vm *vm __unused)
{
	return 0;
}
#endif

struct arg_builder *
arg_init(void)
{
	struct arg_builder *a;
	if ((a = malloc(sizeof(*a))) == NULL)
		goto err3;
	a->args_size = DEFAULT_ARG_SIZE;
	a->args_len = 0;
	if ((a->args = malloc(sizeof(char *) * a->args_size)) == NULL)
		goto err2;
	if ((a->cur = open_memstream(&a->cur_buf, &a->cur_len)) == NULL)
		goto err;

	return a;
err:
	free(a->args);
err2:
	free(a);
err3:
	return NULL;
}

void
arg_free(struct arg_builder *a)
{
	size_t i;

	if (a == NULL)
		return;

	for (i = 0; i < a->args_len; i++)
		free(a->args[i]);
	fclose(a->cur);
	free(a->cur_buf);
	free(a->args);
	free(a);
}

int
arg_write(struct arg_builder *a, const char *f, ...)
{
	int rc;
	va_list va;

	va_start(va, f);
	rc = vfprintf(a->cur, f, va);
	va_end(va);

	return rc;
}

static int
arg_push(struct arg_builder *a, char *v)
{
	size_t ns;
	char **p;

	if (a->args_len >= a->args_size) {
		ns = a->args_size + DEFAULT_ARG_SIZE;
		if ((p = realloc(a->args, sizeof(char *) * ns)) == NULL)
			return -1;
		a->args = p;
		a->args_size = ns;
	}

	a->args[a->args_len++] = v;
	return 0;
}

int
arg_next(struct arg_builder *a)
{
	fclose(a->cur);
	if (arg_push(a, a->cur_buf) < 0 ||
	    (a->cur = open_memstream(&a->cur_buf, &a->cur_len)) == NULL)
		return -1;

	return 0;
}

int
arg_put(struct arg_builder *a, const char *s)
{
	return (fprintf(a->cur, "%s", s) < 0 || arg_next(a) < 0) ? -1 : 0;
}

int
arg_opt(struct arg_builder *a, const char *s, const char *f, ...)
{
	int rc;
	va_list va;

	if (arg_put(a, s) < 0)
		return -1;
	va_start(va, f);
	rc = vfprintf(a->cur, f, va);
	va_end(va);
	if (rc < 0 || arg_next(a) < 0)
		return -1;
	return 0;
}

void
arg_print(FILE *f, struct arg_builder *a)
{
	size_t i = 0;

	if (a->args_len == 0)
		return;

	fprintf(f, "%s", a->args[i++]);
	while (i < a->args_len)
		fprintf(f, " %s", a->args[i++]);
	fprintf(f, "\n");
	fflush(f);
	return;
}

int
arg_execv(const char *p, struct arg_builder *a)
{
	if (arg_push(a, NULL) < 0)
		return -1;

	return execv(p, a->args);
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
	for (ap = ap0; (*ap = strsep(&p, "\n")) != NULL;)
		if (**ap != '\0' && ++ap >= &ap0[n])
			break;

	return (ap0);
}

static int
csm_load(struct vm *vm, nvlist_t *pl_conf __unused)
{
	return set_bootrom(vm, UEFI_CSM_FIRMWARE) == 0 ? 1 : -1;
}

static int
uefi_load(struct vm *vm, nvlist_t *pl_conf __unused)
{
	return (set_bootrom(vm, UEFI_FIRMWARE) < 0 || copy_uefi_vars(vm) < 0) ?
	    -1 :
	    1;
}

static int
bhyve_load(struct vm *vm, nvlist_t *pl_conf __unused)
{
	pid_t pid;
	int outfd[2], errfd[2];
	struct bhyveload_env *be;
	struct vm_conf *conf = vm->conf;
	char *com = vm->assigned_com[0];
	bool dopipe = (com == NULL || strcasecmp(com, "stdio") != 0);

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

	if ((pid = fork()) < 0) {
		ERR("cannot fork (%s)\n", strerror(errno));
		if (dopipe) {
			close(outfd[0]);
			close(outfd[1]);
			close(errfd[0]);
			close(errfd[1]);
		}
		return (-1);
	}

	if (pid == 0) {
		struct arg_builder *a;

		if (dopipe) {
			close(outfd[0]);
			close(errfd[0]);
			dup2(outfd[1], 1);
			dup2(errfd[1], 2);
		}
		if ((a = arg_init()) == NULL) {
			ERR("%s\n", "failed to alloc arg_builder");
			exit(1);
		}

		ARG_PUT(a, strrchr(BHYVELOAD_PATH, '/') + 1);
		if (conf->wired_memory == true)
			ARG_PUT(a, "-S");
		if (conf->single_user)
			ARG_OPT(a, "-e", "boot_single=%s", "YES");
		STAILQ_FOREACH(be, &conf->bhyveload_envs, next)
			ARG_OPT(a, "-e", "%s", &be->env[0]);
		if (conf->bhyveload_loader)
			ARG_OPT(a, "-l", "%s", conf->bhyveload_loader);
		ARG_OPT(a, "-c", "%s", com != NULL ? com : "stdio");
		ARG_OPT(a, "-m", "%s", conf->memory);
		ARG_OPT(a, "-d", "%s",
		    (conf->install) ? STAILQ_FIRST(&conf->isoes)->path :
				      STAILQ_FIRST(&conf->disks)->path);
		ARG_PUT(a, conf->name);

		if (dopipe)
			arg_print(stdout, a);
		arg_execv(BHYVELOAD_PATH, a);
		ERR("cannot exec %s (%s)\n", BHYVELOAD_PATH,
		    strerror(errno));
		exit(1);
	arg_error:
		ERR("cannot build %s arguments\n", BHYVELOAD_PATH);
		exit(1);
	}

	if (dopipe) {
		close(outfd[1]);
		close(errfd[1]);
		vm->outfd = outfd[0];
		vm->errfd = errfd[0];
	}
	vm->pid = pid;
	vm->state = LOAD;
	/* The target kernel is loaded, Boot ROM isn't necessary. */
	clear_bootrom(vm);
	return 0;
}

int
remove_taps(struct vm *vm)
{
	int s;
	struct net_conf *nc, *nnc;

	while ((s = socket(AF_LOCAL, SOCK_DGRAM, 0)) < 0)
		if (errno != EAGAIN && errno != EINTR)
			return -1;

	STAILQ_FOREACH_SAFE(nc, &vm->taps, next, nnc) {
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

	if (STAILQ_FIRST(&vm->taps) != NULL)
		return 0;

	STAILQ_FOREACH(nc, &conf->nets, next) {
		if ((nnc = copy_net_conf(nc)) == NULL)
			goto err;
		STAILQ_INSERT_TAIL(&vm->taps, nnc, next);
	}

	while ((s = socket(AF_LOCAL, SOCK_DGRAM, 0)) < 0)
		if (errno != EAGAIN && errno != EINTR)
			goto err;

	i = 0;
	STAILQ_FOREACH(nc, &vm->taps, next) {
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
	STAILQ_FOREACH_SAFE(nc, &vm->taps, next, nnc)
		free_net_conf(nc);
	STAILQ_INIT(&vm->taps);
	return -1;
}

static int
check_parameters(struct vm *vm)
{
	struct vm_conf *conf = vm->conf;
	struct fbuf *fb = conf->fbuf;
	struct stat st;

	if (fb->enable && fb->unixpath && stat(fb->unixpath, &st) == 0) {
		ERR("%s: graphics: %s already exists\n", conf->name,
		    fb->unixpath);
		return -1;
	}
	return 0;
}

static int
exec_bhyve(struct vm *vm, nvlist_t *pl_conf __unused)
{
	struct vm_conf *conf = vm->conf;
	struct passthru_conf *pc;
	struct disk_conf *dc;
	struct sharefs_conf *sc;
	struct iso_conf *ic;
	struct net_conf *nc;
	struct bhyve_env *be;
	struct cpu_pin *cp;
	struct hda_conf *hc;
	pid_t pid;
	int i, j, k, outfd[2], errfd[2];
	char *com0 = vm->assigned_com[0];
	bool dopipe = (com0 == NULL || strcasecmp(com0, "stdio") != 0);

	if (check_parameters(vm) < 0)
		return -1;

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

	if ((pid = fork()) < 0) {
		ERR("cannot fork (%s)\n", strerror(errno));
		return -1;
	}

	if (pid == 0) {
		struct arg_builder *a;
		char **com;
		unsigned int pcid = 0;

		/* child process */
		if (dopipe) {
			close(outfd[0]);
			close(errfd[0]);
			dup2(outfd[1], 1);
			dup2(errfd[1], 2);
		}

		STAILQ_FOREACH(be, &conf->bhyve_envs, next)
			if (putenv(be->env) < 0)
				ERR("invalid environment: %s\n", be->env);

		if ((a = arg_init()) == NULL) {
			ERR("%s\n", "failed to alloc arg_builder");
			exit(1);
		}

		ARG_PUT(a, strrchr(BHYVE_PATH, '/') + 1);
#if __FreeBSD_version < 1500024
		ARG_PUT(a, "-A");
#endif
		ARG_PUT(a, "-H");
		ARG_PUT(a, "-w");

		if (conf->x2apic == true)
			ARG_PUT(a, "-x");
		if (conf->utctime == true)
			ARG_PUT(a, "-u");
		if (conf->wired_memory == true)
			ARG_PUT(a, "-S");
		if (conf->debug_port != NULL)
			ARG_OPT(a, "-G", "%s", conf->debug_port);

		ARG_OPT(a, "-c", "cpus=%d,sockets=%d,cores=%d,threads=%d",
		    conf->ncpu, conf->ncpu_sockets, conf->ncpu_cores,
		    conf->ncpu_threads);
		STAILQ_FOREACH(cp, &conf->cpu_pins, next)
			ARG_OPT(a, "-p", "%d:%d", cp->vcpu, cp->hostcpu);
		ARG_OPT(a, "-m", "%s", conf->memory);
		ARRAY_FOREACH(com, vm->assigned_com)
			if (*com != NULL)
				ARG_OPT(a, "-l", "com%ld,%s",
				    CONF_COM_NUM(com, vm->assigned_com), *com);

		if (conf->keymap != NULL)
			ARG_OPT(a, "-K", "%s", conf->keymap);

		if (vm->bootrom != NULL) {
			ARG_PUT(a, "-l");
			ARG_WRITE(a, "bootrom,%s", vm->bootrom);
			if (vm->varsfile)
				ARG_WRITE(a, ",%s", vm->varsfile);
			ARG_NEXT(a);
		}

		if (conf->tpm_dev) {
			if (conf->tpm_version) {
				ARG_OPT(a, "-l", "tpm,%s,%s,version=%s",
				    conf->tpm_type, conf->tpm_dev,
				    conf->tpm_version);
			} else {
				ARG_OPT(a, "-l", "tpm,%s,%s", conf->tpm_type,
				    conf->tpm_dev);
			}
		}

		switch (conf->hostbridge) {
		case NONE:
			break;
		case INTEL:
			PCISLOT(a, "hostbridge", pcid, NULL);
			break;
		case AMD:
			PCISLOT(a, "amd_hostbridge", pcid, NULL);
			break;
		}
		PCISLOT(a, "lpc", pcid, NULL);

		if (conf->virt_random)
			PCISLOT(a, "virtio-rnd", pcid, NULL);
		STAILQ_FOREACH(dc, &conf->disks, next) {
			PCIWRITE(a, "%s,%s", pcid, dc->type, dc->path);
			if (dc->nocache)
				ARG_WRITE(a, "%s", ",nocache");
			if (dc->direct)
				ARG_WRITE(a, "%s", ",direct");
			if (dc->readonly)
				ARG_WRITE(a, "%s", ",ro");
			if (dc->nodelete)
				ARG_WRITE(a, "%s", ",nodelete");
			ARG_NEXT(a);
		}
		STAILQ_FOREACH(ic, &conf->isoes, next)
			PCISLOT(a, "%s,%s", pcid, ic->type, ic->path);
		STAILQ_FOREACH(sc, &conf->sharefss, next)
			PCISLOT(a, "virtio-9p,%s=%s%s", pcid, sc->name,
			    sc->path, (sc->readonly) ? ",ro" : "");
		STAILQ_FOREACH(nc, &vm->taps, next) {
			PCIWRITE(a, "%s", pcid, nc->type);
			if (nc->tap) {
				ARG_WRITE(a, ",%s", nc->tap);
			} else if (nc->vale) {
				ARG_WRITE(a, ",%s:%s", nc->vale, nc->vale_port);
			} if (nc->mac) {
				ARG_WRITE(a, ",mac=%s", nc->mac);
			}
			ARG_NEXT(a);
		}
		STAILQ_FOREACH(pc, &conf->passthrues, next)
			PCISLOT(a, "passthru,%s", pcid, pc->devid);
		STAILQ_FOREACH(hc, &conf->hdas, next) {
			PCIWRITE(a, "hda", pcid, NULL);
			if (*hc->play_dev != '\0')
				ARG_WRITE(a, ",play=%s", hc->play_dev);
			if (*hc->rec_dev != '\0')
				ARG_WRITE(a, ",rec=%s", hc->rec_dev);
			ARG_NEXT(a);
		}
		for (i = 0, k = 0; i < conf->virt_console_ncontrollers; i++) {
			PCIWRITE(a, "virtio-console", pcid, NULL);
			for (j = 0; j < conf->virt_console_nports; j++, k++)
				ARG_WRITE(a, ",%s", vm->virt_console_paths[k]);
			ARG_NEXT(a);
                }
		if (conf->fbuf->enable) {
			struct fbuf *fb = conf->fbuf;
			if (fb->unixpath) {
				PCIWRITE(a, "fbuf,rfb=unix:%s,w=%d,h=%d,vga=%s%s",
				    pcid, fb->unixpath, fb->width, fb->height,
				    fb->vgaconf, fb->wait ? ",wait" : "");
			} else {
				PCIWRITE(a, "fbuf,tcp=%s:%d,w=%d,h=%d,vga=%s%s",
				    pcid, fb->ipaddr, fb->port, fb->width,
				    fb->height, fb->vgaconf,
				    fb->wait ? ",wait" : "");
			}
			if (fb->password)
				ARG_WRITE(a, ",password=%s", fb->password);
			ARG_NEXT(a);
		}
		if (conf->mouse)
			PCISLOT(a, "xhci,tablet", pcid, NULL);
		if (pcid > MAX_PCI_SLOT)
			ARG_PUT(a, "-Y");
		ARG_PUT(a, conf->name);

		if (dopipe)
			arg_print(stdout, a);
		arg_execv(BHYVE_PATH, a);
		ERR("cannot exec %s (%s)\n", BHYVE_PATH,
		    strerror(errno));
		exit(1);
	arg_error:
		ERR("cannot build %s arguments\n", BHYVE_PATH);
		exit(1);
	}

	/* parent process */
	if (dopipe) {
		close(outfd[1]);
		close(errfd[1]);
		vm->outfd = outfd[0];
		vm->errfd = errfd[0];
	}
	vm->pid = pid;
	vm->state = RUN;
	return 0;
}

static int
destroy_bhyve(struct vm *vm)
{
	char *name = vm->conf->name;
#if __FreeBSD_version > 1500026
	int rc, fd;
	struct vmmctl_vm_destroy vmd;

	while ((fd = open("/dev/vmmctl", O_RDWR)) < 0)
		if (errno != EINTR)
			break;
	if (fd < 0)
		return -1;

	memset(&vmd, 0, sizeof(vmd));
	(void)strlcpy(vmd.name, name, sizeof(vmd.name));
	rc = ioctl(fd, VMMCTL_VM_DESTROY, &vmd);
	close(fd);
	return rc;
#else
	return sysctlbyname("hw.vmm.destroy", NULL, 0, name, strlen(name));
#endif
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

static void
cleanup_bhyve(struct vm *vm, nvlist_t *pl_conf __unused)
{
	destroy_bhyve(vm);
}

ssize_t
writen(int fd, const void *buf, size_t size)
{
	uintptr_t b = (uintptr_t)buf;
	size_t n = 0;
	ssize_t rc;

	while (n < size) {
		while ((rc = write(fd, (void *)(b + n), size - n)) < 0)
			if (errno != EINTR && errno != EAGAIN)
				break;
		if (rc <= 0)
			return rc;
		n += rc;
	}
	return n;
}

PLUGIN_VM_METHOD(bhyve, exec_bhyve, reset_bhyve, poweroff_bhyve,
    acpi_poweroff_bhyve, cleanup_bhyve);
PLUGIN_LOADER_METHOD(bhyveload, bhyve_load, NULL);
PLUGIN_LOADER_METHOD(uefi, uefi_load, NULL);
PLUGIN_LOADER_METHOD(csm, csm_load, NULL);

PLUGIN_METHOD_MODULE(bhyve, &bhyve, &bhyveload);
PLUGIN_METHOD_MODULE(uefi, NULL, &uefi);
PLUGIN_METHOD_MODULE(csm, NULL, &csm);
