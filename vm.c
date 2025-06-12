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
#include "inspect.h"
#include "log.h"
#include "vm.h"

#define UEFI_CSM_FIRMWARE  LOCALBASE "/share/uefi-firmware/BHYVE_UEFI_CSM.fd"
#define UEFI_FIRMWARE	   LOCALBASE "/share/uefi-firmware/BHYVE_UEFI.fd"
#define UEFI_FIRMWARE_VARS LOCALBASE "/share/uefi-firmware/BHYVE_UEFI_VARS.fd"

#if __FreeBSD_version > 1400000
static int
copy_uefi_vars(struct vm *vm)
{
	char *p;
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

	if (is_install(conf) == false && is_file(fn))
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

	if ((pid = fork()) < 0)  {
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
		STAILQ_FOREACH(be, &conf->bhyveload_envs, next)
			fprintf(fp, "-e\n%s\n", &be->env[0]);
		if (conf->bhyveload_loader)
			fprintf(fp, "-l\n%s\n", conf->bhyveload_loader);
		fprintf(fp, "-c\n%s\n", com != NULL ? com : "stdio");
		fprintf(fp, "-m\n%s\n", conf->memory);
		fprintf(fp, "-d\n%s\n",
		    (conf->install) ? STAILQ_FIRST(&conf->isoes)->path :
				      STAILQ_FIRST(&conf->disks)->path);
		fprintf(fp, "%s\n", conf->name);
		funlockfile(fp);
		fclose(fp);

		argv = split_args(bp);
		if (argv == NULL) {
			ERR("malloc %s\n", strerror(errno));
			exit(1);
		}
		if (dopipe) {
			char **t;
			for (t = argv; *t != NULL; t++)
				printf("%s ", *t);
			printf("\n");
			fflush(stdout);
		}
		execv(argv[0], argv);
		ERR("cannot exec %s\n", argv[0]);
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
	int pcid;
	int outfd[2], errfd[2];
	char *com0 = vm->assigned_com[0];
	bool dopipe = (com0 == NULL || strcasecmp(com0, "stdio") != 0);

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
		char **args, **com, *buf;
		size_t buf_size;
		FILE *fp;

		/* child process */
		if (dopipe) {
			close(outfd[0]);
			close(errfd[0]);
			dup2(outfd[1], 1);
			dup2(errfd[1], 2);
		}

		STAILQ_FOREACH(be, &conf->bhyve_envs, next)
			if (putenv(be->env) < 0)
				ERR("invalid environment: %s", be->env);

		fp = open_memstream(&buf, &buf_size);
		if (fp == NULL) {
			ERR("cannot open memstream (%s)\n", strerror(errno));
			exit(1);
		}
		flockfile(fp);

#if __FreeBSD_version > 1500023
		fprintf(fp, "/usr/sbin/bhyve\n-H\n-w\n");
#else
		fprintf(fp, "/usr/sbin/bhyve\n-A\n-H\n-w\n");
#endif
		if (conf->x2apic == true)
			fprintf(fp, "-x\n");
		if (conf->utctime == true)
			fprintf(fp, "-u\n");
		if (conf->wired_memory == true)
			fprintf(fp, "-S\n");
		if (conf->debug_port != NULL)
			fprintf(fp, "-G\n%s\n", conf->debug_port);

		fprintf(fp, "-c\ncpus=%d,sockets=%d,cores=%d,threads=%d\n",
		    conf->ncpu, conf->ncpu_sockets, conf->ncpu_cores,
		    conf->ncpu_threads);
		STAILQ_FOREACH(cp, &conf->cpu_pins, next)
			fprintf(fp, "-p\n%d:%d\n", cp->vcpu, cp->hostcpu);
		fprintf(fp, "-m\n%s\n", conf->memory);
		ARRAY_FOREACH(com, vm->assigned_com)
			if (*com != NULL)
				fprintf(fp, "-l\ncom%ld,%s\n",
				    CONF_COM_NUM(com, vm->assigned_com), *com);

		if (conf->keymap != NULL)
			fprintf(fp, "-K\n%s\n", conf->keymap);

		if (vm->bootrom != NULL) {
			fprintf(fp, "-l\nbootrom,%s", vm->bootrom);
			if (vm->varsfile)
				fprintf(fp, ",%s", vm->varsfile);
			fprintf(fp, "\n");
		}

		if (conf->tpm_dev) {
			if (conf->tpm_version)
				fprintf(fp, "-l\ntpm,%s,%s,version=%s\n",
				    conf->tpm_type, conf->tpm_dev,
				    conf->tpm_version);
			else
				fprintf(fp, "-l\ntpm,%s,%s\n", conf->tpm_type,
				    conf->tpm_dev);
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
		if (conf->virt_random)
			fprintf(fp, "-s\n%d,virtio-rnd\n", pcid++);
		STAILQ_FOREACH(dc, &conf->disks, next) {
			fprintf(fp, "-s\n%d,%s,%s", pcid++, dc->type, dc->path);
			if (dc->nocache)
				fprintf(fp, ",nocache");
			if (dc->direct)
				fprintf(fp, ",direct");
			if (dc->readonly)
				fprintf(fp, ",ro");
			if (dc->nodelete)
				fprintf(fp, ",nodelete");
			fprintf(fp, "\n");
		}
		STAILQ_FOREACH(ic, &conf->isoes, next)
			fprintf(fp, "-s\n%d,%s,%s\n", pcid++, ic->type,
			    ic->path);
		STAILQ_FOREACH(sc, &conf->sharefss, next)
			fprintf(fp, "-s\n%d,virtio-9p,%s=%s%s\n", pcid++,
			    sc->name, sc->path, (sc->readonly) ? ",ro" : "");
		STAILQ_FOREACH(nc, &vm->taps, next) {
			fprintf(fp, "-s\n%d,%s", pcid++, nc->type);
			if (nc->tap)
				fprintf(fp, ",%s", nc->tap);
			else if (nc->vale)
				fprintf(fp, ",%s:%s", nc->vale, nc->vale_port);
			if (nc->mac)
				fprintf(fp, ",mac=%s", nc->mac);
			fprintf(fp, "\n");
		}
		STAILQ_FOREACH(pc, &conf->passthrues, next)
			fprintf(fp, "-s\n%d,passthru,%s\n", pcid++, pc->devid);
		STAILQ_FOREACH(hc, &conf->hdas, next) {
			fprintf(fp, "-s\n%d,hda", pcid++);
			if (*hc->play_dev != '\0')
				fprintf(fp, ",play=%s", hc->play_dev);
			if (*hc->rec_dev != '\0')
				fprintf(fp, ",rec=%s", hc->rec_dev);
			fprintf(fp, "\n");
		}
		if (conf->fbuf->enable) {
			struct fbuf *fb = conf->fbuf;
			fprintf(fp, "-s\n%d,fbuf,tcp=%s:%d,w=%d,h=%d,vga=%s%s",
			    pcid++, fb->ipaddr, fb->port, fb->width, fb->height,
			    fb->vgaconf, fb->wait ? ",wait" : "");
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

int
write_err_log(int fd, struct vm *vm)
{
	int rc;
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
		rc = writen(vm->logfd, buf, size);
		if (rc < 0)
			ERR("%s: failed to write err_logfile (%s)\n",
			    vm->conf->name, strerror(errno));
		if (rc <= 0) {
			close(vm->logfd);
			vm->logfd = -1;
		}
	}

	return size;
}

PLUGIN_VM_METHOD(bhyve, exec_bhyve, reset_bhyve, poweroff_bhyve,
    acpi_poweroff_bhyve, cleanup_bhyve);
PLUGIN_LOADER_METHOD(bhyveload, bhyve_load, NULL);
PLUGIN_LOADER_METHOD(uefi, uefi_load, NULL);
PLUGIN_LOADER_METHOD(csm, csm_load, NULL);

PLUGIN_METHOD_MODULE(bhyve, &bhyve, &bhyveload);
PLUGIN_METHOD_MODULE(uefi, NULL, &uefi);
PLUGIN_METHOD_MODULE(csm, NULL, &csm);
