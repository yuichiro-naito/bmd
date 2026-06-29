/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2025 Yuichiro Naito
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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "bmd_plugin.h"
#include "inspect.h"
#include "log.h"
#include "vm.h"

struct grub_pty_buf {
	size_t command_len;
	char *command;
	int nwritten;
	char buf[1024];
};

#define PTYKEY "grubpty"
#define BUFKEY "grubbuf"

int
write_mapfile(struct vm_conf *conf, char **mapfile)
{
	int fd, i;
	char *fn;
	FILE *fp;
	struct disk_conf *dc;
	struct iso_conf *ic;

	if (asprintf(&fn, "/tmp/bmd.%s.%d.XXXXXX", get_name(conf), getpid()) <
	    0)
		return -1;

	fd = mkstemp(fn);
	if (fd < 0) {
		ERR("%s\n", "can't create mapfile");
		free(fn);
		return -1;
	}

	*mapfile = fn;

	if ((fp = fdopen(fd, "w+")) == NULL) {
		ERR("can't open mapfile (%s)\n", strerror(errno));
		goto err2;
	}

	i = 0;
	DISK_CONF_FOREACH(dc, conf)
		if (fprintf(fp, "(hd%d) %s\n", i++, get_disk_conf_path(dc)) < 0)
			goto err;

	i = 0;
	ISO_CONF_FOREACH(ic, conf)
		if (fprintf(fp, "(cd%d) %s\n", i++, get_iso_conf_path(ic)) < 0)
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

static char *
create_load_command(struct vm_conf *conf, size_t *length)
{
#define STRING_VALEN(s)  {(s), sizeof(s) - 1}
	const static struct {
		const char *cmd;
		size_t len;
	} *p, repl[] = {
		STRING_VALEN("kopenbsd "),
		STRING_VALEN("knetbsd "),
	};
#undef STRING_VALEN
	size_t len = 0;
	char *cmd = NULL;
	char *t = (is_install(conf)) ? get_installcmd(conf) : get_loadcmd(conf);
	if (t == NULL)
		goto end;

	if (strcasecmp(t, "auto") == 0) {
		if ((cmd = inspect(conf)) == NULL) {
			ERR("%s inspection failed for VM %s\n",
			    is_install(conf) ? "installcmd" : "loadcmd",
			    get_name(conf));
			goto end;
		}
		len = strlen(cmd);
		goto end;
	}

	if (is_single_user(conf))
		for (p = &repl[0]; p < &repl[nitems(repl)]; p++) {
			if (strncmp(t, p->cmd, p->len) == 0) {
				len = asprintf(&cmd, "%s-s %s\nboot\n", p->cmd,
				    t + p->len);
				goto end;
			}
		}
	len = asprintf(&cmd, "%s\nboot\n", t);

end:
	if (length)
		*length = len;

	return cmd;
}

static struct grub_pty_buf *
create_grub_pty_buf(struct vm *vm)
{
	struct grub_pty_buf *b;

	if ((b = malloc(sizeof(*b))) == NULL)
		return NULL;
	b->command = create_load_command(vm_get_conf(vm), &b->command_len);
	b->nwritten = 0;
	return b;
}

static void
free_grub_pty_buf(struct grub_pty_buf *b)
{
	if (b == NULL)
		return;
	free(b->command);
	free(b);
}

static void
hook_read(int id, const char *buf, ssize_t size, void *data)
{
	struct grub_pty_buf *b = data;
	int n;

	if (b->command == NULL)
		return;

	if ((n = MIN(size, (ssize_t)sizeof(b->buf) - b->nwritten)) > 0) {
		memcpy(&b->buf[b->nwritten], buf, n);
		b->nwritten += n;
		if (memmem(b->buf, b->nwritten, "grub> ", 6) != NULL) {
			if (writen(id, b->command, b->command_len) < 0)
				ERR("failed to write loadcmd (%s)\n",
				    strerror(errno));
			free(b->command);
			b->command = NULL;
			b->command_len = 0;
		}
	}
}

static void
grub_load_cleanup(struct vm *vm, nvlist_t *pl_conf)
{
	const char *fn;
	struct loader_pty *p;
	struct grub_pty_buf *b;

	if (nvlist_exists_number(pl_conf, PTYKEY)) {
		p = (struct loader_pty *)nvlist_take_number(pl_conf, PTYKEY);
		free_loader_pty(p);
	}

	if (nvlist_exists_number(pl_conf, BUFKEY)) {
		b = (struct grub_pty_buf *)nvlist_take_number(pl_conf, BUFKEY);
		free_grub_pty_buf(b);
	}

	if ((fn = get_mapfile(vm)) != NULL) {
		unlink(fn);
		free_mapfile(vm);
	}
}

static int
grub_load(struct vm *vm, nvlist_t *pl_conf)
{
	int ifd[2], ofd[2], efd[2], rc;
	pid_t pid;
	struct vm_conf *conf = vm_get_conf(vm);
	char *mapfile = NULL;
	struct loader_pty *p;
	struct grub_pty_buf *b;

	if (pipe(ifd) < 0) {
		ERR("cannot create pipe (%s)\n", strerror(errno));
		return -1;
	}

	if (pipe(ofd) < 0) {
		ERR("cannot create pipe (%s)\n", strerror(errno));
		goto err0;
	}

	if (pipe(efd) < 0) {
		ERR("cannot create pipe (%s)\n", strerror(errno));
		goto err1;
	}

	if (write_mapfile(conf, &mapfile) < 0)
		goto err2;

	if (mapfile != NULL) {
		if (get_mapfile(vm))
			unlink(get_mapfile(vm));
		rc = set_mapfile(vm, mapfile);
		free(mapfile);
		if (rc < 0)
			goto err2;
	}

	if ((b = create_grub_pty_buf(vm)) == NULL) {
		ERR("%s\n", "failed to create grub_pty_buf");
		goto err2;
	}

	if ((p = create_loader_pty(vm, hook_read, b)) == NULL) {
		ERR("%s\n", "failed to create loader_pty");
		goto err3;
	}

	if ((pid = fork()) < 0) {
		ERR("cannot fork (%s)\n", strerror(errno));
		goto err4;
	}
	if (pid == 0) {
		struct arg_builder *a;

		close(ifd[1]);
		close(ofd[0]);
		close(efd[0]);
		dup2(ifd[0], 0);
		dup2(ofd[1], 1);
		dup2(efd[1], 2);

		if ((a = arg_init()) == NULL) {
			ERR("%s\n", "failed to alloc arg_builder");
			exit(1);
		}

		setenv("TERM", "vt100", 1);
		ARG_PUT(a, strrchr(GRUB_PATH, '/') + 1);
		if (is_wired_memory(conf))
			ARG_PUT(a, "-S");
		ARG_OPT(a, "-c", "%s", get_loader_ptyname(p));
		if (is_install(conf)) {
			ARG_OPT(a, "-r", "%s", "cd0");
		} else if (get_grub_run_partition(conf)) {
			ARG_OPT(a, "-r", "hd0,%s", get_grub_run_partition(conf));
		} else {
			ARG_OPT(a, "-r", "%s", "hd0,1");
		}
		ARG_OPT(a, "-M", "%s", get_memory(conf));
		ARG_OPT(a, "-m", "%s", get_mapfile(vm));
		ARG_PUT(a, get_name(conf));
		arg_print(stdout, a);
		arg_execv(GRUB_PATH, a);
		ERR("cannot exec %s (%s)\n", GRUB_PATH,
		    strerror(errno));
		exit(1);
	arg_error:
		ERR("cannot build %s arguments\n", GRUB_PATH);
		exit(1);
	}

	nvlist_force_add_number(pl_conf, PTYKEY, (intptr_t)p);
	nvlist_force_add_number(pl_conf, BUFKEY, (intptr_t)b);

	set_pid(vm, pid);
	set_state(vm, LOAD);
	close(ifd[0]);
	set_infd(vm, ifd[1]);
	close(ofd[1]);
	set_outfd(vm, ofd[0]);
	close(efd[1]);
	set_errfd(vm, efd[0]);
	/* The target kernel is loaded, Boot ROM isn't necessary. */
	clear_bootrom(vm);
	return 0;
err4:
	free_loader_pty(p);
err3:
	free_grub_pty_buf(b);
err2:
	close(efd[0]);
	close(efd[1]);
err1:
	close(ofd[0]);
	close(ofd[1]);
err0:
	close(ifd[0]);
	close(ifd[1]);
	return -1;
}

PLUGIN_LOADER_METHOD(grub, grub_load, grub_load_cleanup);
PLUGIN_METHOD_MODULE(grub, NULL, &grub);
