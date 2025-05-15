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
#include <sys/queue.h>
#include <sys/signal.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <libutil.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "bmd_plugin.h"
#include "conf.h"
#include "inspect.h"
#include "log.h"
#include "server.h"
#include "vm.h"

struct grub_pty {
	int fdin;
	int fdout;
	int master;
	int slave;
	size_t command_len;
	char *command;
	char ptyname[24];
	struct termios defterm;
	struct termios term;
	int nwritten;
	char buf[1024];
};

#define PTYKEY "grubpty"
#define DEFAULT_COLUMNS 80
#define DEFAULT_ROWS 24
#define PIXELS_PER_COLUMN 8
#define PIXELS_PER_ROW 16

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
		if (fprintf(fp, "(hd%d) %s\n", i++, dc->path) < 0)
			goto err;

	i = 0;
	ISO_CONF_FOREACH(ic, conf)
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

static char *
create_load_command(struct vm_conf *conf, size_t *length)
{
	const char **p, *repl[] = { "kopenbsd ", "knetbsd " };
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
		ARRAY_FOREACH(p, repl) {
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

static ssize_t
writen(int fd, char *buf, size_t size)
{
	size_t n;
	ssize_t rc;

	n = 0;
	while (n < size) {
		while ((rc = write(fd, buf + n, size - n)) < 0)
			if (errno != EINTR && errno != EAGAIN)
				break;
		if (rc <= 0)
			return rc;
		n += rc;
	}
	return n;
}

static int
on_read_master(int id, void *data)
{
	struct grub_pty *p = data;
	ssize_t size;
	int n, peer, rc;
	char buf[128];

	peer = p->fdin;

	while ((size = read(id, buf, sizeof(buf))) < 0)
		if (errno != EINTR && errno != EAGAIN)
			break;
	if (size < 0)
		return 0;
	if (size == 0) {
		plugin_stop_waiting_read_fd(id, p);
		if (id > 2)
			close(id);
		p->master = -1;
	}
	if (p->command != NULL &&
	    (n = MIN(size, (ssize_t)sizeof(p->buf) - p->nwritten)) > 0) {
		memcpy(&p->buf[p->nwritten], buf, n);
		p->nwritten += n;
		if (memmem(p->buf, p->nwritten, "grub> ", 6) != NULL) {
			if (writen(id, p->command, p->command_len) < 0)
				ERR("failed to write loadcmd (%s)\n",
				    strerror(errno));
			free(p->command);
			p->command = NULL;
			p->command_len = 0;
		}
	}
	if (peer != -1) {
		if ((rc = writen(peer, buf, size)) < 0)
			ERR("failed to write (%s)\n", strerror(errno));
		if (rc <= 0) {
			plugin_stop_waiting_read_fd(peer, p);
			if (peer > 2)
				close(peer);
			p->fdin = -1;
		}
	}

	return 0;
}

static int
on_read_nmdm(int id, void *data)
{
	struct grub_pty *p = data;
	ssize_t size;
	int peer, rc;
	char buf[128];

	peer = p->master;

	while ((size = read(id, buf, sizeof(buf))) < 0)
		if (errno != EINTR && errno != EAGAIN)
			break;
	if (size < 0)
		return 0;
	if (size == 0) {
		plugin_stop_waiting_read_fd(id, p);
		if (id > 2)
			close(id);
		p->fdout = -1;
		return 0;
	}
	if (peer != -1) {
		if ((rc = writen(peer, buf, size)) < 0)
			ERR("failed to write (%s)\n", strerror(errno));
		if (rc <= 0) {
			plugin_stop_waiting_read_fd(peer, p);
			if (peer > 2)
				close(peer);
			p->master = -1;
		}
	}

	return 0;
}

static struct grub_pty *
create_grub_pty(struct vm *vm)
{
	int fd;
	struct grub_pty *p;
	char *com = get_assigned_com(vm, 0);
	struct termios *term = NULL;
	struct winsize winsz;

	if ((p = malloc(sizeof(*p))) == NULL)
		return NULL;

	p->command = create_load_command(vm_get_conf(vm), &p->command_len);

	p->nwritten = 0;

	winsz.ws_col = DEFAULT_COLUMNS;
	winsz.ws_xpixel = DEFAULT_COLUMNS * PIXELS_PER_COLUMN;
	winsz.ws_row = DEFAULT_ROWS;
	winsz.ws_ypixel = DEFAULT_ROWS * PIXELS_PER_ROW;
	if (com != NULL) {
		if (strcasecmp(com, "stdio") == 0) {
			p->fdin = 1;
			p->fdout = 0;
			localttysetup(&p->defterm, &p->term);
			term = &p->term;
			tcgetwinsize(0, &winsz);
		} else {
			if ((fd = open(com, O_RDWR | O_NONBLOCK)) < 0) {
				ERR("failed to open %s\n", com);
				goto err;
			}
			ttysetup(fd, 115200);
			p->fdin = p->fdout = fd;
		}
	} else
		p->fdin = p->fdout = -1;

	if (openpty(&p->master, &p->slave, p->ptyname, term, &winsz) < 0) {
		ERR("%s\n", "failed to open pty");
		goto err2;
	}

	if (plugin_wait_for_read_fd(p->master, on_read_master, p) < 0 ||
	    (p->fdout != -1 &&
		plugin_wait_for_read_fd(p->fdout, on_read_nmdm, p) < 0)) {
		ERR("%s\n", "failed to wait for fds");
		goto err3;
	}

	return p;
err3:
	close(p->master);
	close(p->slave);
	revoke(p->ptyname);
err2:
	if (p->fdin != p->fdout && p->fdin > 2)
		close(p->fdin);
	if (p->fdout > 2)
		close(p->fdout);
err:
	free(p->command);
	free(p);
	return NULL;
}

static void
free_grub_pty(struct grub_pty *p)
{
	if (p == NULL)
		return;

	if (p->fdin == 1 && p->fdout == 0)
		rollbackttysetup(&p->defterm);

	if (p->fdin != p->fdout && p->fdin > 2)
		close(p->fdin);
	if (p->fdout != -1)
		plugin_stop_waiting_read_fd(p->fdout, p);
	if (p->fdout > 2)
		close(p->fdout);
	if (p->master != -1) {
		plugin_stop_waiting_read_fd(p->master, p);
		close(p->master);
	}
	if (p->slave != -1)
		close(p->slave);
	revoke(p->ptyname);
	free(p->command);
	free(p);
}

static void
grub_load_cleanup(struct vm *vm, nvlist_t *pl_conf)
{
	const char *fn;
	struct grub_pty *p;

	if (nvlist_exists_number(pl_conf, PTYKEY)) {
		p = (struct grub_pty *)nvlist_get_number(pl_conf, PTYKEY);
		free_grub_pty(p);
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
	size_t len;
	char *mapfile = NULL;
	struct grub_pty *p;

	if (pipe(ifd) < 0) {
		ERR("cannot create pipe (%s)\n", strerror(errno));
		return -1;
	}

	if (pipe(ofd) < 0) {
		ERR("cannot create pipe (%s)\n", strerror(errno));
		close(ifd[0]);
		close(ifd[1]);
		return -1;
	}

	if (pipe(efd) < 0) {
		ERR("cannot create pipe (%s)\n", strerror(errno));
		close(ifd[0]);
		close(ifd[1]);
		close(ofd[0]);
		close(ofd[1]);
		return -1;
	}

	if (write_mapfile(conf, &mapfile) < 0)
		goto err;

	if (mapfile != NULL) {
		if (get_mapfile(vm))
			unlink(get_mapfile(vm));
		rc = set_mapfile(vm, mapfile);
		free(mapfile);
		if (rc < 0)
			goto err;
	}

	if ((p = create_grub_pty(vm)) == NULL) {
		ERR("%s\n", "failed to create grub_pty");
		goto err;
	}

	if (nvlist_exists_number(pl_conf, PTYKEY))
		nvlist_free_number(pl_conf, PTYKEY);
	nvlist_add_number(pl_conf, PTYKEY, (intptr_t)p);

	pid = fork();
	if (pid > 0) {
		set_pid(vm, pid);
		set_state(vm, LOAD);
		close(ifd[0]);
		set_infd(vm, ifd[1]);
		close(ofd[1]);
		set_outfd(vm, ofd[0]);
		close(efd[1]);
		set_errfd(vm, efd[0]);
	} else if (pid == 0) {
		FILE *fp;
		char **argv, *bp, **t;

		close(ifd[1]);
		close(ofd[0]);
		close(efd[0]);
		dup2(ifd[0], 0);
		dup2(ofd[1], 1);
		dup2(efd[1], 2);
		fp = open_memstream(&bp, &len);
		if (fp == NULL) {
			ERR("cannot open memstream (%s)\n", strerror(errno));
			exit(1);
		}
		flockfile(fp);

		setenv("TERM", "vt100", 1);
		fprintf(fp, LOCALBASE "/sbin/grub-bhyve\n");
		if (is_wired_memory(conf))
			fprintf(fp, "-S\n");
		fprintf(fp, "-c\n%s\n", p->ptyname);
		fprintf(fp, "-r\n");
		if (is_install(conf))
			fprintf(fp, "cd0\n");
		else if (get_grub_run_partition(conf))
			fprintf(fp, "hd0,%s\n", get_grub_run_partition(conf));
		else
			fprintf(fp, "hd0,1\n");
		fprintf(fp, "-M\n%s\n", get_memory(conf));
		fprintf(fp, "-m\n%s\n", get_mapfile(vm));
		fprintf(fp, "%s\n", get_name(conf));
		funlockfile(fp);
		fclose(fp);

		argv = split_args(bp);
		if (argv == NULL) {
			ERR("malloc: %s\n", strerror(errno));
			exit(1);
		}
		for (t = argv; *t != NULL; t++)
			printf("%s ", *t);
		printf("\n");
		fflush(stdout);
		execv(argv[0], argv);
		ERR("cannot exec %s\n", argv[0]);
		exit(1);
	} else {
		ERR("cannot fork (%s)\n", strerror(errno));
		goto err;
	}

	return 0;
err:

	close(ifd[0]);
	close(ifd[1]);
	close(ofd[0]);
	close(ofd[1]);
	close(efd[0]);
	close(efd[1]);
	return -1;
}

struct loader_method grub2load_method = { "grub", grub_load,
	grub_load_cleanup };
