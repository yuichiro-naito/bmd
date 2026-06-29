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

#include <errno.h>
#include <fcntl.h>
#include <libutil.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <termios.h>
#include <unistd.h>

#include "bmd_plugin.h"
#include "event_listener.h"
#include "log.h"
#include "server.h"
#include "vm.h"

struct loader_pty {
	int fdin;
	int fdout;
	int master;
	int slave;
	char ptyname[24];
	struct termios defterm;
	struct termios term;
	struct event_listener *fd_listener, *pty_listener;
	loader_pty_read_hook master_read_hook;
	void *master_read_hook_data;
};

#define PTYKEY "loaderpty"
#define DEFAULT_COLUMNS 80
#define DEFAULT_ROWS 24
#define PIXELS_PER_COLUMN 8
#define PIXELS_PER_ROW 16

void
nvlist_force_add_number(nvlist_t *nv, const char *key, long v)
{
	if (nvlist_exists_number(nv, key))
		nvlist_free_number(nv, key);
	nvlist_add_number(nv, key, v);
}

char *
get_loader_ptyname(struct loader_pty *p)
{
	return p->ptyname;
}

static int
on_read_master(struct event_listener *el __unused, int id, void *data)
{
	struct loader_pty *p = data;
	ssize_t size;
	int peer, rc;
	char buf[256];

	peer = p->fdin;

	while ((size = read(id, buf, sizeof(buf))) < 0)
		if (errno != EINTR && errno != EAGAIN)
			break;
	if (size < 0)
		return 0;
	if (size == 0) {
		destroy_event_listener(p->pty_listener);
		p->pty_listener = NULL;
		if (id > 2)
			close(id);
		p->master = -1;
	}
	if (p->master_read_hook != NULL)
		p->master_read_hook(id, buf, size, p->master_read_hook_data);
	if (peer != -1) {
		if ((rc = writen(peer, buf, size)) < 0)
			ERR("failed to write (%s)\n", strerror(errno));
		if (rc <= 0) {
			destroy_event_listener(p->fd_listener);
			p->fd_listener = NULL;
			if (peer > 2)
				close(peer);
			p->fdin = -1;
		}
	}

	return 0;
}

static int
on_read_nmdm(struct event_listener *el __unused, int id, void *data)
{
	struct loader_pty *p = data;
	ssize_t size;
	int peer, rc;
	char buf[256];

	peer = p->master;

	while ((size = read(id, buf, sizeof(buf))) < 0)
		if (errno != EINTR && errno != EAGAIN)
			break;
	if (size < 0)
		return 0;
	if (size == 0) {
		destroy_event_listener(p->fd_listener);
		p->fd_listener = NULL;
		if (id > 2)
			close(id);
		p->fdout = -1;
		return 0;
	}
	if (peer != -1) {
		if ((rc = writen(peer, buf, size)) < 0)
			ERR("failed to write (%s)\n", strerror(errno));
		if (rc <= 0) {
			destroy_event_listener(p->pty_listener);
			p->pty_listener = NULL;
			if (peer > 2)
				close(peer);
			p->master = -1;
		}
	}

	return 0;
}

struct loader_pty *
create_loader_pty(struct vm *vm, loader_pty_read_hook hook, void *data)
{
	int fd;
	struct loader_pty *p;
	char *com = get_assigned_com(vm, 0);
	struct termios *term = NULL;
	struct winsize winsz;
	struct event_listener *el0, *el1;

	if ((p = malloc(sizeof(*p))) == NULL)
		return NULL;

	p->master_read_hook = hook;
	p->master_read_hook_data = data;
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

	el0 = create_fd_read_listener(p->master, on_read_master, p);
	el1 = create_fd_read_listener(p->fdout, on_read_nmdm, p);
	if (el0 == NULL || el1 == NULL) {
		destroy_event_listener(el0);
		destroy_event_listener(el1);
		ERR("%s\n", "failed to wait for fds");
		goto err3;
	}
	p->pty_listener = el0;
	p->fd_listener = el1;

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
	free(p);
	return NULL;
}

void
free_loader_pty(struct loader_pty *p)
{
	if (p == NULL)
		return;

	if (p->fdin == 1 && p->fdout == 0)
		rollbackttysetup(&p->defterm);
	if (p->fdout != -1)
		destroy_event_listener(p->fd_listener);
	if (p->fdin != p->fdout && p->fdin > 2)
		close(p->fdin);
	if (p->fdout > 2)
		close(p->fdout);
	if (p->master != -1) {
		destroy_event_listener(p->pty_listener);
		close(p->master);
	}
	if (p->slave != -1)
		close(p->slave);
	revoke(p->ptyname);
	free(p);
}
