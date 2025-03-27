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

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/wait.h>

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bmd.h"
#include "bmd_plugin.h"
#include "log.h"

struct wol_monitor {
	LIST_ENTRY(wol_monitor) next;
	pid_t pid;
	int infd;
	int outfd;
	bool timer_is_set;
	size_t data_len;
	size_t sent_len;
	char *send_data;
};

#define MAX_WOL_MONITORS 10
static int nwolmon = 0;
static unsigned int wolmonid = 0;
static LIST_HEAD(, wol_monitor) monitor_list = LIST_HEAD_INITIALIZER();

static int
on_write_fd(int fd, void *data)
{
	ssize_t n;
	struct wol_monitor *wm = data;

	n = write(fd, wm->send_data + wm->sent_len,
	    wm->data_len - wm->sent_len);
	if (n < 0) {
		ERR("%s\n", "failed to send WoL list");
		kill(wm->pid, SIGTERM);
		return -1;
	}
	if (n == 0)
		return 0;
	wm->sent_len += n;
	if (wm->sent_len >= wm->data_len) {
		plugin_stop_waiting_write_fd(wm->infd, wm);
		free(wm->send_data);
		wm->send_data = NULL;
	}

	return 0;
}

static int
on_read_fd(int fd, void *data __unused)
{
	ssize_t n;
	char **names, **name, buf[1024 + 1];
	struct vm_entry *vm_ent;

	n = read(fd, buf, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = '\0';
		if ((names = split_args(buf)) == NULL)
			return 0;
		for (name = names; *name != NULL; name++)
			if ((vm_ent = lookup_vm_by_name(*name)) &&
			    VM_STATE(vm_ent) == TERMINATE)
				start_virtual_machine(vm_ent);
		free(names);
	}

	return 0;
}

static int
on_monitor_exit(int ident __unused, void *data)
{
	struct wol_monitor *mon = data;

	waitpid(mon->pid, NULL, 0);

	plugin_stop_waiting_read_fd(mon->outfd, mon);
	plugin_stop_waiting_write_fd(mon->infd, mon);
	close(mon->infd);
	close(mon->outfd);

	LIST_REMOVE(mon, next);
	free(mon->send_data);
	free(mon);
	nwolmon--;
	return 0;
}

static int
on_timer(int ident __unused, void *data)
{
	struct wol_monitor *mon = data;

	kill(mon->pid, SIGTERM);
	return 0;
}

static struct wol_monitor *
exec_wol_monitor(void)
{
	pid_t pid;
	int infd[2];
	int outfd[2];
	char num[12];
	struct wol_monitor *mon;

	if ((mon = malloc(sizeof(*mon))) == NULL)
		return NULL;

	if (pipe(infd) < 0)
		goto err;

	if (pipe(outfd) < 0)
		goto err1;

	pid = fork();
	if (pid < 0)
		goto err2;

	if (pid == 0) {
		close(infd[1]);
		close(outfd[0]);
		dup2(infd[0], 0);
		dup2(outfd[1], 1);
		if (snprintf(num, sizeof(num), "%u", wolmonid) >= 0)
			setenv("WOL_MON_ID", num, 1);
		setenv("WOL_PARAM_SOCKET", "0", 1);
		execl(LOCALBASE "/sbin/bmdwolmon", "bmdwolmon", NULL);
		exit(1);
	}
	close(infd[0]);
	close(outfd[1]);
	mon->pid = pid;
	mon->infd = infd[1];
	mon->outfd = outfd[0];
	mon->timer_is_set = false;
	wolmonid++;

	return mon;

err2:
	close(outfd[0]);
	close(outfd[1]);
err1:
	close(infd[0]);
	close(infd[1]);
err:
	free(mon);
	return NULL;
}

static inline struct vm_conf *
get_vm_conf(struct vm_entry *v)
{
	return VM_NEWCONF(v) != NULL ? &VM_NEWCONF(v)->conf : VM_CONF(v);
}

static inline bool
is_wol_enable(struct net_conf *n)
{
	return (n->wol && n->mac && strlen(n->mac) > 0);
}

static bool
check_wol(void)
{
	struct vm_entry *v;
	struct net_conf *n;

	SLIST_FOREACH(v, &vm_list, next)
		NET_CONF_FOREACH(n, get_vm_conf(v))
			if (is_wol_enable(n))
				return true;

	return false;
}

static int
make_wol_list(struct wol_monitor *wm)
{
	struct vm_entry *v;
	struct net_conf *n;
	char *buf;
	size_t len;
	FILE *fp;

	if ((fp = open_memstream(&buf, &len)) == NULL)
		return -1;

	SLIST_FOREACH(v, &vm_list, next)
		NET_CONF_FOREACH(n, get_vm_conf(v))
			if (is_wol_enable(n))
				if (fprintf(fp, "%s\t%s\t%s\n",
					VM_CONF(v)->name,
					n->vale ? n->vale : n->bridge,
					n->mac) < 0)
					break;
	if (fprintf(fp, ".end.\n") < 0)
		goto err;
	fclose(fp);
	wm->send_data = buf;
	wm->data_len = len;
	wm->sent_len = 0;
	return 0;
err:
	fclose(fp);
	free(buf);
	return -1;
}

static int
kill_monitors(void)
{
	struct wol_monitor *mon;

	LIST_FOREACH(mon, &monitor_list, next)
		if (!mon->timer_is_set)
			if (plugin_set_timer(1, on_timer, mon) == 0)
				mon->timer_is_set = true;
	return 0;
}

int
start_wol_monitor(void)
{
	struct wol_monitor *mon;

	if (!check_wol()) {
		kill_monitors();
		return 0;
	}

	if (nwolmon >= MAX_WOL_MONITORS)
		return 0;

	if ((mon = exec_wol_monitor()) == NULL)
		return -1;

	if (make_wol_list(mon) < 0 ||
	    plugin_wait_for_read_fd(mon->outfd, on_read_fd, mon) < 0 ||
	    plugin_wait_for_write_fd(mon->infd, on_write_fd, mon) < 0 ||
	    plugin_wait_for_process(mon->pid, on_monitor_exit, mon) < 0 ||
	    kill_monitors() < 0) {
		ERR("%s\n", "failed to start WoL monitor!");
		kill(mon->pid, SIGTERM);
		on_monitor_exit(mon->pid, mon);
		return -1;
	}

	LIST_INSERT_HEAD(&monitor_list, mon, next);
	nwolmon++;
	return 0;
}

int
stop_wol_monitor(void)
{
	struct wol_monitor *mon;

	LIST_FOREACH(mon, &monitor_list, next)
		kill(mon->pid, SIGTERM);

	return 0;
}
