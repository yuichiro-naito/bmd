/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2026 Yuichiro Naito
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

#include <sys/param.h>
#include <sys/queue.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bmd_plugin.h"
#include "event_listener.h"
#include "log.h"
#include "server.h"

#define NEVENTS 10

/*
  Global event queue
 */
static struct event_queue {
	int kq;
	uint nins;
	uint nouts;
	struct kevent in_events[NEVENTS];
	struct kevent out_events[NEVENTS];
} eventq;

/*
  Event Listener
 */
struct event_listener {
	EVENT_CATEGORY category;
	struct kevent kev;
	void *data;
	event_call_back ecb;
	plugin_call_back pcb;
	LIST_ENTRY(event_listener) next;
	LIST_ENTRY(event_listener) all;
};

/*
  All Listeners
*/
static struct listener_list all_listeners = LIST_HEAD_INITIALIZER();

/*
  Last Timer Event ID
 */
static int timer_id = 0;

int
create_eventq(void)
{
#if __FreeBSD_version >= 1400088 || \
    (__FreeBSD_version < 1400000 && __FreeBSD_version >= 1302505)
	if ((eventq.kq = kqueue1(O_CLOEXEC)) < 0) {
#else
	if ((eventq.kq = kqueue()) < 0) {
#endif
		ERR("%s\n", "cannot open kqueue");
		return -1;
	}
	eventq.nins = eventq.nouts = 0;
	return 0;
}

void
destroy_eventq(void)
{
	struct event_listener *el, *eln;

	LIST_FOREACH_SAFE(el, &all_listeners, all, eln)
		free(el);
	LIST_INIT(&all_listeners);

	close(eventq.kq);
	eventq.kq = -1;
	eventq.nins = eventq.nouts = 0;
}

static int
wait_for_eventq(struct timespec *to)
{
	int rc;

	while ((rc = kevent(eventq.kq, eventq.in_events, eventq.nins,
		    eventq.out_events, nitems(eventq.out_events), to)) < 0)
		if (errno != EINTR)
			break;
	eventq.nins = 0;
	if (rc < 0) {
		ERR("kevent failure (%s)\n", strerror(errno));
		return -1;
	}
	eventq.nouts = rc;
	return rc;
}

static int
kevent_try_add(struct kevent *kev, int flags)
{
	int rc;
	uint i = eventq.nins;

	eventq.in_events[i] = *kev;
	eventq.in_events[i].flags = flags;
	eventq.nins = i + 1;

	if (eventq.nins < nitems(eventq.in_events))
		return 0;

	while ((rc = kevent(eventq.kq, eventq.in_events, eventq.nins, NULL, 0,
		    NULL)) < 0)
		if (errno != EINTR)
			break;
	eventq.nins = 0;
	if (rc < 0) {
		ERR("add kevent failure (%s)\n", strerror(errno));
		return -1;
	}
	eventq.nouts = 0;
	return rc;
}

static int
kevent_del(struct kevent *kev)
{
	int rc;
	struct kevent k = *kev;

	k.flags = EV_DELETE;
	while ((rc = kevent(eventq.kq, &k, 1, NULL, 0, NULL)) < 0)
		if (errno != EINTR)
			break;
	if (rc < 0) {
		ERR("del kevent failure (%s)\n", strerror(errno));
		return -1;
	}
	return rc;
}

static int
call_event_cb(int ident, struct event_listener *ev)
{
	int do_remove, rc;

	do_remove = (ev->kev.flags & EV_ONESHOT) ? 1 : 0;
	if (ev->pcb)
		rc = (ev->pcb)(ident, ev->data);
	else if (ev->ecb)
		rc = (ev->ecb)(ev, ident, ev->data);
	else
		rc = 0;
	if (do_remove) {
		LIST_REMOVE(ev, all);
		free(ev);
	}
	return rc;
}

int
event_loop(int *quit)
{
	struct kevent *ev;
	int i, n;
	struct timespec *to, timeout;

	while (*quit == 0) {
		to = calc_timeout(COMMAND_TIMEOUT_SEC, &timeout);
		if ((n = wait_for_eventq(to)) < 0)
			return -1;
		if (n == 0) {
			close_timeout_sock_buf(COMMAND_TIMEOUT_SEC);
			continue;
		}
		for (i = 0; i < n; i++) {
			ev = &eventq.out_events[i];
			if (ev->udata == NULL) {
				ERR("recieved unexpcted event! (%d)\n",
				    ev->filter);
				continue;
			}
			if (call_event_cb(ev->ident, ev->udata) < 0)
				ERR("%s\n", "event callback failed");
		}
	}

	return 0;
}

static struct event_listener *
register_event(EVENT_CATEGORY cate, struct kevent *kev, event_call_back ecb,
    plugin_call_back pcb, void *data)
{
	struct event_listener *el;

	if (ecb != NULL && pcb != NULL) {
		ERR("%s\n", "illegal event");
		return NULL;
	}

	if ((el = malloc(sizeof(*el))) == NULL) {
		ERR("%s\n", "failed to allocate memory");
		return NULL;
	}

	kev->udata = el;
	el->category = cate;
	el->kev = *kev;
	el->ecb = ecb;
	el->pcb = pcb;
	el->data = data;

	if (kevent_try_add(kev, kev->flags) < 0) {
		free(el);
		return NULL;
	}

	LIST_INSERT_HEAD(&all_listeners, el, all);
	return el;
}

void
destroy_event_listener(struct event_listener *el)
{
	if (el == NULL)
		return;
	kevent_del(&el->kev);
	LIST_REMOVE(el, all);
	free(el);
}

struct event_listener *
create_vm_listener(pid_t pid, event_call_back ecb, void *data)
{
	struct kevent kev;

	EV_SET(&kev, pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);

	return register_event(VMEVENT, &kev, ecb, NULL, data);
}

struct event_listener *
create_proc_listener(pid_t pid, event_call_back ecb, void *data)
{
	struct kevent kev;

	EV_SET(&kev, pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);

	return register_event(CLIENT, &kev, ecb, NULL, data);
}

struct event_listener *
create_fd_read_listener(int fd, event_call_back ecb, void *data)
{
	struct kevent kev;

	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);

	return register_event(CLIENT, &kev, ecb, NULL, data);
}
struct event_listener *
create_fd_write_listener(int fd, event_call_back ecb, void *data)
{
	struct kevent kev;

	EV_SET(&kev, fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);

	return register_event(CLIENT, &kev, ecb, NULL, data);
}

struct event_listener *
create_alarm_listener(int second, event_call_back ecb, void *data)
{
	struct kevent kev;

	EV_SET(&kev, ++timer_id, EVFILT_TIMER, EV_ADD | EV_ONESHOT,
	    NOTE_SECONDS, second, NULL);

	return register_event(VMEVENT, &kev, ecb, NULL, data);
}

struct event_listener *
create_signal_listener(int sig, event_call_back ecb, void *data)
{
	struct kevent kev;

	EV_SET(&kev, sig, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	return register_event(CLIENT, &kev, ecb, NULL, data);
}

int
disable_event_listener(struct event_listener *el)
{
	return kevent_try_add(&el->kev, EV_DISABLE);
}

int
enable_event_listener(struct event_listener *el)
{
	return kevent_try_add(&el->kev, EV_ENABLE);
}

static int
count_plugin_process_events(void)
{
	int n = 0;
	struct event_listener *el;

	LIST_FOREACH(el, &all_listeners, all)
		if (el->category == PLUGIN && el->kev.filter == EVFILT_PROC)
			n++;
	return n;
}

int
wait_for_all_vm_terminate(int nvms)
{
	int i, n;
	struct kevent *ev;
	struct event_listener *el;

	while (count_plugin_process_events() + nvms > 0) {
		if ((n = wait_for_eventq(NULL)) < 0)
			return -1;
		for (i = 0; i < n; i++) {
			ev = &eventq.out_events[i];
			if (ev->udata == NULL)
				continue;
			el = ev->udata;
			if (el->category == VMEVENT &&
			    el->kev.filter == EVFILT_PROC)
				nvms--;
			if (call_event_cb(ev->ident, ev->udata) < 0)
				ERR("%s\n", "event callback failed");
		}
	}
#if __FreeBSD_version < 1400059
	// waiting for vm memory is actually freed in the kernel.
	sleep(3);
#endif
	return 0;
}

int
plugin_wait_for_process(pid_t pid, plugin_call_back pcb, void *data)
{
	struct kevent kev;

	EV_SET(&kev, pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);

	return register_event(PLUGIN, &kev, NULL, pcb, data) != NULL ? 0 : -1;
}

static void
stop_waiting_for(bool (*fn)(struct event_listener *, void *), void *data)
{
	struct event_listener *el, *eln;

	LIST_FOREACH_SAFE(el, &all_listeners, all, eln)
		if (fn(el, data))
			destroy_event_listener(el);
}

struct plugin_fd_filter {
	int fd;
	short filter;
	void *data;
};

static bool
plugin_fd(struct event_listener *el, void *data)
{
	struct kevent *k = &el->kev;
	struct plugin_fd_filter *f = data;

	return el->data == f->data && k->filter == f->filter &&
	    el->category == PLUGIN && ((int)k->ident == f->fd);
}

void
plugin_stop_waiting_read_fd(int fd, void *data)
{
	struct plugin_fd_filter filter = {
		.fd = fd,
		.filter = EVFILT_READ,
		.data = data,
	};

	stop_waiting_for(plugin_fd, &filter);
}

int
plugin_wait_for_read_fd(int fd, plugin_call_back pcb, void *data)
{
	struct kevent kev;

	EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);

	return register_event(PLUGIN, &kev, NULL, pcb, data) != NULL ? 0 : -1;
}

void
plugin_stop_waiting_write_fd(int fd, void *data)
{
	struct plugin_fd_filter filter = {
		.fd = fd,
		.filter = EVFILT_WRITE,
		.data = data,
	};

	stop_waiting_for(plugin_fd, &filter);
}

int
plugin_wait_for_write_fd(int fd, plugin_call_back pcb, void *data)
{
	struct kevent kev;

	EV_SET(&kev, fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);

	return register_event(PLUGIN, &kev, NULL, pcb, data) != NULL ? 0 : -1;
}

int
plugin_set_timer(int second, plugin_call_back pcb, void *data)
{
	struct kevent kev;

	EV_SET(&kev, ++timer_id, EVFILT_TIMER, EV_ADD | EV_ONESHOT,
	    NOTE_SECONDS, second, NULL);

	return register_event(PLUGIN, &kev, NULL, pcb, data) != NULL ? 0 : -1;
}

void
init_listener_list(struct listener_list *ll)
{
	LIST_INIT(ll);
}

void
remove_all_listeners(struct listener_list *ll)
{
	struct event_listener *e, *en;
	LIST_FOREACH_SAFE(e, ll, next, en)
		destroy_event_listener(e);
	LIST_INIT(ll);
}

void
add_listener(struct listener_list *l, struct event_listener *e)
{
	LIST_INSERT_HEAD(l, e, next);
}

void
del_listener(struct event_listener *e)
{
	LIST_REMOVE(e, next);
}

struct event_listener *
get_first_listener(struct listener_list *l)
{
	return LIST_FIRST(l);
}

struct event_listener *
get_next_listener(struct event_listener *el)
{
	return LIST_NEXT(el, next);
}
