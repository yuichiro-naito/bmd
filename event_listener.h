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
#ifndef _EVENT_LISTENER_H_
#define _EVENT_LISTENER_H_
#include <sys/types.h>
#include <sys/event.h>
#include <sys/nv.h>
#include <sys/queue.h>

#include "bmd_plugin.h"

/*
  Command timeout in second.
 */
#define COMMAND_TIMEOUT_SEC 30

struct event_listener;
typedef enum event_category { VMEVENT, PLUGIN, CLIENT } EVENT_CATEGORY;

typedef int (*event_call_back)(struct event_listener *, int, void *);
LIST_HEAD(listener_list, event_listener);

void init_listener_list(struct listener_list *);
void remove_all_listeners(struct listener_list *);
void add_listener(struct listener_list *, struct event_listener *);
void del_listener(struct event_listener *);
struct event_listener *get_first_listener(struct listener_list *);
struct event_listener *get_next_listener(struct event_listener *);
#define LISTENER_FOREACH(l, lst)                           \
	for ((l) = get_first_listener((lst)); (l) != NULL; \
	    (l) = get_next_listener((l)))
#define LISTENER_FOREACH_SAFE(l, lst, t)      \
	for ((l) = get_first_listener((lst)); \
	    (l) != NULL && (((t) = get_next_listener((l))), 1); (l) = (t))

int create_eventq(void);
void destroy_eventq(void);
int event_loop(int *);

/* One shot listeners*/
struct event_listener *create_vm_listener(pid_t, event_call_back, void *);
struct event_listener *create_proc_listener(pid_t, event_call_back, void *);
struct event_listener *create_alarm_listener(int, event_call_back, void *);

/* Regular event listeners */
struct event_listener *create_fd_read_listener(int, event_call_back, void *);
struct event_listener *create_fd_write_listener(int, event_call_back, void *);
struct event_listener *create_signal_listener(int, event_call_back, void *);

void destroy_event_listener(struct event_listener *);
int disable_event_listener(struct event_listener *);
int enable_event_listener(struct event_listener *);

int wait_for_all_vm_terminate(int);

#endif /* _EVENT_LISTENER_H_ */
