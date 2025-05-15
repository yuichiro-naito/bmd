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
#ifndef _SERVER_H
#define _SERVER_H

#include <termios.h>

/*
 * Nmdm number offset for auto assignment.
 */
#define DEFAULT_NMDM_OFFSET 200

struct sock_buf;
struct global_conf;

struct sock_buf *create_sock_buf(int);
void destroy_sock_buf(struct sock_buf *);
void clear_sock_buf(struct sock_buf *);
int recv_sock_buf(struct sock_buf *);
void clear_send_sock_buf(struct sock_buf *);
int send_sock_buf(struct sock_buf *);

typedef unsigned int com_opener_id;
struct com_opener *lookup_com_opener(com_opener_id);
char *get_peer_comport(const char *);

int ttysetup(int, int);
int localttysetup(struct termios *, struct termios *);
int rollbackttysetup(struct termios *);

int connect_to_server(const struct global_conf *);
int create_command_server(const struct global_conf *);
int accept_command_socket(int s0);
int recv_command(struct sock_buf *);
struct timespec *calc_timeout(int, struct timespec *);
void close_timeout_sock_buf(int);

int attach_console(int);

#endif
