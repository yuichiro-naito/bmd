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
#ifndef _LOG_H_
#define _LOG_H_
#include <sys/types.h>
#include <syslog.h>

#define LOG_OPEN()	      openlog("bmd", LOG_PID, LOG_DAEMON)
#define LOG_OPEN_PERROR()     openlog("bmd", LOG_PID | LOG_PERROR, LOG_DAEMON)
#define LOG_CLOSE()	      closelog()

#define LOGGER(pri, msg, ...) logger(pri, msg, __VA_ARGS__)
#define ERR(msg, ...)	      logger(LOG_ERR, msg, __VA_ARGS__)
#define WARN(msg, ...)	      logger(LOG_WARNING, msg, __VA_ARGS__)
#define INFO(msg, ...)	      logger(LOG_INFO, msg, __VA_ARGS__)
#define DEBUG(msg, ...)	      logger(LOG_DEBUG, msg, __VA_ARGS__)

int start_log_collector(void);
int end_log_collector(char **, size_t *);
int set_log_fd(int fd);
int clear_log_fd(void);
int logger(int pri, const char *msg, ...);
int on_read_log_fd(int, void *);

#endif
