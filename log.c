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

#include <sys/uio.h>
#include <sys/param.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include "log.h"

static int collector_fd = -1;
static FILE *collector = NULL;
static char *collector_buf;
static size_t collector_size;

int
start_log_collector(void)
{
	if (collector)
		return 0;

	collector = open_memstream(&collector_buf, &collector_size);
	if (collector == NULL)
		return -1;

	return 0;
}

int
end_log_collector(char **bufp, size_t *sizep)
{
	if (collector == NULL)
		return 0;
	fputc('\0', collector);
	fclose(collector);
	collector = NULL;
	if (bufp && sizep) {
		*bufp = collector_buf;
		*sizep = collector_size;
	}
	return 0;
}

int
on_read_log_fd(int fd, void *data __unused)
{
	int n, rc, size;
	char buf[256];

	while ((rc = read(fd, &size, sizeof(size))) < 0)
		if (errno != EAGAIN && errno != EINTR)
			break;
	if (rc < 0)
		return -1;
	if (rc == 0)
		return 0;
	for (n = 0; n < size; n += rc) {
		while ((rc = read(fd, buf, sizeof(buf))) < 0)
			if (errno != EAGAIN && errno != EINTR)
				break;
		if (rc < 0)
			return rc;
		if (rc == 0)
			return 0;
		if (collector != NULL && fwrite(buf, 1, rc, collector) < 0)
			return -1;
	}

	return n;
}

int
set_log_fd(int fd)
{
	if (collector_fd != -1)
		return 0;
	collector_fd = fd;
	return 0;
}

int
clear_log_fd(void)
{
	if (collector_fd == -1)
		return 0;
	close(collector_fd);
	collector_fd = -1;
	return 0;
}

int
logger(int pri, const char *msg, ...)
{
	char *buf;
	int len;
	struct iovec iov[2];
	va_list ap;

	if (pri == LOG_ERR) {
		va_start(ap, msg);
		if (collector_fd != -1) {
			if ((len = vasprintf(&buf, msg, ap)) < 0)
				goto end_collection;
			iov[0].iov_base = &len;
			iov[0].iov_len = sizeof(len);
			iov[1].iov_base = buf;
			iov[1].iov_len = len;
			while (writev(collector_fd, iov, nitems(iov)) < 0)
				if (errno != EAGAIN && errno != EINTR)
					break;
			free(buf);
		} else if (collector != NULL)
			vfprintf(collector, msg, ap);
end_collection:
		va_end(ap);
	}

	va_start(ap, msg);
	vsyslog(pri, msg, ap);
	va_end(ap);
	return 0;
}
