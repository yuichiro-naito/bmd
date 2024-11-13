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
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "server.h"

static int stop = 0;
static struct termios defterm, term;

static void
sighandler_stop(int sig __unused)
{
	stop++;
}

static pid_t child_pid;

static void
sighandler_kill(int sig __unused)
{
	kill(child_pid, SIGTERM);
	waitpid(child_pid, NULL, 0);
	exit(0);
}

static void
sighandler_exit(int sig __unused)
{
	exit(0);
}

static ssize_t
put_char(int fd, char c)
{
	ssize_t n;
	while ((n = write(fd, &c, 1)) < 0)
		if (stop || errno != EINTR)
			break;
	return n;
}

static void
suspend(int local_only)
{
	tcsetattr(0, TCSADRAIN, &defterm);
	kill(local_only ? getpid() : 0, SIGTSTP);
	tcsetattr(0, TCSADRAIN, &term);
}

static int
console_in(int fd)
{
	int c;

	while ((c = getchar()) != EOF) {
		if (stop)
			break;
		if (c == '~') {
			switch (c = getchar()) {
			case '.':
			case 4: /* ^D */
				return 0;
			case 0x19: /* ^Y */
				suspend(1);
				continue;
			case 0x1a: /* ^Z */
				suspend(0);
				continue;
			case '~':
				break;
			default:
				if (put_char(fd, '~') <= 0)
					return 0;
			}
		}
		if (put_char(fd, c) <= 0)
			break;
	}

	return 0;
}

static int
console_out(int fd)
{
	ssize_t sz, n, written;
	char buf[1024];

	signal(SIGINT, sighandler_exit);
	signal(SIGTERM, sighandler_exit);

	for (;;) {
		while ((sz = read(fd, buf, sizeof(buf))) < 0)
			if (errno != EINTR)
				break;
		if (sz <= 0)
			break;

		written = 0;
	retry:
		while ((n = write(1, buf + written, sz - written)) < 0)
			if (errno != EINTR)
				break;
		if (n <= 0)
			break;
		written += n;
		if (written < sz)
			goto retry;
	}

	exit(0);
}

/*
 * Set up the "remote" tty's state
 */
static int
ttysetup(int fd, int speed)
{
	struct termios cntrl;

	if (tcgetattr(fd, &cntrl))
		return (-1);
	cfsetspeed(&cntrl, speed);
	cntrl.c_cflag &= ~(CSIZE | PARENB);
	cntrl.c_cflag |= CS8;
	cntrl.c_cflag |= CLOCAL;
	cntrl.c_iflag &= ~(ISTRIP | ICRNL);
	cntrl.c_oflag &= ~OPOST;
	cntrl.c_lflag &= ~(ICANON | ISIG | IEXTEN | ECHO);
	cntrl.c_cc[VMIN] = 1;
	cntrl.c_cc[VTIME] = 0;
	return (tcsetattr(fd, TCSAFLUSH, &cntrl));
}

int
attach_console(int fd)
{
	int status;
	pid_t out_pid;

	if (ttysetup(fd, 115200) < 0)
		return -1;

	tcgetattr(0, &defterm);
	term = defterm;
	term.c_lflag &= ~(ICANON | IEXTEN | ECHO);
	term.c_iflag &= ~(INPCK | ICRNL);
	term.c_oflag &= ~OPOST;
	term.c_cc[VMIN] = 1;
	term.c_cc[VTIME] = 0;
	term.c_cc[VINTR] = term.c_cc[VQUIT] = term.c_cc[VSUSP] =
	    term.c_cc[VDSUSP] = term.c_cc[VDISCARD] = term.c_cc[VLNEXT] =
		_POSIX_VDISABLE;
	tcsetattr(0, TCSADRAIN, &term);

	signal(SIGINT, sighandler_stop);
	signal(SIGTERM, sighandler_stop);

	if ((out_pid = fork()) < 0)
		return -1;

	child_pid = out_pid;
	signal(SIGHUP, sighandler_kill);

	if (out_pid)
		console_in(fd);
	else
		console_out(fd);

	kill(out_pid, SIGTERM);
	waitpid(out_pid, &status, 0);

	return 0;
}
