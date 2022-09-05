#include <sys/event.h>
#include <sys/signal.h>
#include <sys/unistd.h>

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "../vars.h"

#define AVAHI_PUBLISH "/usr/local/bin/avahi-publish"

static struct global_conf *gl_conf;
static int avahi_enable = 0;

static int
avahi_initialize(struct global_conf *conf)
{
	gl_conf = conf;

	if (access(AVAHI_PUBLISH, R_OK | X_OK) == 0)
		avahi_enable = 1;

	return 0;
}

static void
avahi_finalize(struct global_conf *conf)
{
}

static int
exec_avahi_publish(struct vm *vm)
{
	pid_t pid;
	char buf[12];
	char *args[6];
	sigset_t mask;

	args[0] = AVAHI_PUBLISH;
	args[1] = "-s";
	args[2] = vm->conf->name;
	args[3] = "_rfb._tcp";
	snprintf(buf, sizeof(buf), "%d", vm->conf->fbuf->port);
	args[4] = buf;
	args[5] = NULL;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);

	pid = fork();
	if (pid == 0) {
		sigprocmask(SIG_UNBLOCK, &mask, NULL);
		execv(args[0], args);
		exit(1);
	}

	return pid;
}

static void
avahi_status_change(struct vm *vm, nvlist_t *config)
{
	struct kevent ev;
	pid_t pid;

	if (avahi_enable == 0 || vm->conf->fbuf->enable == false)
		return;

	pid = nvlist_exists_number(config, "pid") ?
		nvlist_take_number(config, "pid") : 0;

	switch (vm->state) {
	case LOAD:
	case RUN:
		if (pid == 0 && (pid = exec_avahi_publish(vm)) > 0) {
			EV_SET(&ev, pid, EVFILT_PROC,
			       EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);
			while(kevent(gl_conf->kq, &ev, 1, NULL, 0, NULL) < 0)
				if (errno != EINTR)
					break;
		}
		/* FALLTHROUGH */
	default:
		if (pid > 0)
			nvlist_add_number(config, "pid", pid);
		break;
	case TERMINATE:
		if (pid > 0)
			kill(pid, SIGINT);
		break;
	}
}

PLUGIN_DESC plugin_desc = { PLUGIN_VERSION, "avahi", avahi_initialize,
	avahi_finalize, avahi_status_change, NULL };
