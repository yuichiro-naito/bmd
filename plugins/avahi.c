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

struct avahi_data {
	pid_t pid;
};

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
avahi_status_change(struct vm *vm, void **data)
{
	struct kevent ev;
	struct avahi_data *ad;

	if (avahi_enable == 0 || vm->conf->fbuf->enable == false)
		return;

	if (*data == NULL) {
		ad = calloc(1, sizeof(*ad));
		if (ad == NULL)
			return;
		*data = ad;
	} else
		ad = *data;

	switch (vm->state) {
	case LOAD:
	case RUN:
		if (ad->pid == 0 &&
		    (ad->pid = exec_avahi_publish(vm)) > 0) {
			EV_SET(&ev, ad->pid, EVFILT_PROC,
			       EV_ADD | EV_ONESHOT, NOTE_EXIT, 0, NULL);
			while(kevent(gl_conf->kq, &ev, 1, NULL, 0, NULL) < 0)
				if (errno != EINTR)
					break;
		}
		break;
	case TERMINATE:
		if (ad->pid > 0)
			kill(ad->pid, SIGINT);
		free(ad);
		*data = NULL;
		break;
	default:
		break;
	}
}

PLUGIN_DESC plugin_desc = { PLUGIN_VERSION, "avahi", avahi_initialize,
	avahi_finalize, avahi_status_change };
