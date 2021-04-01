#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "unistd.h"
#include "stdio.h"
#include "stdlib.h"
#include "../vars.h"

#define AVAHI_PUBLISH "/usr/local/bin/avahi-publish"

struct avahi_data {
	pid_t pid;
};

static int avahi_enable = 0;

static int
avahi_initialize(struct global_conf *conf)
{
	if (access(AVAHI_PUBLISH, R_OK|X_OK) == 0)
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
	char *port;
	char *args[9];
	sigset_t mask;

	pid = fork();
	if (pid == 0) {
		sigemptyset(&mask);
		sigaddset(&mask, SIGTERM);
		sigaddset(&mask, SIGINT);
		sigaddset(&mask, SIGHUP);
		sigprocmask(SIG_UNBLOCK, &mask, NULL);

		args[0] = AVAHI_PUBLISH;
		args[1] = "-s";
		args[2] = vm->conf->name;
		args[3] = "_rfb._tcp";
		asprintf(&port, "%d", vm->conf->fbuf->port);
		args[4] = port;
		args[5] = NULL;
		execv(args[0], args);
		exit(1);
	}

	return pid;
}

static void
avahi_status_change(struct vm *vm, void **data)
{
	int status;
	struct avahi_data *ad;

	if (avahi_enable == 0 ||
	    vm->conf->fbuf->enable == false)
		return;

	if (*data == NULL) {
		ad = calloc(1, sizeof(*data));
		if (ad == NULL)
			return;
		*data = ad;
	} else
		ad = *data;

	switch (vm->state) {
	case INIT:
		break;
	case LOAD:
	case RUN:
		if (ad->pid <= 0)
			ad->pid = exec_avahi_publish(vm);
		break;
	case STOP:
	case REMOVE:
	case RESTART:
		break;
	case TERMINATE:
		if (ad->pid > 0) {
			kill(ad->pid, SIGINT);
			waitpid(ad->pid, &status, 0);
		}
		free(ad);
		*data = NULL;
		break;
	}
}

PLUGIN_DESC plugin_desc = {
	PLUGIN_VERSION,
	"avahi",
	avahi_initialize,
	avahi_finalize,
	avahi_status_change
};
