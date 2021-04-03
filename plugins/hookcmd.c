#include <sys/event.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include "../vars.h"

static struct global_conf *gl_conf;

static int
hookcmd_initialize(struct global_conf *conf)
{
	gl_conf = conf;
	return 0;
}

static void
hookcmd_finalize(struct global_conf *conf)
{
}

static void
hookcmd_status_change(struct vm *vm, void **data)
{
	pid_t pid;
	struct kevent ev;
	char *args[4];
	static char *state_name[] = {
		"INIT",	"LOAD", "RUN", "TERMINATE", "STOP", "REMOVE", "RESTART"
	};

	if (vm->conf->hookcmd == NULL)
		return;

	if ((pid = fork()) < 0)
		return;

	if (pid == 0) {
		args[0] = vm->conf->hookcmd;
		args[1] = vm->conf->name;
		args[2] = state_name[vm->state];
		args[3] = NULL;
		execv(args[0], args);
		exit(1);
	}

	EV_SET(&ev, pid, EVFILT_PROC, EV_ADD|EV_ONESHOT, NOTE_EXIT, 0, NULL);
	kevent(gl_conf->kq, &ev, 1, NULL, 0, NULL);
}

PLUGIN_DESC plugin_desc = {
	PLUGIN_VERSION,
	"hookcmd",
	hookcmd_initialize,
	hookcmd_finalize,
	hookcmd_status_change
};
