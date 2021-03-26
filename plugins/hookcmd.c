#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "unistd.h"
#include "stdio.h"
#include "stdlib.h"
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

	if ((pid = fork()) <0 )
		return;

	if (pid == 0) {
		exit(1);
	}

	EV_SET(&ev, pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, NULL);
	kevent(gl_conf->kq, &ev, 1, NULL, 0, NULL);
}

PLUGIN_DESC plugin_desc = {
	PLUGIN_VERSION,
	"hookcmd",
	hookcmd_initialize,
	hookcmd_finalize,
	hookcmd_status_change
};
