#include <sys/wait.h>
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

static int on_process_exit(int id, void *data);

static int
exec_avahi_publish(nvlist_t *config)
{
	pid_t pid;
	char  *args[6];
	sigset_t mask;

	args[0] = AVAHI_PUBLISH;
	args[1] = "-s";
	args[2] = (char *)nvlist_get_string(config, "name");
	args[3] = "_rfb._tcp";
	args[4] = (char *)nvlist_get_string(config, "port");
	args[5] = NULL;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);

	pid = fork();
	if (pid == 0) {
		sigprocmask(SIG_UNBLOCK, &mask, NULL);
		execv(args[0], args);
		exit(1);
	}

	if (pid > 0)
		plugin_wait_for_process(pid, on_process_exit, config);
	return pid;
}

static int
on_timer(int id, void *data)
{
	nvlist_t *config = data;
	pid_t pid = exec_avahi_publish(config);
	if (pid > 0) {
		if (nvlist_exists_number(config, "pid"))
			nvlist_free_number(config, "pid");
		nvlist_add_number(config, "pid", pid);
	}
	return 0;
}


static int
on_process_exit(int id, void *data)
{
	int status;
	if (waitpid(id, &status, WNOHANG) < 0)
		return -1;

	/* If avahi-publish exit on error, retry */
	if (WIFEXITED(status) && WEXITSTATUS(status) == 1)
		plugin_set_timer(5, on_timer, data);

	return 0;
}

void
set_params(nvlist_t *config, struct vm *vm)
{
	char num[16];

	if (nvlist_exists_string(config, "name"))
		nvlist_free_string(config, "name");
	if (nvlist_exists_string(config, "port"))
		nvlist_free_string(config, "port");

	nvlist_add_string(config, "name", vm->conf->name);
	snprintf(num, sizeof(num), "%d", vm->conf->fbuf->port);
	nvlist_add_string(config, "port", num);
}


static void
avahi_status_change(struct vm *vm, nvlist_t *config)
{
	pid_t pid;

	if (avahi_enable == 0 || vm->conf->fbuf->enable == false)
		return;

	pid = nvlist_exists_number(config, "pid") ?
		nvlist_take_number(config, "pid") : 0;

	switch (vm->state) {
	case LOAD:
	case RUN:
		if (pid == 0) {
			set_params(config, vm);
			pid = exec_avahi_publish(config);
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
