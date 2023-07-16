#include <sys/wait.h>

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>

#include "../bmd_plugin.h"

static PLUGIN_ENV *plugin_env;

static int
hookcmd_initialize(PLUGIN_ENV *env)
{
	plugin_env = env;
	return 0;
}

static void
hookcmd_finalize()
{
}

static int
hookcmd_parse_config(nvlist_t *config, const char *key, const char *val)
{
	if (strcasecmp(key, "hookcmd"))
		return 1;

	if (access(val, R_OK | X_OK) == 0) {
		nvlist_add_string(config, "hookcmd", val);
		return 0;
	}

	return -1;
}

static int
on_process_exit(int id, void *data)
{
	return waitpid(id, NULL, WNOHANG);
}

static void
hookcmd_status_change(struct vm *vm, nvlist_t *config)
{
	pid_t pid;
	const char *cmd0;
	char *cmd1, *cmd2, *args[4];
	static char *state_name[] = { "TERMINATE", "LOAD", "RUN",
		"STOP", "REMOVE", "RESTART" };

	if (! nvlist_exists_string(config, "hookcmd"))
		return;

	cmd0 = nvlist_get_string(config, "hookcmd");
	if ((cmd1 = strdup(cmd0)) == NULL)
		return;
	cmd2 = basename(cmd1);

	if ((pid = fork()) < 0) {
		free(cmd1);
		return;
	}

	if (pid == 0) {
		args[0] = cmd2;
		args[1] = vm->conf->name;
		args[2] = state_name[vm->state];
		args[3] = NULL;
		execv(cmd0, args);
		exit(1);
	}
	free(cmd1);

	plugin_env->wait_for_process(pid, on_process_exit, NULL);
}

PLUGIN_DESC plugin_desc = { PLUGIN_VERSION, "hookcmd", hookcmd_initialize,
			    hookcmd_finalize, hookcmd_status_change, hookcmd_parse_config, NULL};
