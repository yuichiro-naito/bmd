#include <sys/wait.h>

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>

#include "../bmd_plugin.h"

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
	struct vm_conf *conf = vm_get_conf(vm);
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
		args[1] = get_name(conf);
		args[2] = state_name[get_state(vm)];
		args[3] = NULL;
		execv(cmd0, args);
		exit(1);
	}
	free(cmd1);

	plugin_wait_for_process(pid, on_process_exit, NULL);
}

PLUGIN_DESC plugin_desc = {
	.version = PLUGIN_VERSION,
	.name = "hookcmd",
	.initialize = NULL,
	.finalize = NULL,
	.on_status_change = hookcmd_status_change,
	.parse_config = hookcmd_parse_config,
	.method = NULL
};
