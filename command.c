#include <sys/types.h>
#include <sys/nv.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "vars.h"
#include "vm.h"

int
connect_to_server(const struct global_conf *gc)
{
	int s;
	struct sockaddr_un addr;

	addr.sun_family = PF_UNIX;
	strncpy(addr.sun_path, gc->cmd_sock_path, sizeof(addr.sun_path));
	addr.sun_len = SUN_LEN(&addr);

	while ((s = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
		if (errno != EAGAIN && errno != EINTR)
			return -1;

	while (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		if (errno != EAGAIN && errno != EINTR)
			goto err;

	return s;
err:
	close(s);
	return -1;
}

int
create_command_server(const struct global_conf *gc)
{
	int s;
	void *set = NULL;
	struct sockaddr_un addr;
	struct stat st;

	addr.sun_family = PF_UNIX;
	strncpy(addr.sun_path, gc->cmd_sock_path, sizeof(addr.sun_path));
	addr.sun_len = SUN_LEN(&addr);

	while ((s = socket(PF_UNIX, SOCK_STREAM, 0)) < 0)
		if (errno != EAGAIN && errno != EINTR)
			return -1;

	while (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		if (errno != EAGAIN && errno != EINTR)
			goto err;

	while (listen(s, 5) < 0)
		if (errno != EAGAIN && errno != EINTR)
			goto err;

	if (gc->unix_domain_socket_mode == NULL ||
	    stat(gc->cmd_sock_path, &st) < 0 ||
	    (set = setmode(gc->unix_domain_socket_mode)) == NULL)
		return s;

	if (chmod(gc->cmd_sock_path, getmode(set, st.st_mode)) < 0)
		goto err;

	free(set);
	return s;
err:
	free(set);
	close(s);
	return -1;
}

int
accept_command_socket(int s0)
{
	int s;

	while ((s = accept(s0, NULL, 0)) < 0)
		if (errno != EAGAIN && errno != EINTR)
			return -1;

	return s;
}

int boot_command(int s, const nvlist_t *nv);
int install_command(int s, const nvlist_t *nv);
int reload_command(int s, const nvlist_t *nv);
int list_command(int s, const nvlist_t *nv);
int shutdown_command(int s, const nvlist_t *nv);

typedef int (*cfunc)(int s, const nvlist_t *nv);

struct command_entry {
	char *name;
	cfunc func;
};

/* must be sorted by name */
struct command_entry command_list[] = {
	{ "boot", &boot_command },
	{ "install", &install_command },
	{ "list", &list_command },
	{ "reload", &reload_command },
	{ "shutdown", &shutdown_command },
};

static int
compare_command_entry(const void *a, const void *b)
{
	const char *name = a;
	const struct command_entry *ent = b;
	return strcasecmp(name, ent->name);
}

static cfunc
get_command_function(const char *name)
{

	struct command_entry *p;

	p = bsearch(name, command_list,
	    sizeof(command_list) / sizeof(command_list[0]),
	    sizeof(command_list[0]), compare_command_entry);

	return ((p != NULL) ? p->func : NULL);
}

int
recv_command(int s)
{
	const char *cmd;
	nvlist_t *nv;
	cfunc func;

	if ((nv = nvlist_recv(s, 0)) == NULL)
		return -1;

	if ((cmd = nvlist_get_string(nv, "command")) == NULL)
		goto err;

	if ((func = get_command_function(cmd)) == NULL)
		goto err;

	if ((*func)(s, nv) < 0)
		goto err;

	nvlist_destroy(nv);
	return 0;
err:
	nvlist_destroy(nv);
	nv = nvlist_create(0);
	nvlist_add_bool(nv, "error", true);
	nvlist_add_string(nv, "reason", "unknown command");
	nvlist_send(s, nv);
	nvlist_destroy(nv);
	return -1;
}
