#include <sys/signal.h>
#include <sys/nv.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdbool.h>

#include "log.h"
#include "conf.h"
#include "vars.h"
#include "parser.h"
#include "bmd.h"
#include "vm.h"

extern SLIST_HEAD(vm_conf_head, vm_conf_entry) vm_conf_list;
extern SLIST_HEAD(, vm_entry) vm_list;
extern struct global_conf gl_conf;

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


static int
boot0_command(int s, const nvlist_t *nv, bool install)
{
	const char *name, *reason;
	struct vm_entry *vm_ent;
	nvlist_t *res;
	bool error = false;

	if ((name = nvlist_get_string(nv, "name")) == NULL ||
	    (vm_ent = lookup_vm_by_name(name)) == NULL) {
		error = true;
		reason = "VM not found";
		goto ret;
	}

	if (vm_ent->vm.state != INIT && vm_ent->vm.state != TERMINATE) {
		error = true;
		reason = "already running";
		goto ret;
	}

	vm_ent->vm.conf->install = install;

	if (start_virtual_machine(vm_ent) < 0) {
		error = true;
		reason = "failed to start";
	}

ret:
	res = nvlist_create(0);
	nvlist_add_bool(res, "error", error);
	if (error)
		nvlist_add_string(res, "reason", reason);
	nvlist_send(s, res);
	nvlist_destroy(res);
	return 0;
}

static int
reload_command(int s, const nvlist_t *nv)
{
	int fd;
	const char *name, *reason;
	struct vm_entry *vm_ent;
	struct vm *vm;
	struct vm_conf *conf;
	struct vm_conf_entry *conf_ent;
	nvlist_t *res;
	bool error = false;

	if ((name = nvlist_get_string(nv, "name")) == NULL ||
	    (vm_ent = lookup_vm_by_name(name)) == NULL) {
		error = true;
		reason = "VM not found";
		goto ret;
	}
	vm = &vm_ent->vm;

	close(gl_conf.config_fd);
	if ((gl_conf.config_fd = open(gl_conf.config_dir,
		 O_DIRECTORY | O_RDONLY)) < 0) {
		error = true;
		reason = "failed to open config directory";
		goto ret;
	}

	if ((fd = openat(gl_conf.config_fd, vm->conf->filename, O_RDONLY)) <
	    0) {
		error = true;
		reason = "failed to load config file";
		goto ret;
	}

	conf = parse_file(fd, vm->conf->filename);
	close(fd);

	if (conf == NULL) {
		error = true;
		reason = "failed to load config file";
		goto ret;
	}
	conf_ent = realloc(conf, sizeof(*conf_ent));
	if (conf_ent == NULL) {
		free_vm_conf(conf);
		error = true;
		reason = "failed to load config file";
		goto ret;
	}

	SLIST_REMOVE(&vm_conf_list, (struct vm_conf_entry *)vm->conf,
	    vm_conf_entry, next);
	SLIST_INSERT_HEAD(&vm_conf_list, conf_ent, next);
	free_vm_conf(vm->conf);
	vm->conf = conf = &conf_ent->conf;

	switch (vm->state) {
	case LOAD:
	case RUN:
		INFO("stop vm %s\n", conf->name);
		acpi_poweroff_vm(&vm_ent->vm);
		set_timer(vm_ent, conf->stop_timeout);
		vm->state = RESTART;
		break;
	case INIT:
	case TERMINATE:
		start_virtual_machine(vm_ent);
		INFO("start vm %s\n", conf->name);
		break;
	case STOP:
	case REMOVE:
		vm->state = RESTART;
		break;
	default:
		break;
	}

ret:
	res = nvlist_create(0);
	nvlist_add_bool(res, "error", error);
	if (error)
		nvlist_add_string(res, "reason", reason);
	nvlist_send(s, res);
	nvlist_destroy(res);
	return 0;
}

static int
boot_command(int s, const nvlist_t *nv)
{
	return boot0_command(s, nv, false);
}

static int
install_command(int s, const nvlist_t *nv)
{
	return boot0_command(s, nv, true);
}

static int
list_command(int s, const nvlist_t *nv)
{
	size_t i, count = 0;
	const char *reason;
	nvlist_t *res, *p;
	const nvlist_t **list = NULL;
	struct vm_entry *vm_ent;
	bool error = false;
	static char *state_string[] = { "STOP", "LOAD", "RUN", "STOP",
		"TERMINATING", "TERMINATING", "REBOOTING" };

	res = nvlist_create(0);

	SLIST_FOREACH (vm_ent, &vm_list, next)
		count++;

	list = malloc(count * sizeof(nvlist_t *));
	if (list == NULL) {
		reason = "can not allocate memory";
		goto ret;
	}

	i = 0;
	SLIST_FOREACH (vm_ent, &vm_list, next) {
		p = nvlist_create(0);
		nvlist_add_string(p, "name", vm_ent->vm.conf->name);
		nvlist_add_string(p, "state", state_string[vm_ent->vm.state]);
		list[i++] = p;
	}

	nvlist_add_nvlist_array(res, "vm_list", list, count);
ret:
	nvlist_add_bool(res, "error", error);
	if (error)
		nvlist_add_string(res, "reason", reason);
	nvlist_send(s, res);
	nvlist_destroy(res);
	free(list);
	return 0;
}

static int
vm_down_command(int s, const nvlist_t *nv, int how)
{
	const char *name, *reason;
	struct vm_entry *vm_ent;
	struct vm_conf *conf;
	nvlist_t *res;
	bool error = false;

	if ((name = nvlist_get_string(nv, "name")) == NULL ||
	    (vm_ent = lookup_vm_by_name(name)) == NULL) {
		error = true;
		reason = "VM not found";
		goto ret;
	}

	if (vm_ent->vm.state != LOAD && vm_ent->vm.state != RUN)
		goto ret;

	conf = vm_ent->vm.conf;
	switch (how) {
	case 0:
		INFO("stop vm %s\n", conf->name);
		acpi_poweroff_vm(&vm_ent->vm);
		set_timer(vm_ent, vm_ent->vm.conf->stop_timeout);
		vm_ent->vm.state = STOP;
		break;
	case 1:
		INFO("reset vm %s\n", conf->name);
		reset_vm(&vm_ent->vm);
		break;
	case 2:
		INFO("poweroff vm %s\n", conf->name);
		poweroff_vm(&vm_ent->vm);
		vm_ent->vm.state = STOP;
		break;
	default:
		error = true;
		reason = "Unknown command";
	}

ret:
	res = nvlist_create(0);
	nvlist_add_bool(res, "error", error);
	if (error)
		nvlist_add_string(res, "reason", reason);
	nvlist_send(s, res);
	nvlist_destroy(res);
	return 0;
}

static int
shutdown_command(int s, const nvlist_t *nv) {
	return vm_down_command(s, nv, 0);
}

static int
reset_command(int s, const nvlist_t *nv) {
	return vm_down_command(s, nv, 1);
}

static int
poweroff_command(int s, const nvlist_t *nv) {
	return vm_down_command(s, nv, 2);
}

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
	{ "poweroff", &poweroff_command },
	{ "reload", &reload_command },
	{ "reset", &reset_command },
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
