#include <sys/nv.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

#include "log.h"
#include "conf.h"
#include "vars.h"
#include "parser.h"
#include "bmd.h"
#include "vm.h"

extern SLIST_HEAD(vm_conf_head, vm_conf_entry) vm_conf_list;
extern SLIST_HEAD(, vm_entry) vm_list;
extern struct global_conf gl_conf;

SLIST_HEAD(, sock_buf) sock_list = SLIST_HEAD_INITIALIZER();

struct sock_buf *
create_sock_buf(int fd)
{
	struct sock_buf *r;

	if ((r = calloc(1, sizeof(*r))) == NULL)
		return NULL;
	r->type = SOCKBUF;
	r->fd = fd;
	SLIST_INSERT_HEAD(&sock_list, r, next);
	return r;
}

void
destroy_sock_buf(struct sock_buf *p)
{
	if (p == NULL)
		return;
	close(p->fd);
	free(p->buf);
	SLIST_REMOVE(&sock_list, p, sock_buf, next);
	free(p);
}

struct sock_buf *
lookup_sock_buf(int fd)
{
	struct sock_buf *p;

	SLIST_FOREACH (p, &sock_list, next)
		if (p->fd == fd)
			return p;
	return NULL;
}

void
clear_sock_buf(struct sock_buf *p)
{
	free(p->buf);
	p->buf = NULL;
	p->state = 0;
	p->buf_size = 0;
	p->read_size = 0;
	p->read_bytes = 0;
}

void
clear_send_sock_buf(struct sock_buf *p)
{
	free(p->res_buf);
	p->res_buf = NULL;
	p->res_size = 0;
	p->res_bytes = 0;
}

/**
 * return value:
 * -1 : error
 *  0 : closed
 *  1 : continue
 *  2 : finished reading
 */
int
send_sock_buf(struct sock_buf *p)
{
	ssize_t n = p->res_bytes;
	size_t size = p->res_size;
	char *buf = p->res_buf;

retry:
	if ((n = send(p->fd, buf + n, size - n, MSG_DONTWAIT)) < 0) {
		switch (errno) {
		case EINTR:
			goto retry;
		case EAGAIN:
			return 1;
		default:
			return -1;
		}
	}
	p->res_bytes += n;
	if (p->res_bytes == p->res_size)
		return 2;
	return 1;
}

/**
 * return value:
 * -1 : error
 *  0 : closed
 *  1 : continue
 *  2 : finished reading
 */
int
recv_sock_buf(struct sock_buf *sb)
{
	ssize_t n;
	char *start;
	size_t nread, size;
	char buf[1];

	if (sb->state == 0) {
		start = sb->size;
		nread = sb->read_size;
		size = sizeof(sb->size);
	} else {
		start = sb->buf;
		nread = sb->read_bytes;
		size = sb->buf_size;
	}

	if (size == nread) {
		/*
		 * Prepare 1 byte buffer
		 * to deletect the socket is closed.
		 */
		start = buf;
		nread = 0;
		size = sizeof(buf);
	}

retry:
	n = recv(sb->fd, start + nread, size - nread, MSG_DONTWAIT);
	if (n < 0) {
		switch (errno) {
		case EINTR:
			goto retry;
		case EAGAIN:
			return 1;
		default:
			return -1;
		}
	}
	if (n == 0)
		return 0;
	if (start == buf)
		return -1;

	nread += n;
	if (sb->state == 0) {
		sb->read_size = nread;
		if (nread == size) {
			sb->state = 1;
			sb->buf_size = ntohl(*((int32_t *)sb->size));
			if (sb->buf_size > 1024*1024)
				return -1;
			sb->buf = malloc(sb->buf_size);
			if (sb->buf == NULL)
				return -1;
		}
	} else {
		sb->read_bytes = nread;
		if (nread == size)
			return 2;
	}
	return 1;
}

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


/*
 * The argument `style` must be one of followings.
 *  -  0 = boot
 *  -  1 = install
 */
static nvlist_t *
boot0_command(int s, const nvlist_t *nv, int style)
{
	int fd;
	const char *name, *reason;
	struct vm_entry *vm_ent;
	struct vm *vm;
	struct vm_conf *conf;
	struct vm_conf_entry *conf_ent;
	nvlist_t *res;
	bool error = false;

	if (style < 0) {
		error = true;
		reason = "internal error";
	}

	if ((name = nvlist_get_string(nv, "name")) == NULL ||
	    (vm_ent = lookup_vm_by_name(name)) == NULL) {
		error = true;
		reason = "VM not found";
		goto ret;
	}
	vm = &vm_ent->vm;

	if (style < 2 && vm_ent->vm.state != INIT &&
	    vm_ent->vm.state != TERMINATE) {
		error = true;
		reason = "already running";
		goto ret;
	}

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

	switch (style) {
	case 0:
		break;
	case 1:
		vm_ent->vm.conf->install = true;
		break;
	default:
		error = true;
		reason = "internal error";
		goto ret;
	}

	if (start_virtual_machine(vm_ent) < 0) {
		error = true;
		reason = "failed to start";
	}

ret:
	res = nvlist_create(0);
	nvlist_add_bool(res, "error", error);
	if (error)
		nvlist_add_string(res, "reason", reason);
	return res;
}

static nvlist_t *
boot_command(int s, const nvlist_t *nv)
{
	return boot0_command(s, nv, 0);
}

static nvlist_t *
install_command(int s, const nvlist_t *nv)
{
	return boot0_command(s, nv, 1);
}

static nvlist_t *
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
		nvlist_add_string(p, "ncpu", vm_ent->vm.conf->ncpu);
		nvlist_add_string(p, "memory", vm_ent->vm.conf->memory);
		nvlist_add_string(p, "loader", vm_ent->vm.conf->loader);
		nvlist_add_string(p, "state", state_string[vm_ent->vm.state]);
		list[i++] = p;
	}

	nvlist_add_nvlist_array(res, "vm_list", list, count);
ret:
	nvlist_add_bool(res, "error", error);
	if (error)
		nvlist_add_string(res, "reason", reason);
	free(list);
	return res;
}

static nvlist_t *
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
	return res;
}

static nvlist_t *
shutdown_command(int s, const nvlist_t *nv) {
	return vm_down_command(s, nv, 0);
}

static nvlist_t *
reset_command(int s, const nvlist_t *nv) {
	return vm_down_command(s, nv, 1);
}

static nvlist_t *
poweroff_command(int s, const nvlist_t *nv) {
	return vm_down_command(s, nv, 2);
}

typedef nvlist_t *(*cfunc)(int s, const nvlist_t *nv);

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
recv_command(struct sock_buf *sb)
{
	const char *cmd;
	nvlist_t *nv, *res;
	cfunc func;

	if ((nv = nvlist_unpack(sb->buf, sb->buf_size, 0)) == NULL)
		return -1;

	if ((cmd = nvlist_get_string(nv, "command")) == NULL)
		goto err;

	if ((func = get_command_function(cmd)) == NULL)
		goto err;

	res = (*func)(sb->fd, nv);

	sb->res_buf = nvlist_pack(res, &sb->res_size);
	if (sb->res_buf == NULL) {
		nvlist_destroy(nv);
		return -1;
	}
	sb->res_bytes = 0;

	nvlist_destroy(nv);
	return 0;
err:
	nvlist_destroy(nv);
	res = nvlist_create(0);
	nvlist_add_bool(res, "error", true);
	nvlist_add_string(res, "reason", "unknown command");
	sb->res_buf = nvlist_pack(res, &sb->res_size);
	if (sb->res_buf == NULL) {
		nvlist_destroy(res);
		return -1;
	}
	sb->res_bytes = 0;
	nvlist_destroy(res);
	return 0;
}
