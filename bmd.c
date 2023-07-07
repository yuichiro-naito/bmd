#include <sys/param.h>
#include <sys/dirent.h>
#include <sys/event.h>
#include <sys/procctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include "bmd.h"
#include "conf.h"
#include "log.h"
#include "parser.h"
#include "server.h"
#include "vars.h"
#include "vm.h"

/*
  List of VM configurations.
 */
struct vm_conf_head vm_conf_list = LIST_HEAD_INITIALIZER();

/*
  List of virtual machines.
 */
SLIST_HEAD(, vm_entry) vm_list = SLIST_HEAD_INITIALIZER();
SLIST_HEAD(, plugin_entry) plugin_list = SLIST_HEAD_INITIALIZER();

/*
  Global configuration.
 */
struct global_conf gl_conf0 = { LOCALBASE "/etc/bmd.conf",
	LOCALBASE "/libexec/bmd", LOCALBASE "/var/cache/bmd",
	"/var/run/bmd.pid", "/var/run/bmd.sock", NULL, NMDM_OFFSET, -1, 0, -1 };

struct global_conf *gl_conf = &gl_conf0;

extern struct vm_methods method_list[];

void
free_gl_conf(struct global_conf *gl)
{
	free(gl->config_file);
	free(gl->pid_path);
	free(gl->plugin_dir);
	free(gl->vars_dir);
	free(gl->cmd_sock_path);
	free(gl->unix_domain_socket_mode);
	free(gl);
}

int
init_gl_conf()
{
	struct global_conf *t;
	if ((t = calloc(1, sizeof(*t))) == NULL)
		return -1;
#define COPY_ATTR_STRING(attr) \
	if (gl_conf0.attr != NULL &&				\
	    (t->attr = strdup(gl_conf0.attr)) == NULL)		\
		goto err;
#define COPY_ATTR_INT(attr) t->attr = gl_conf0.attr

	COPY_ATTR_STRING(config_file);
	COPY_ATTR_STRING(pid_path);
	COPY_ATTR_STRING(plugin_dir);
	COPY_ATTR_STRING(vars_dir);
	COPY_ATTR_STRING(cmd_sock_path);
	COPY_ATTR_STRING(unix_domain_socket_mode);
	COPY_ATTR_INT(nmdm_offset);
	COPY_ATTR_INT(cmd_sock);
	COPY_ATTR_INT(foreground);
	COPY_ATTR_INT(kq);
#undef COPY_ATTR_STRING
#undef COPY_ATTR_INT

	gl_conf = t;
	return 0;

err:
	free_gl_conf(t);
	return -1;
}

int
merge_gl_conf(struct global_conf *gc)
{
#define REPLACE_STR(attr)	\
	if (gc->attr) {							\
		if (gl_conf->attr)					\
			free(gl_conf->attr);				\
		gl_conf->attr = gc->attr;				\
		gc->attr = NULL;					\
	}
#define REPLACE_INT(attr)  \
	if (gc->attr != 0)			\
		gl_conf->attr = gc->attr;

	REPLACE_STR(config_file);
	REPLACE_STR(pid_path);
	REPLACE_STR(plugin_dir);
	REPLACE_STR(vars_dir);
	REPLACE_STR(cmd_sock_path);
	REPLACE_STR(unix_domain_socket_mode);
	REPLACE_INT(nmdm_offset);
#undef REPLACE_INT
#undef REPLACE_STR

	free(gc);
	return 0;
}

int
wait_for_reading(struct vm_entry *vm_ent)
{
	int i = 0;
	struct kevent ev[2];

	if (VM_OUTFD(vm_ent) != -1)
		EV_SET(&ev[i++], VM_OUTFD(vm_ent), EVFILT_READ, EV_ADD, 0, 0,
		    vm_ent);
	if (VM_ERRFD(vm_ent) != -1)
		EV_SET(&ev[i++], VM_ERRFD(vm_ent), EVFILT_READ, EV_ADD, 0, 0,
		    vm_ent);
	while (kevent(gl_conf->kq, ev, i, NULL, 0, NULL) < 0)
		if (errno != EINTR) {
			ERR("failed to wait reading fd (%s)\n",
			    strerror(errno));
			return -1;
		}

	return 0;
}

int
stop_waiting_fd(struct vm_entry *vm_ent)
{
	int i = 0;
	struct kevent ev[2];

	if (VM_OUTFD(vm_ent) != -1)
		EV_SET(&ev[i++], VM_OUTFD(vm_ent), EVFILT_READ, EV_DELETE, 0, 0,
		    vm_ent);
	if (VM_ERRFD(vm_ent) != -1)
		EV_SET(&ev[i++], VM_ERRFD(vm_ent), EVFILT_READ, EV_DELETE, 0, 0,
		    vm_ent);
	while (kevent(gl_conf->kq, ev, i, NULL, 0, NULL) < 0)
		if (errno != EINTR) {
			ERR("failed to delete waiting fd (%s)\n",
			    strerror(errno));
			return -1;
		}

	VM_CLOSE(vm_ent, OUTFD);
	VM_CLOSE(vm_ent, ERRFD);

	return 0;
}

/*
 * Set event timer.
 * Event timer has 2 types. One is for stop timeout, the other is delay boot.
 * If an event is for delay boot, set flag = 1.
 */
int
set_timer(struct vm_entry *vm_ent, int second, int flag)
{
	static int id = 0;
	struct event_list *el;

	if ((el = malloc(sizeof(*el))) == NULL)
		goto err;

	EV_SET(&el->ev, ((id += 2) | (flag & 1)), EVFILT_TIMER,
	       EV_ADD | EV_ONESHOT, NOTE_SECONDS, second, vm_ent);
	while (kevent(gl_conf->kq, &el->ev, 1, NULL, 0, NULL) < 0)
		if (errno != EINTR)
			goto err;
	SLIST_INSERT_HEAD(VM_EVLIST(vm_ent), el, next);
	return 0;
err:
	free(el);
	ERR("failed to set timer (%s)\n", strerror(errno));
	return -1;
}

/**
 * Clear all timers for VM.
 */
int
clear_all_timers(struct vm_entry *vm_ent)
{
	struct event_list *el, *eln;

	SLIST_FOREACH_SAFE (el, VM_EVLIST(vm_ent), next, eln) {
		el->ev.flags = EV_DELETE;
		while (kevent(gl_conf->kq, &el->ev, 1, NULL, 0, NULL) < 0)
			if (errno != EINTR)
				break;
		free(el);
	}
	SLIST_INIT(VM_EVLIST(vm_ent));
	return 0;
}

int
wait_for_process(struct vm_entry *vm_ent)
{
	struct kevent ev;

	EV_SET(&ev, VM_PID(vm_ent), EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT,
	    0, vm_ent);
	while (kevent(gl_conf->kq, &ev, 1, NULL, 0, NULL) < 0)
		if (errno != EINTR) {
			ERR("failed to wait process (%s)\n", strerror(errno));
			return -1;
		}
	return 0;
}

int
load_plugins(const char *plugin_dir)
{
	DIR *d;
	void *hdl;
	int fd;
	struct dirent *ent;
	struct plugin_desc *desc;
	struct plugin_entry *pl_ent;
	static int loaded = 0;

	if (loaded != 0)
		return 0;

	if ((d = opendir(plugin_dir)) == NULL) {
		ERR("can not open %s\n", gl_conf->plugin_dir);
		return -1;
	}

	while ((ent = readdir(d)) != NULL) {
		if (ent->d_namlen < 4 || ent->d_name[0] == '.' ||
		    strcmp(&ent->d_name[ent->d_namlen - 3], ".so") != 0)
			continue;
		while ((fd = openat(dirfd(d), ent->d_name, O_RDONLY)) < 0)
			if (errno != EINTR)
				break;
		if (fd < 0)
			continue;

		if ((hdl = fdlopen(fd, RTLD_NOW)) == NULL)
			goto next;

		if ((desc = dlsym(hdl, "plugin_desc")) == NULL ||
		    desc->version != PLUGIN_VERSION ||
		    (pl_ent = calloc(1, sizeof(*pl_ent))) == NULL) {
			dlclose(hdl);
			goto next;
		}

		if (desc->initialize && (*(desc->initialize))(gl_conf) < 0) {
			free(pl_ent);
			dlclose(hdl);
			goto next;
		}
		pl_ent->desc = *desc;
		pl_ent->handle = hdl;
		SLIST_INSERT_HEAD(&plugin_list, pl_ent, next);
		loaded++;
	next:
		close(fd);
	}

	closedir(d);

	return 0;
}

int
remove_plugins()
{
	struct plugin_entry *pl_ent, *pln;

	SLIST_FOREACH_SAFE (pl_ent, &plugin_list, next, pln) {
		if (pl_ent->desc.finalize)
			(*pl_ent->desc.finalize)(gl_conf);
		dlclose(pl_ent->handle);
		free(pl_ent);
	}
	SLIST_INIT(&plugin_list);

	return 0;
}

void
call_plugins(struct vm_entry *vm_ent)
{
	struct plugin_data *pd;

	SLIST_FOREACH (pd, &VM_PLUGIN_DATA(vm_ent), next)
		if (pd->ent->desc.on_status_change)
			(pd->ent->desc.on_status_change)(VM_PTR(vm_ent),
							 pd->pl_conf);
}

int
call_plugin_parser(struct plugin_data_head *head,
		   const char *key, const char *val)
{
	int rc;
	struct plugin_data *pd;

	SLIST_FOREACH (pd, head, next)
		if (pd->ent->desc.parse_config &&
		    (rc = (pd->ent->desc.parse_config)(pd->pl_conf, key, val)) <= 0)
			return rc;
	return 1;
}

void
free_vm_entry(struct vm_entry *vm_ent)
{
	struct net_conf *nc, *nnc;
	struct event_list *el, *eln;

	STAILQ_FOREACH_SAFE (nc, VM_TAPS(vm_ent), next, nnc)
		free_net_conf(nc);
	SLIST_FOREACH_SAFE (el, VM_EVLIST(vm_ent), next, eln)
		free(el);
	free(VM_MAPFILE(vm_ent));
	free(VM_VARSFILE(vm_ent));
	free(VM_ASCOMPORT(vm_ent));
	free_vm_conf_entry(VM_CONF_ENT(vm_ent));
	free(vm_ent);
}

void
free_vm_list()
{
	struct vm_entry *vm_ent, *vmn;

	SLIST_FOREACH_SAFE (vm_ent, &vm_list, next, vmn)
		free_vm_entry(vm_ent);
	SLIST_INIT(&vm_list);
}

void
free_plugin_data(struct plugin_data_head *head)
{
	struct plugin_data *pld, *pln;

	SLIST_FOREACH_SAFE (pld, head, next, pln) {
		nvlist_destroy(pld->pl_conf);
		free(pld);
	}
	SLIST_INIT(head);
}

void
free_vm_conf_entry(struct vm_conf_entry *conf_ent)
{
	free_plugin_data(&conf_ent->pl_data);
	free_vm_conf(&conf_ent->conf);
}

int
create_plugin_data(struct plugin_data_head *head)
{
	struct plugin_entry *pl_ent;
	struct plugin_data *pld;

	SLIST_INIT(head);
	SLIST_FOREACH (pl_ent, &plugin_list, next) {
		if ((pld = calloc(1, sizeof(*pld))) == NULL)
			goto err;
		pld->ent = pl_ent;
		if ((pld->pl_conf = nvlist_create(0)) == NULL) {
			free(pld);
			goto err;
		}
		SLIST_INSERT_HEAD(head, pld, next);
	}

	return 0;

err:
	free_plugin_data(head);
	return -1;
}

struct vm_entry *
create_vm_entry(struct vm_conf_entry *conf_ent)
{
	struct vm_entry *vm_ent;

	if ((vm_ent = calloc(1, sizeof(struct vm_entry))) == NULL)
		return NULL;
	VM_TYPE(vm_ent) = VMENTRY;
	VM_METHOD(vm_ent) = &method_list[conf_ent->conf.backend];
	VM_CONF(vm_ent) = &conf_ent->conf;
	VM_STATE(vm_ent) = TERMINATE;
	VM_PID(vm_ent) = -1;
	VM_INFD(vm_ent) = -1;
	VM_OUTFD(vm_ent) = -1;
	VM_ERRFD(vm_ent) = -1;
	VM_LOGFD(vm_ent) = -1;
	STAILQ_INIT(VM_TAPS(vm_ent));
	SLIST_INIT(VM_EVLIST(vm_ent));
	SLIST_INSERT_HEAD(&vm_list, vm_ent, next);

	return vm_ent;
}

static int
nmdm_selector(const struct dirent *e)
{
	return (strncmp(e->d_name, "nmdm", 4) == 0 &&
		e->d_name[e->d_namlen - 1] == 'B');
}

static int
get_nmdm_number(const char *p)
{
	int v = 0;

	if (p == NULL)
		return -1;

	for (; *p != '\0'; p++)
		if (isnumber(*p))
			v = v * 10 + *p - '0';
	return v;
}

/**
 * Assign new 'nmdm' which has a bigger number in all VM configurations and
 * "/dev/" directory.
 */
int
assign_comport(struct vm_entry *vm_ent)
{
	int fd, i, n, v, max = -1;
	struct dirent **names;
	char *new_com;
	struct vm_entry *e;
	struct vm_conf *conf = VM_CONF(vm_ent);

	if (conf->comport == NULL)
		return 0;

	/* Already assigned */
	if (VM_ASCOMPORT(vm_ent))
		return 0;

	/* If no need to assign comport, copy from `struct vm_conf.comport`. */
	if (strcasecmp(conf->comport, "auto")) {
		if ((VM_ASCOMPORT(vm_ent) = strdup(conf->comport)) == NULL)
			return -1;
		return 0;
	}

	/* Get maximum nmdm number of all VMs. */
	SLIST_FOREACH (e, &vm_list, next) {
		v = get_nmdm_number(VM_CONF(e)->comport);
		if (v > max)
			max = v;
		v = get_nmdm_number(VM_ASCOMPORT(e));
		if (v > max)
			max = v;
	}

	/* Get maximum nmdm number in "/dev" directory. */
	if ((n = scandir("/dev", &names, nmdm_selector, NULL)) < 0)
		return -1;

	for (i = 0; i < n; i++) {
		v = get_nmdm_number(names[i]->d_name);
		if (v > max)
			max = v;
		free(names[i]);
	}
	free(names);

	if (max < gl_conf->nmdm_offset - 1)
		max = gl_conf->nmdm_offset - 1;

	for (i = 1; i < 6; i++) {
		if (asprintf(&new_com, "/dev/nmdm%dB", max + i) < 0)
			return -1;

		while ((fd = open(new_com, O_RDWR|O_NONBLOCK)) < 0)
			if (errno != EINTR)
				break;
		if (fd >= 0)
			break;
		free(new_com);
	}
	if (fd < 0)
		return -1;
	close(fd);
	VM_ASCOMPORT(vm_ent) = new_com;

	return 0;
}

int
start_virtual_machine(struct vm_entry *vm_ent)
{
	struct vm_conf *conf = VM_CONF(vm_ent);
	char *name = conf->name;

	VM_METHOD(vm_ent) = &method_list[conf->backend];

	if (assign_comport(vm_ent) < 0) {
		ERR("failed to assign comport for vm %s\n", name);
		return -1;
	}

	if (VM_START(vm_ent) < 0) {
		ERR("failed to start vm %s\n", name);
		VM_CLEANUP(vm_ent);
		return -1;
	}

	if (wait_for_process(vm_ent) < 0 || wait_for_reading(vm_ent) < 0) {
		ERR("failed to set kevent for vm %s\n", name);
		/*
		 * Force to kill bhyve.
		 * If this error happens, we can't manage bhyve process at all.
		 */
		VM_POWEROFF(vm_ent);
		waitpid(VM_PID(vm_ent), NULL, 0);
		VM_CLEANUP(vm_ent);
		return -1;
	}

	if (VM_STATE(vm_ent) == RUN)
		INFO("start vm %s\n", name);

	call_plugins(vm_ent);
	if (VM_STATE(vm_ent) == LOAD && conf->loader_timeout >= 0 &&
	    shutdown_timer(vm_ent, conf->loader_timeout) < 0) {
		ERR("failed to set timer for vm %s\n", name);
		return -1;
	}

	if (VM_LOGFD(vm_ent) == -1)
		while ((VM_LOGFD(vm_ent) = open(conf->err_logfile,
						O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC,
						0644)) < 0)
			if (errno != EINTR)
				break;

	return 0;
}

int
start_virtual_machines()
{
	struct vm_conf *conf;
	struct vm_conf_entry *conf_ent;
	struct vm_entry *vm_ent;
	struct kevent sigev[3];

	EV_SET(&sigev[0], SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&sigev[1], SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&sigev[2], SIGHUP, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);

	while (kevent(gl_conf->kq, sigev, 3, NULL, 0, NULL) < 0)
		if (errno != EINTR)
			return -1;

	LIST_FOREACH (conf_ent, &vm_conf_list, next) {
		vm_ent = create_vm_entry(conf_ent);
		if (vm_ent == NULL)
			return -1;
		conf = &conf_ent->conf;
		if (conf->boot == NO)
			continue;
		if (conf->boot_delay > 0) {
			if (boot_timer(vm_ent, conf->boot_delay) < 0)
				ERR("failed to set boot delay timer for vm %s\n",
				    conf->name);
			continue;
		}
		start_virtual_machine(vm_ent);
	}

	return 0;
}

void
stop_virtual_machine(struct vm_entry *vm_ent)
{
	stop_waiting_fd(vm_ent);
	clear_all_timers(vm_ent);
	VM_CLEANUP(vm_ent);
	call_plugins(vm_ent);
}

struct vm_entry *
lookup_vm_by_name(const char *name)
{
	struct vm_entry *vm_ent;

	SLIST_FOREACH (vm_ent, &vm_list, next)
		if (strcmp(VM_CONF(vm_ent)->name, name) == 0)
			return vm_ent;
	return NULL;
}

int
reload_virtual_machines()
{
	struct vm_conf *conf;
	struct vm_conf_entry *conf_ent, *cen;
	struct vm_entry *vm_ent, *vmn;
	struct vm_conf_head new_list = LIST_HEAD_INITIALIZER();

	if (load_config_file(&new_list, false) < 0)
		return -1;

	/* make sure new_conf is NULL */
	SLIST_FOREACH (vm_ent, &vm_list, next)
		VM_NEWCONF(vm_ent) = NULL;

	LIST_FOREACH (conf_ent, &new_list, next) {
		conf = &conf_ent->conf;
		vm_ent = lookup_vm_by_name(conf->name);
		if (vm_ent == NULL) {
			vm_ent = create_vm_entry(conf_ent);
			if (vm_ent == NULL)
				return -1;
			VM_NEWCONF(vm_ent) = conf;
			if (conf->boot == NO)
				continue;
			if (conf->boot_delay > 0) {
				if (boot_timer(vm_ent, conf->boot_delay) < 0)
					ERR("failed to set timer for %s\n",
					    conf->name);
				continue;
			}
			start_virtual_machine(vm_ent);
			continue;
		}
		if (VM_LOGFD(vm_ent) != -1 &&
		    VM_CONF(vm_ent)->err_logfile != NULL) {
			VM_CLOSE(vm_ent, LOGFD);
			while ((VM_LOGFD(vm_ent) =
				open(VM_CONF(vm_ent)->err_logfile,
				     O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC,
				     0644)) < 0)
				if (errno != EINTR)
					break;
		}
		VM_NEWCONF(vm_ent) = conf;
		if (conf->boot != NO && conf->reboot_on_change &&
		    compare_vm_conf(conf, VM_CONF(vm_ent)) != 0) {
			switch (VM_STATE(vm_ent)) {
			case TERMINATE:
				boot_timer(vm_ent, MAX(conf->boot_delay, 1));
				break;
			case LOAD:
			case RUN:
				INFO("reboot vm %s\n", conf->name);
				VM_ACPI_POWEROFF(vm_ent);
				shutdown_timer(vm_ent, conf->stop_timeout);
				VM_STATE(vm_ent) = RESTART;
				break;
			case STOP:
				VM_STATE(vm_ent) = RESTART;
			default:
				break;
			}
			continue;
		}
		if (VM_NEWCONF(vm_ent)->boot == VM_CONF(vm_ent)->boot)
			continue;
		switch (conf->boot) {
		case NO:
			if (VM_STATE(vm_ent) == LOAD ||
			    VM_STATE(vm_ent) == RUN) {
				INFO("acpi power off vm %s\n", conf->name);
				VM_ACPI_POWEROFF(vm_ent);
				shutdown_timer(vm_ent, conf->stop_timeout);
				VM_STATE(vm_ent) = STOP;
			} else if (VM_STATE(vm_ent) == RESTART)
				VM_STATE(vm_ent) = STOP;
			break;
		case ALWAYS:
		case YES:
			if (VM_STATE(vm_ent) == TERMINATE) {
				VM_CONF(vm_ent) = conf;
				start_virtual_machine(vm_ent);
			} else if (VM_STATE(vm_ent) == STOP)
				VM_STATE(vm_ent) = RESTART;
			break;
		case ONESHOT:
			// do nothing
			break;
		}
	}

	SLIST_FOREACH_SAFE (vm_ent, &vm_list, next, vmn)
		if (VM_NEWCONF(vm_ent) == NULL) {
			switch (VM_STATE(vm_ent)) {
			case LOAD:
			case RUN:
				conf = VM_CONF(vm_ent);
				INFO("acpi power off vm %s\n", conf->name);
				VM_ACPI_POWEROFF(vm_ent);
				shutdown_timer(vm_ent, conf->stop_timeout);
				/* FALLTHROUGH */
			case STOP:
			case REMOVE:
			case RESTART:
				VM_STATE(vm_ent) = REMOVE;
				/* remove vm_conf_entry from the list
				   to keep it until actually freed. */
				LIST_REMOVE(VM_CONF_ENT(vm_ent), next);
				break;
			default:
				SLIST_REMOVE(&vm_list, vm_ent, vm_entry,
					     next);
				LIST_REMOVE(VM_CONF_ENT(vm_ent), next);
				free_vm_entry(vm_ent);
			}

		} else {
			VM_CONF(vm_ent) = VM_NEWCONF(vm_ent);
			VM_NEWCONF(vm_ent) = NULL;
		}

	LIST_FOREACH_SAFE (conf_ent, &vm_conf_list, next, cen)
		free_vm_conf_entry(conf_ent);
	LIST_INIT(&vm_conf_list);

	LIST_CONCAT(&vm_conf_list, &new_list, vm_conf_entry, next);

	return 0;
}

static char *
reason_string(int status)
{
	int sz;
	char *mes;

	if (WIFSIGNALED(status))
		sz = asprintf(&mes, " by signal %d%s", WTERMSIG(status),
			      (WCOREDUMP(status) ? " coredump" : ""));
	else if (WIFSTOPPED(status))
		sz = asprintf(&mes, " by signal %d", WSTOPSIG(status));
	else
		sz = ((mes = strdup("")) == NULL ? -1 : 0);

	return (sz < 0) ? NULL : mes;
}

int
event_loop()
{
	struct kevent ev, ev2[2];
	struct vm_entry *vm_ent;
	int n, status;
	char *rs;
	struct sock_buf *sb;
	struct timespec *to, timeout;

	EV_SET(&ev, gl_conf->cmd_sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
	while (kevent(gl_conf->kq, &ev, 1, NULL, 0, NULL) < 0)
		if (errno != EINTR)
			return -1;

wait:
	to = calc_timeout(COMMAND_TIMEOUT_SEC, &timeout);
	while ((n = kevent(gl_conf->kq, NULL, 0, &ev, 1, to)) < 0)
		if (errno != EINTR) {
			ERR("kevent failure (%s)\n", strerror(errno));
			return -1;
		}
	if (n == 0) {
		close_timeout_sock_buf(COMMAND_TIMEOUT_SEC);
		goto wait;
	}

	vm_ent = ev.udata;
	switch (ev.filter) {
	case EVFILT_WRITE:
		if (vm_ent != NULL && VM_TYPE(vm_ent) == SOCKBUF) {
			sb = (struct sock_buf *)vm_ent;
			switch (send_sock_buf(sb)) {
			case 2:
				clear_send_sock_buf(sb);
				EV_SET(&ev2[0], ev.ident, EVFILT_READ,
				    EV_ENABLE, 0, 0, sb);
				EV_SET(&ev2[1], ev.ident, EVFILT_WRITE,
				    EV_DELETE, 0, 0, sb);
				while (kevent(gl_conf->kq, ev2, 2, NULL, 0,
					   NULL) < 0)
					if (errno != EINTR)
						break;
			case 1:
				break;
			default:
				destroy_sock_buf(sb);
				EV_SET(&ev2[0], ev.ident, EVFILT_READ,
				    EV_DELETE, 0, 0, NULL);
				EV_SET(&ev2[1], ev.ident, EVFILT_WRITE,
				    EV_DELETE, 0, 0, NULL);
				while (kevent(gl_conf->kq, ev2, 2, NULL, 0,
					   NULL) < 0)
					if (errno != EINTR)
						break;
				break;
			}
		}
		break;
	case EVFILT_READ:
		if (ev.ident == gl_conf->cmd_sock) {
			if ((n = accept_command_socket(ev.ident)) < 0)
				break;
			sb = create_sock_buf(n);
			EV_SET(&ev, n, EVFILT_READ, EV_ADD, 0, 0, sb);
			while (kevent(gl_conf->kq, &ev, 1, NULL, 0, NULL) < 0)
				if (errno != EINTR) {
					destroy_sock_buf(sb);
					break;
				}
			break;
		}
		if (vm_ent != NULL && VM_TYPE(vm_ent) == SOCKBUF) {
			sb = (struct sock_buf *)vm_ent;
			switch (recv_sock_buf(sb)) {
			case 2:
				if (recv_command(sb) == 0) {
					clear_sock_buf(sb);
					EV_SET(&ev2[0], ev.ident, EVFILT_READ,
					    EV_DISABLE, 0, 0, sb);
					EV_SET(&ev2[1], ev.ident, EVFILT_WRITE,
					    EV_ADD, 0, 0, sb);
					while (kevent(gl_conf->kq, ev2, 2, NULL,
						   0, NULL) < 0)
						if (errno != EINTR)
							break;
					break;
				}
				/* FALLTHROUGH */
			case 1:
				break;
			default:
				destroy_sock_buf(sb);
				EV_SET(&ev, ev.ident, EVFILT_READ, EV_DELETE, 0,
				    0, NULL);
				while (kevent(gl_conf->kq, &ev, 1, NULL, 0,
					   NULL) < 0)
					if (errno != EINTR)
						break;
			}
			break;
		}
		if (write_err_log(ev.ident, VM_PTR(vm_ent)) == 0) {
			EV_SET(&ev, ev.ident, EVFILT_READ, EV_DELETE, 0, 0,
			    NULL);
			while (kevent(gl_conf->kq, &ev, 1, NULL, 0, NULL) < 0)
				if (errno != EINTR)
					break;
		}
		break;
	case EVFILT_TIMER:
		switch (VM_STATE(vm_ent)) {
		case TERMINATE:
			/* delayed boot */
			if (is_event_boot(&ev))
				start_virtual_machine(vm_ent);
			break;
		case LOAD:
		case STOP:
		case REMOVE:
		case RESTART:
			/* loader timout or stop timeout */
			/* force to poweroff */
			ERR("timeout kill vm %s\n", VM_CONF(vm_ent)->name);
			VM_POWEROFF(vm_ent);
			break;
		case RUN:
			/* ignore timer */
			break;
		}
		break;
	case EVFILT_PROC:
		if (waitpid(ev.ident, &status, 0) < 0)
			ERR("wait error (%s)\n", strerror(errno));
		if (vm_ent == NULL || VM_PID(vm_ent) != ev.ident)
			// Maybe plugin set this event
			break;
		switch (VM_STATE(vm_ent)) {
		case LOAD:
			if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
				VM_CLOSE(vm_ent, INFD);
				stop_waiting_fd(vm_ent);
				start_virtual_machine(vm_ent);
			} else {
				ERR("failed loading vm %s (status:%d)\n",
				    VM_CONF(vm_ent)->name, WEXITSTATUS(status));
				stop_virtual_machine(vm_ent);
			}
			break;
		case RESTART:
			stop_virtual_machine(vm_ent);
			VM_STATE(vm_ent) = TERMINATE;
			boot_timer(vm_ent, MAX(VM_CONF(vm_ent)->boot_delay, 3));
			break;
		case RUN:
			if (VM_CONF(vm_ent)->install == false &&
			    WIFEXITED(status) &&
			    (VM_CONF(vm_ent)->boot == ALWAYS ||
				(VM_CONF(vm_ent)->backend == BHYVE &&
				    WEXITSTATUS(status) == 0))) {
				start_virtual_machine(vm_ent);
				break;
			}
			/* FALLTHROUGH */
		case STOP:
			rs = reason_string(status);
			INFO("vm %s is stopped%s\n", VM_CONF(vm_ent)->name,
			     (rs == NULL ? "" : rs));
			free(rs);
			stop_virtual_machine(vm_ent);
			VM_CONF(vm_ent)->install = false;
			break;
		case REMOVE:
			INFO("vm %s is stopped\n", VM_CONF(vm_ent)->name);
			stop_virtual_machine(vm_ent);
			SLIST_REMOVE(&vm_list, vm_ent, vm_entry, next);
			free_vm_entry(vm_ent);
			break;
		case TERMINATE:
			break;
		}
		break;
	case EVFILT_SIGNAL:
		switch (ev.ident) {
		case SIGTERM:
		case SIGINT:
			INFO("%s\n", "stopping daemon");
			goto end;
		case SIGHUP:
			INFO("%s\n", "reload config files");
			reload_virtual_machines();
			goto wait;
		}
		break;
	default:
		ERR("recieved unknown event! (%d)", ev.filter);
		return -1;
	}

	goto wait;
end:
	return 0;
}

int
stop_virtual_machines()
{
	struct kevent ev, ev2[2];
	struct vm_entry *vm_ent;
	int status, count = 0;

	SLIST_FOREACH (vm_ent, &vm_list, next) {
		if (VM_STATE(vm_ent) == LOAD || VM_STATE(vm_ent) == RUN) {
			count++;
			VM_ACPI_POWEROFF(vm_ent);
			shutdown_timer(vm_ent, VM_CONF(vm_ent)->stop_timeout);
		}
	}

	while (count > 0) {
		if (kevent(gl_conf->kq, NULL, 0, &ev, 1, NULL) < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		vm_ent = ev.udata;
		if (ev.filter == EVFILT_PROC) {
			if (waitpid(ev.ident, &status, 0) < 0)
				ERR("wait error (%s)\n", strerror(errno));
			if (vm_ent == NULL || VM_PID(vm_ent) != ev.ident)
				// maybe plugin's child process
				continue;
			INFO("stop vm %s\n", VM_CONF(vm_ent)->name);
			stop_virtual_machine(vm_ent);
			count--;
		} else if (ev.filter == EVFILT_TIMER) {
			/* force to poweroff VM */
			ERR("timeout kill vm %s\n", VM_CONF(vm_ent)->name);
			VM_POWEROFF(vm_ent);
		} else if (ev.filter == EVFILT_WRITE) {
			if (VM_TYPE(vm_ent) == SOCKBUF) {
				destroy_sock_buf((struct sock_buf *)vm_ent);
				EV_SET(&ev2[0], ev.ident, EVFILT_READ,
				    EV_DELETE, 0, 0, NULL);
				EV_SET(&ev2[1], ev.ident, EVFILT_WRITE,
				    EV_DELETE, 0, 0, NULL);
				while (kevent(gl_conf->kq, ev2, 2, NULL, 0,
					   NULL) < 0)
					if (errno != EINTR)
						break;
			}
		} else if (ev.filter == EVFILT_READ) {
			if (VM_TYPE(vm_ent) == SOCKBUF) {
				destroy_sock_buf((struct sock_buf *)vm_ent);
				EV_SET(&ev, ev.ident, EVFILT_READ, EV_DELETE, 0,
				    0, NULL);
				while (kevent(gl_conf->kq, &ev, 1, NULL, 0,
					   NULL) < 0)
					if (errno != EINTR)
						break;
				continue;
			}
			if (write_err_log(ev.ident, VM_PTR(vm_ent)) == 0) {
				EV_SET(&ev, ev.ident, EVFILT_READ, EV_DELETE, 0,
				    0, NULL);
				while (kevent(gl_conf->kq, &ev, 1, NULL, 0,
					   NULL) < 0)
					if (errno != EINTR)
						break;
			}
		}
	}
#if __FreeBSD_version < 1400059
	// waiting for vm memory is actually freed in the kernel.
	sleep(3);
#endif

	return 0;
}

int
parse_opt(int argc, char *argv[])
{
	int ch;

	while ((ch = getopt(argc, argv, "Fc:f:p:m:")) != -1) {
		switch (ch) {
		case 'F':
			gl_conf->foreground = 1;
			break;
		case 'c':
			free(gl_conf->config_file);
			gl_conf->config_file = strdup(optarg);
			break;
		case 'f':
			free(gl_conf->pid_path);
			gl_conf->pid_path = strdup(optarg);
			break;
		case 'p':
			free(gl_conf->plugin_dir);
			gl_conf->plugin_dir = strdup(optarg);
			break;
		case 'm':
			free(gl_conf->unix_domain_socket_mode);
			gl_conf->unix_domain_socket_mode = strdup(optarg);
			break;
		default:
			fprintf(stderr,
			    "usage: %s [-F] [-f pid file] "
			    "[-p plugin directory] \n"
			    "\t[-m unix domain socket permission] \n"
			    "\t[-c config file]\n",
			    argv[0]);
			return -1;
		}
	}

	if (gl_conf->foreground == 0)
		daemon(0, 0);

	return 0;
}

int
strendswith(const char *t, const char *s)
{
	const char *p = &t[strlen(t)];
	const char *q = &s[strlen(s)];

	while (p > t && q > s)
		if (*--p != *--q)
			return (*p) - (*q);

	return (*p) - (*q);
}

int control(int argc, char *argv[]);

int
main(int argc, char *argv[])
{
	FILE *fp;
	sigset_t nmask, omask;

	if (init_gl_conf() < 0) {
		fprintf(stderr, "failed to allocate memory "
			"for global configuration\n");
		return 1;
	}

	if (init_global_vars() < 0) {
		fprintf(stderr,	"failed to allocate memory "
			"for global variables\n");
		free_gl_conf(gl_conf);
		return 1;
	}

	if (strendswith(argv[0], "ctl") == 0)
		return control(argc, argv);

	if (parse_opt(argc, argv) < 0)
		return 1;

	if (gl_conf->foreground)
		LOG_OPEN_PERROR();
	else
		LOG_OPEN();


	sigemptyset(&nmask);
	sigaddset(&nmask, SIGTERM);
	if (gl_conf->foreground)
		sigaddset(&nmask, SIGINT);
	sigaddset(&nmask, SIGHUP);
	sigaddset(&nmask, SIGPIPE);
	sigprocmask(SIG_BLOCK, &nmask, &omask);

	if (procctl(P_PID, getpid(), PROC_SPROTECT, &(int[]) { PPROT_SET }[0]) <
	    0)
		WARN("%s\n", "can not protect from OOM killer");

	if (load_config_file(&vm_conf_list, true) < 0)
		return 1;

	if ((gl_conf->kq = kqueue()) < 0) {
		ERR("%s\n", "can not open kqueue");
		return 1;
	}

	if ((gl_conf->cmd_sock = create_command_server(gl_conf)) < 0) {
		ERR("can not bind %s\n", gl_conf->cmd_sock_path);
		return 1;
	}

	if (gl_conf->foreground == 0 &&
	    (fp = fopen(gl_conf->pid_path, "w")) != NULL) {
		fprintf(fp, "%d\n", getpid());
		fclose(fp);
	}

	INFO("%s\n", "start daemon");

	if (start_virtual_machines() < 0) {
		ERR("%s\n", "failed to start virtual machines");
		return 1;
	}

	event_loop();

	unlink(gl_conf->cmd_sock_path);
	close(gl_conf->cmd_sock);

	stop_virtual_machines();
	free_vm_list();
	close(gl_conf->kq);
	remove_plugins();
	free_id_list();
	free_global_vars();
	free_gl_conf(gl_conf);
	gl_conf = &gl_conf0;
	INFO("%s\n", "quit daemon");
	LOG_CLOSE();
	return 0;
}
