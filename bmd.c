#include <sys/param.h>
#include <sys/dirent.h>
#include <sys/event.h>
#include <sys/nv.h>
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
SLIST_HEAD(vm_conf_head, vm_conf_entry) vm_conf_list = SLIST_HEAD_INITIALIZER();
/*
  List of virtual machines.
 */
SLIST_HEAD(, vm_entry) vm_list = SLIST_HEAD_INITIALIZER();
SLIST_HEAD(, plugin_entry) plugin_list = SLIST_HEAD_INITIALIZER();

/*
  Global configuration.
 */
struct global_conf gl_conf = { LOCALBASE "/etc/bmd.d", LOCALBASE "/libexec/bmd",
	LOCALBASE "/var/cache/bmd",
	"/var/run/bmd.pid", "/var/run/bmd.sock", NULL, -1, -1, -1, 0, -1 };

extern struct vm_methods method_list[];

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
	while (kevent(gl_conf.kq, ev, i, NULL, 0, NULL) < 0)
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
	while (kevent(gl_conf.kq, ev, i, NULL, 0, NULL) < 0)
		if (errno != EINTR) {
			ERR("failed to delete waiting fd (%s)\n",
			    strerror(errno));
			return -1;
		}

	VM_CLOSE(vm_ent, OUTFD);
	VM_CLOSE(vm_ent, ERRFD);

	return 0;
}

int
set_timer(struct vm_entry *vm_ent, int second)
{
	static int id = 1;
	struct kevent ev;

	EV_SET(&ev, id++, EVFILT_TIMER, EV_ADD | EV_ONESHOT, NOTE_SECONDS,
	    second, vm_ent);
	while (kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL) < 0)
		if (errno != EINTR) {
			ERR("failed to set timer (%s)\n", strerror(errno));
			return -1;
		}
	return 0;
}

int
wait_for_process(struct vm_entry *vm_ent)
{
	struct kevent ev;

	EV_SET(&ev, VM_PID(vm_ent), EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT,
	    0, vm_ent);
	while (kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL) < 0)
		if (errno != EINTR) {
			ERR("failed to wait process (%s)\n", strerror(errno));
			return -1;
		}
	return 0;
}

int
load_plugins()
{
	DIR *d;
	void *hdl;
	int fd;
	struct dirent *ent;
	struct plugin_desc *desc;
	struct plugin_entry *pl_ent;

	d = fdopendir(gl_conf.plugin_fd);
	if (d == NULL) {
		ERR("can not open %s\n", gl_conf.plugin_dir);
		return -1;
	}

	while ((ent = readdir(d)) != NULL) {
		fd = -1;
		if (ent->d_namlen < 4 || ent->d_name[0] == '.' ||
		    strcmp(&ent->d_name[ent->d_namlen - 3], ".so") != 0 ||
		    (fd = openat(gl_conf.plugin_fd, ent->d_name, O_RDONLY)) <
			0 ||
		    ((hdl = fdlopen(fd, RTLD_NOW)) == NULL))
			goto next;

		desc = dlsym(hdl, "plugin_desc");
		if (desc == NULL || desc->version != PLUGIN_VERSION ||
		    (pl_ent = calloc(1, sizeof(*pl_ent))) == NULL ||
		    (desc->initialize && (*(desc->initialize))(&gl_conf) < 0)) {
			dlclose(hdl);
			goto next;
		}
		memcpy(&pl_ent->desc, desc, sizeof(PLUGIN_DESC));
		pl_ent->handle = hdl;
		SLIST_INSERT_HEAD(&plugin_list, pl_ent, next);
	next:
		close(fd);
	}

	fdclosedir(d);

	return 0;
}

int
remove_plugins()
{
	struct plugin_entry *pl_ent, *pln;

	SLIST_FOREACH_SAFE (pl_ent, &plugin_list, next, pln) {
		if (pl_ent->desc.finalize)
			(*pl_ent->desc.finalize)(&gl_conf);
		dlclose(pl_ent->handle);
		free(pl_ent);
	}

	return 0;
}

void
call_plugins(struct vm_entry *vm_ent)
{
	struct plugin_data *pl_data;

	SLIST_FOREACH (pl_data, &VM_PLUGIN_DATA(vm_ent), next)
		if (pl_data->ent->desc.on_status_change)
			(*(pl_data->ent->desc.on_status_change))(VM_PTR(vm_ent),
			    &pl_data->data);
}

void
free_vm_entry(struct vm_entry *vm_ent)
{
	struct plugin_data *pl_data, *pln;
	struct net_conf *nc, *nnc;

	SLIST_FOREACH_SAFE (pl_data, &VM_PLUGIN_DATA(vm_ent), next, pln)
		free(pl_data);
	STAILQ_FOREACH_SAFE (nc, &VM_TAPS(vm_ent), next, nnc)
		free_net_conf(nc);
	free(VM_MAPFILE(vm_ent));
	free(VM_VARSFILE(vm_ent));
	free_vm_conf(VM_CONF(vm_ent));
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

int
load_config_files(struct vm_conf_head *list)
{
	DIR *d;
	int fd;
	struct dirent *ent;
	struct vm_conf *conf;
	struct vm_conf_entry *conf_ent;

	if (gl_conf.config_fd != -1)
		close(gl_conf.config_fd);

	if ((gl_conf.config_fd = open(gl_conf.config_dir,
		 O_DIRECTORY | O_RDONLY)) < 0) {
		ERR("can not open %s\n", gl_conf.config_dir);
		return -1;
	}

	d = fdopendir(gl_conf.config_fd);
	if (d == NULL) {
		ERR("can not open %s\n", gl_conf.config_dir);
		return -1;
	}

	rewinddir(d);

	while ((ent = readdir(d)) != NULL) {
		if (ent->d_namlen > 0 && ent->d_name[0] == '.')
			continue;
		if ((fd = openat(gl_conf.config_fd, ent->d_name, O_RDONLY)) < 0)
			continue;
		conf = parse_file(fd, ent->d_name);
		close(fd);
		if (conf == NULL)
			continue;
		conf_ent = realloc(conf, sizeof(*conf_ent));
		if (conf_ent == NULL) {
			free_vm_conf(conf);
			continue;
		}
		SLIST_INSERT_HEAD(list, conf_ent, next);
	}

	fdclosedir(d);

	return 0;
}

void
free_config_files()
{
	struct vm_conf_entry *conf_ent, *cen;

	SLIST_FOREACH_SAFE (conf_ent, &vm_conf_list, next, cen)
		free_vm_conf(&conf_ent->conf);
	SLIST_INIT(&vm_conf_list);
}

struct vm_entry *
create_vm_entry(struct vm_conf_entry *conf_ent)
{
	struct vm_entry *vm_ent;
	struct plugin_entry *pl_ent;
	struct plugin_data *pld, *pln;

	vm_ent = calloc(1, sizeof(struct vm_entry));
	if (vm_ent == NULL)
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
	SLIST_INIT(&VM_PLUGIN_DATA(vm_ent));
	STAILQ_INIT(&VM_TAPS(vm_ent));
	SLIST_FOREACH (pl_ent, &plugin_list, next) {
		if ((pld = calloc(1, sizeof(*pld))) == NULL)
			goto err;
		pld->ent = pl_ent;
		SLIST_INSERT_HEAD(&VM_PLUGIN_DATA(vm_ent), pld, next);
	}
	SLIST_INSERT_HEAD(&vm_list, vm_ent, next);

	return vm_ent;
err:
	SLIST_FOREACH_SAFE (pld, &VM_PLUGIN_DATA(vm_ent), next, pln)
		free(pld);
	free(vm_ent);
	return NULL;
}

int
start_virtual_machine(struct vm_entry *vm_ent)
{
	struct vm_conf *conf = VM_CONF(vm_ent);
	char *name = conf->name;

	VM_METHOD(vm_ent) = &method_list[conf->backend];

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
	if (VM_STATE(vm_ent) == LOAD &&
	    set_timer(vm_ent, conf->loader_timeout) < 0) {
		ERR("failed to set timer for vm %s\n", name);
		return -1;
	}

	if (VM_LOGFD(vm_ent) == -1)
		VM_LOGFD(vm_ent) = open(conf->err_logfile,
		    O_WRONLY | O_APPEND | O_CREAT, 0644);

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

	while (kevent(gl_conf.kq, sigev, 3, NULL, 0, NULL) < 0)
		if (errno != EINTR)
			return -1;

	SLIST_FOREACH (conf_ent, &vm_conf_list, next) {
		vm_ent = create_vm_entry(conf_ent);
		if (vm_ent == NULL)
			return -1;
		conf = &conf_ent->conf;
		if (conf->boot == NO)
			continue;
		if (conf->boot_delay > 0) {
			if (set_timer(vm_ent, conf->boot_delay) < 0)
				ERR("failed to set boot delay timer for vm %s\n",
				    conf->name);
			continue;
		}
		start_virtual_machine(vm_ent);
	}

	return 0;
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
	struct vm_entry *vm_ent;
	struct vm_conf_head new_list = SLIST_HEAD_INITIALIZER();

	if (load_config_files(&new_list) < 0)
		return -1;

	/* make sure new_conf is NULL */
	SLIST_FOREACH (vm_ent, &vm_list, next)
		VM_NEWCONF(vm_ent) = NULL;

	SLIST_FOREACH (conf_ent, &new_list, next) {
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
				if (set_timer(vm_ent, conf->boot_delay) < 0)
					ERR("failed to set timer for %s\n",
					    conf->name);
				continue;
			}
			start_virtual_machine(vm_ent);
			continue;
		} else if (VM_LOGFD(vm_ent) != -1 &&
			VM_CONF(vm_ent)->err_logfile != NULL) {
			VM_CLOSE(vm_ent, LOGFD);
			VM_LOGFD(vm_ent) = open(VM_CONF(vm_ent)->err_logfile,
			    O_WRONLY | O_APPEND | O_CREAT, 0644);
		}
		VM_NEWCONF(vm_ent) = conf;
		if (conf->reboot_on_change &&
		    compare_vm_conf(conf, VM_CONF(vm_ent)) != 0) {
			if (VM_STATE(vm_ent) == LOAD ||
			    VM_STATE(vm_ent) == RUN) {
				INFO("reboot vm %s\n", conf->name);
				VM_ACPI_POWEROFF(vm_ent);
				set_timer(vm_ent, conf->stop_timeout);
				VM_STATE(vm_ent) = RESTART;
			} else if (VM_STATE(vm_ent) == STOP)
				VM_STATE(vm_ent) = RESTART;
			continue;
		}
		if (VM_NEWCONF(vm_ent)->boot == VM_CONF(vm_ent)->boot)
			continue;
		switch (conf->boot) {
		case NO:
			if (VM_STATE(vm_ent) == LOAD ||
			    VM_STATE(vm_ent) == RUN) {
				INFO("stop vm %s\n", conf->name);
				VM_ACPI_POWEROFF(vm_ent);
				set_timer(vm_ent, conf->stop_timeout);
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

	SLIST_FOREACH (vm_ent, &vm_list, next)
		if (VM_NEWCONF(vm_ent) == NULL) {
			conf = VM_CONF(vm_ent);
			switch (VM_STATE(vm_ent)) {
			case LOAD:
			case RUN:
				INFO("stop vm %s\n", conf->name);
				VM_ACPI_POWEROFF(vm_ent);
				set_timer(vm_ent, conf->stop_timeout);
				/* FALLTHROUGH */
			case STOP:
			case REMOVE:
			case RESTART:
				VM_STATE(vm_ent) = REMOVE;
				/* remove vm_conf_entry from the list
				   to keep it until actually freed. */
				if (SLIST_FIRST(&vm_conf_list))
					SLIST_REMOVE(&vm_conf_list,
					    (struct vm_conf_entry *)conf,
					    vm_conf_entry, next);
				break;
			default:
				if (SLIST_FIRST(&vm_list))
					SLIST_REMOVE(&vm_list, vm_ent, vm_entry,
					    next);
				if (SLIST_FIRST(&vm_conf_list))
					SLIST_REMOVE(&vm_conf_list,
					    (struct vm_conf_entry *)conf,
					    vm_conf_entry, next);
				free_vm_entry(vm_ent);
			}

		} else {
			VM_CONF(vm_ent) = VM_NEWCONF(vm_ent);
			VM_NEWCONF(vm_ent) = NULL;
		}

	SLIST_FOREACH_SAFE (conf_ent, &vm_conf_list, next, cen)
		free_vm_conf(&conf_ent->conf);

	vm_conf_list = new_list;

	return 0;
}

#define BUFSIZE (4 * 1024)

int
event_loop()
{
	struct kevent ev, ev2[2];
	struct vm_entry *vm_ent;
	int n, status;
	struct sock_buf *sb;

	EV_SET(&ev, gl_conf.cmd_sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
	while (kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL) < 0)
		if (errno != EINTR)
			return -1;

wait:
	while (kevent(gl_conf.kq, NULL, 0, &ev, 1, NULL) < 0)
		if (errno != EINTR) {
			ERR("kevent failure (%s)\n", strerror(errno));
			return -1;
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
				while (kevent(gl_conf.kq, ev2, 2, NULL, 0,
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
				while (kevent(gl_conf.kq, ev2, 2, NULL, 0,
					   NULL) < 0)
					if (errno != EINTR)
						break;
				break;
			}
		}
		break;
	case EVFILT_READ:
		if (ev.ident == gl_conf.cmd_sock) {
			if ((n = accept_command_socket(ev.ident)) < 0)
				break;
			sb = create_sock_buf(n);
			EV_SET(&ev, n, EVFILT_READ, EV_ADD, 0, 0, sb);
			while (kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL) < 0)
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
					while (kevent(gl_conf.kq, ev2, 2, NULL,
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
				while (kevent(gl_conf.kq, &ev, 1, NULL, 0,
					   NULL) < 0)
					if (errno != EINTR)
						break;
			}
			break;
		}
		if (write_err_log(ev.ident, VM_PTR(vm_ent)) == 0) {
			EV_SET(&ev, ev.ident, EVFILT_READ, EV_DELETE, 0, 0,
			    NULL);
			while (kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL) < 0)
				if (errno != EINTR)
					break;
		}
		break;
	case EVFILT_TIMER:
		if (VM_STATE(vm_ent) == TERMINATE) {
			/* delayed boot */
			start_virtual_machine(vm_ent);
		} else if (VM_STATE(vm_ent) == LOAD ||
		    VM_STATE(vm_ent) == STOP || VM_STATE(vm_ent) == REMOVE ||
		    VM_STATE(vm_ent) == RESTART) {
			/* loader timout or stop timeout */
			/* force to poweroff */
			ERR("timeout kill vm %s\n", VM_CONF(vm_ent)->name);
			VM_POWEROFF(vm_ent);
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
			VM_CLOSE(vm_ent, INFD);
			VM_CLOSE(vm_ent, OUTFD);
			VM_CLOSE(vm_ent, ERRFD);
			if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
				start_virtual_machine(vm_ent);
			else {
				ERR("failed loading vm %s (status:%d)\n",
				    VM_CONF(vm_ent)->name, WEXITSTATUS(status));
				stop_waiting_fd(vm_ent);
				VM_CLEANUP(vm_ent);
				call_plugins(vm_ent);
			}
			break;
		case RESTART:
			stop_waiting_fd(vm_ent);
			VM_CLEANUP(vm_ent);
			call_plugins(vm_ent);

			VM_STATE(vm_ent) = TERMINATE;
			set_timer(vm_ent, MAX(VM_CONF(vm_ent)->boot_delay, 3));
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
			INFO("stop vm %s\n", VM_CONF(vm_ent)->name);
			stop_waiting_fd(vm_ent);
			VM_CLEANUP(vm_ent);
			call_plugins(vm_ent);
			VM_CONF(vm_ent)->install = false;
			break;
		case REMOVE:
			stop_waiting_fd(vm_ent);
			VM_CLEANUP(vm_ent);
			call_plugins(vm_ent);
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
			set_timer(vm_ent, VM_CONF(vm_ent)->stop_timeout);
		}
	}

	while (count > 0) {
		if (kevent(gl_conf.kq, NULL, 0, &ev, 1, NULL) < 0) {
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
			stop_waiting_fd(vm_ent);
			VM_CLEANUP(vm_ent);
			call_plugins(vm_ent);
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
				while (kevent(gl_conf.kq, ev2, 2, NULL, 0,
					   NULL) < 0)
					if (errno != EINTR)
						break;
			}
		} else if (ev.filter == EVFILT_READ) {
			if (VM_TYPE(vm_ent) == SOCKBUF) {
				destroy_sock_buf((struct sock_buf *)vm_ent);
				EV_SET(&ev, ev.ident, EVFILT_READ, EV_DELETE, 0,
				    0, NULL);
				while (kevent(gl_conf.kq, &ev, 1, NULL, 0,
					   NULL) < 0)
					if (errno != EINTR)
						break;
				continue;
			}
			if (write_err_log(ev.ident, VM_PTR(vm_ent)) == 0) {
				EV_SET(&ev, ev.ident, EVFILT_READ, EV_DELETE, 0,
				    0, NULL);
				while (kevent(gl_conf.kq, &ev, 1, NULL, 0,
					   NULL) < 0)
					if (errno != EINTR)
						break;
			}
		}
	}
	// waiting for vm memory is actually freed in the kernel.
	sleep(3);

	return 0;
}

int
parse_opt(int argc, char *argv[])
{
	int ch;

	while ((ch = getopt(argc, argv, "Ff:p:m:")) != -1) {
		switch (ch) {
		case 'F':
			gl_conf.foreground = 1;
			break;
		case 'c':
			gl_conf.config_dir = strdup(optarg);
			break;
		case 'f':
			gl_conf.pid_path = strdup(optarg);
			break;
		case 'p':
			gl_conf.plugin_dir = strdup(optarg);
			break;
		case 'm':
			gl_conf.unix_domain_socket_mode = strdup(optarg);
			break;
		default:
			fprintf(stderr,
			    "usage: %s [-F] [-f pid file] "
			    "[-p plugin directory] \n"
			    "\t[-m unix domain socket permission] \n"
			    "\t[-c vm config directory]\n",
			    argv[0]);
			return -1;
		}
	}

	if (gl_conf.foreground == 0)
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

	if (strendswith(argv[0], "ctl") == 0)
		return control(argc, argv);

	if (parse_opt(argc, argv) < 0)
		return 1;

	if (gl_conf.foreground)
		LOG_OPEN_PERROR();
	else
		LOG_OPEN();

	sigemptyset(&nmask);
	sigaddset(&nmask, SIGTERM);
	if (gl_conf.foreground)
		sigaddset(&nmask, SIGINT);
	sigaddset(&nmask, SIGHUP);
	sigaddset(&nmask, SIGPIPE);
	sigprocmask(SIG_BLOCK, &nmask, &omask);

	if (procctl(P_PID, getpid(), PROC_SPROTECT, &(int[]) { PPROT_SET }[0]) <
	    0)
		WARN("%s\n", "can not protect from OOM killer");

	if ((gl_conf.kq = kqueue()) < 0) {
		ERR("%s\n", "can not open kqueue");
		return 1;
	}

	if ((gl_conf.config_fd = open(gl_conf.config_dir,
		 O_DIRECTORY | O_RDONLY)) < 0) {
		ERR("can not open %s\n", gl_conf.config_dir);
		return 1;
	}

	if ((gl_conf.plugin_fd = open(gl_conf.plugin_dir,
		 O_DIRECTORY | O_RDONLY)) < 0) {
		ERR("can not open %s\n", gl_conf.plugin_dir);
		return 1;
	}

	if ((gl_conf.cmd_sock = create_command_server(&gl_conf)) < 0) {
		ERR("can not bind %s\n", gl_conf.cmd_sock_path);
		return 1;
	}

	if (gl_conf.foreground == 0 &&
	    (fp = fopen(gl_conf.pid_path, "w")) != NULL) {
		fprintf(fp, "%d\n", getpid());
		fclose(fp);
	}

	INFO("%s\n", "start daemon");

	if (load_plugins() < 0 || load_config_files(&vm_conf_list) < 0 ||
	    start_virtual_machines())
		return 1;

	event_loop();

	unlink(gl_conf.cmd_sock_path);
	close(gl_conf.cmd_sock);

	stop_virtual_machines();
	free_vm_list();
	close(gl_conf.kq);
	close(gl_conf.plugin_fd);
	close(gl_conf.config_fd);
	remove_plugins();
	INFO("%s\n", "quit daemon");
	LOG_CLOSE();
	return 0;
}
