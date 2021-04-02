#include <errno.h>
#include <sys/wait.h>
#include <sys/event.h>
#include <sys/dirent.h>
#include <sys/queue.h>
#include <sys/signal.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>

#include "vars.h"
#include "vm.h"
#include "conf.h"
#include "parser.h"
#include "log.h"

#define MAX(x,y)      ((x) > (y) ? (x) : (y))

struct plugin_entry {
	struct plugin_desc desc;
	void *handle;
	SLIST_ENTRY(plugin_entry) next;
};

struct plugin_data {
	struct plugin_entry *ent;
	void *data;
	SLIST_ENTRY(plugin_data) next;
};

/*
  entry of vm_conf list.
  make sure 'conf' is the first element of the structure.
 */
struct vm_conf_entry {
	struct vm_conf conf;
	SLIST_ENTRY(vm_conf_entry) next;
};

/*
  entry of vm list.
  make sure 'vm' is the first element of the structure.
 */
struct vm_entry {
	struct vm vm;
	struct vm_conf *new_conf;
	SLIST_HEAD(, plugin_data) pl_data;
	SLIST_ENTRY(vm_entry) next;
};


SLIST_HEAD(vm_conf_head, vm_conf_entry) vm_conf_list = SLIST_HEAD_INITIALIZER();
SLIST_HEAD(, vm_entry) vm_list = SLIST_HEAD_INITIALIZER();
SLIST_HEAD(, plugin_entry) plugin_list = SLIST_HEAD_INITIALIZER();

struct global_conf gl_conf = {
	"./conf.d",
	"./plugins"
};

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
		if (ent->d_namlen < 4 ||
		    ent->d_name[0] == '.' ||
		    strcmp(&ent->d_name[ent->d_namlen-3], ".so") != 0 ||
		    (fd = openat(gl_conf.plugin_fd, ent->d_name, O_RDONLY)) < 0 ||
		    ((hdl = fdlopen(fd, RTLD_LAZY)) == NULL))
			goto next;

		desc = dlsym(hdl, "plugin_desc");
		if (desc == NULL ||
		    desc->version != PLUGIN_VERSION ||
		    (desc->initialize && (*(desc->initialize))(&gl_conf) < 0) ||
		    (pl_ent = calloc(1, sizeof(*pl_ent))) == NULL) {
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

	SLIST_FOREACH_SAFE(pl_ent, &plugin_list, next, pln) {
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
	struct vm *vm = &vm_ent->vm;

	SLIST_FOREACH(pl_data, &vm_ent->pl_data, next)
		if (pl_data->ent->desc.on_status_change)
			(*(pl_data->ent->desc.on_status_change))(vm, &pl_data->data);
}

void
free_vm_entry(struct vm_entry *vm_ent)
{
	struct plugin_data *pl_data, *pln;
	struct net_conf *nc, *nnc;

	SLIST_FOREACH_SAFE(pl_data, &vm_ent->pl_data, next, pln)
		free(pl_data);
	STAILQ_FOREACH_SAFE(nc, &vm_ent->vm.taps, next, nnc)
		free_net_conf(nc);
	free(vm_ent->vm.mapfile);
	free_vm_conf(vm_ent->vm.conf);
	free(vm_ent);
}

int
load_config_files(struct vm_conf_head *list)
{
	DIR *d;
	int fd;
	struct dirent *ent;
	struct vm_conf *conf;
	struct vm_conf_entry *conf_ent;

	d = fdopendir(gl_conf.config_fd);
	if (d == NULL) {
		ERR("can not open %s\n", gl_conf.config_dir);
		return -1;
	}

	rewinddir(d);

	while ((ent = readdir(d)) != NULL) {
		if (ent->d_namlen > 0 &&
		    ent->d_name[0] == '.')
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

struct vm_entry*
create_vm_entry(struct vm_conf_entry *conf_ent)
{
	struct vm_entry *vm_ent;
	struct vm *vm;
	struct vm_conf *conf;
	struct plugin_entry *pl_ent;
	struct plugin_data *pl_data;

	vm_ent = calloc(1, sizeof(struct vm_entry));
	if (vm_ent == NULL)
		return NULL;
	vm = &vm_ent->vm;
	conf = &conf_ent->conf;
	vm->conf = conf;
	vm->state = INIT;
	vm->pid = -1;
	vm->infd = -1;
	SLIST_INIT(&vm_ent->pl_data);
	STAILQ_INIT(&vm->taps);
	SLIST_FOREACH(pl_ent, &plugin_list, next) {
		pl_data = calloc(1, sizeof(*pl_data));
		if (pl_data == NULL) {
			free(vm_ent);
			return NULL;
		}
		pl_data->ent = pl_ent;
		SLIST_INSERT_HEAD(&vm_ent->pl_data, pl_data, next);
	}
	SLIST_INSERT_HEAD(&vm_list, vm_ent, next);

	return vm_ent;
}

int
start_virtual_machines()
{
	struct vm_conf *conf;
	struct vm_conf_entry *conf_ent;
	struct vm *vm;
	struct vm_entry *vm_ent;
	struct kevent ev,sigev[3];

	EV_SET(&sigev[0], SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&sigev[1], SIGINT,  EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&sigev[2], SIGHUP,  EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	if (kevent(gl_conf.kq, sigev, 3, NULL, 0, NULL) < 0)
		return -1;

	SLIST_FOREACH(conf_ent, &vm_conf_list, next) {
		vm_ent = create_vm_entry(conf_ent);
		if (vm_ent == NULL)
			return -1;
		conf = &conf_ent->conf;
		if (conf->boot == NO)
			continue;
		if (conf->boot_delay > 0) {
			EV_SET(&ev, 1, EVFILT_TIMER, EV_ADD,
			       NOTE_SECONDS, conf->boot_delay, vm_ent);
			if (kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL) < 0)
				return -1;
			continue;
		}
		vm = &vm_ent->vm;
		if (assign_taps(vm) < 0 ||
		    start_vm(vm) < 0) {
			remove_taps(vm);
			ERR("failed to start vm %s\n", conf->name);
		} else
			call_plugins(vm_ent);
	}

	return 0;
}

struct vm_entry*
lookup_vm(struct vm_conf *conf)
{
	struct vm_entry *vm_ent;

	SLIST_FOREACH(vm_ent, &vm_list, next)
		if (strcmp(vm_ent->vm.conf->name, conf->name) == 0)
			return vm_ent;
	return NULL;
}

int
reload_virtual_machines()
{
	struct vm_conf *conf;
	struct vm_conf_entry *conf_ent, *cen;
	struct vm *vm;
	struct vm_entry *vm_ent;
	struct vm_conf_head new_list = SLIST_HEAD_INITIALIZER();
	struct kevent ev;

	if (load_config_files(&new_list) < 0)
		return -1;

	/* make sure new config is NULL */
	SLIST_FOREACH(vm_ent, &vm_list, next)
		vm_ent->new_conf = NULL;

	SLIST_FOREACH(conf_ent, &new_list, next) {
		conf = &conf_ent->conf;
		vm_ent = lookup_vm(conf);
		if (vm_ent == NULL) {
			vm_ent = create_vm_entry(conf_ent);
			if (vm_ent == NULL)
				return -1;
			if (conf->boot == NO)
				continue;
			INFO("start vm %s\n", conf->name);
			if (conf->boot_delay > 0) {
				EV_SET(&ev, 1, EVFILT_TIMER, EV_ADD,
				       NOTE_SECONDS, conf->boot_delay, vm_ent);
				if (kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL) < 0)
					return -1;
				continue;
			}
			vm = &vm_ent->vm;
			if (assign_taps(vm) < 0 ||
			    start_vm(vm) < 0) {
				remove_taps(vm);
				ERR("failed to start vm %s\n", conf->name);
			} else
				call_plugins(vm_ent);
			vm_ent->new_conf = conf;
			continue;
		}
		vm = &vm_ent->vm;
		switch (conf->boot) {
		case NO:
			if (vm->state == LOAD ||
			    vm->state == RUN) {
				INFO("stop vm %s\n", conf->name);
				kill(vm->pid, SIGTERM);
			} else if (vm->state == RESTART)
				vm->state = STOP;
			break;
		case ALWAYS:
		case YES:
			if (vm->state == INIT ||
			    vm->state == TERMINATE) {
				INFO("start vm %s\n", conf->name);
				if (assign_taps(vm) < 0 ||
				    start_vm(vm) < 0) {
					remove_taps(vm);
					ERR("failed to start vm %s\n", conf->name);
				} else
					call_plugins(vm_ent);
			} else if (vm->state == STOP)
				vm->state = RESTART;
			break;
		case ONESHOT:
			// do nothing
			break;
		case INSTALL:
			if (vm->state == INIT ||
			    vm->state == TERMINATE) {
				INFO("install vm %s\n", conf->name);
				// do_install
			}
			break;
		case REBOOT:
			INFO("reboot vm %s\n", conf->name);
			kill(vm->pid, SIGTERM);
			vm->state = RESTART;
			break;
		}
		vm_ent->new_conf = conf;
	}

	SLIST_FOREACH(vm_ent, &vm_list, next)
		if (vm_ent->new_conf == NULL) {
			vm = &vm_ent->vm;
			switch(vm->state) {
			case LOAD:
			case RUN:
				INFO("stop vm %s\n", vm->conf->name);
				kill(vm->pid, SIGTERM);
				/* GO THROUGH */
			case STOP:
			case REMOVE:
			case RESTART:
				vm->state = REMOVE;
				/* remove vm_conf_entry from the list
				   to keep it when removed. */
				if (SLIST_FIRST(&vm_conf_list))
					SLIST_REMOVE(&vm_conf_list,
						     (struct vm_conf_entry*)vm->conf,
						     vm_conf_entry,
						     next);
				break;
			default:
				if (SLIST_FIRST(&vm_conf_list))
					SLIST_REMOVE(&vm_list, vm_ent, vm_entry, next);
				free_vm_entry(vm_ent);
			}

		} else
			vm_ent->vm.conf = vm_ent->new_conf;

	SLIST_FOREACH_SAFE(conf_ent, &vm_conf_list, next, cen)
		free_vm_conf(&conf_ent->conf);

	vm_conf_list = new_list;

	return 0;
}

int
event_loop()
{
	struct kevent ev;
	struct vm_entry *vm_ent;
	struct vm *vm;
	int status;

wait:
	if (kevent(gl_conf.kq, NULL, 0, &ev, 1, NULL) < 0) {
		if (errno == EINTR) goto wait;
		return -1;
	}

	switch (ev.filter) {
	case EVFILT_TIMER:
		vm_ent = ev.udata;
		vm = &vm_ent->vm;
		ev.flags = EV_DELETE;
		kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL);
		if (vm->state == INIT) {
			if (assign_taps(vm) < 0 ||
			    start_vm(vm) < 0) {
				remove_taps(vm);
				ERR("failed to start vm %s\n", vm->conf->name);
			} else
				call_plugins(vm_ent);
		}
		break;
	case EVFILT_PROC:
		vm_ent = ev.udata;
		vm = &vm_ent->vm;
		if (vm == NULL || vm->pid != ev.ident) {
			// maybe plugin's child process
			ev.flags = EV_DELETE;
			kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL);
			if (waitpid(ev.ident, &status, 0) < 0) {
				ERR("wait error (%s)\n", strerror(errno));
			}
			break;
		}
		ev.flags = EV_DELETE;
		kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL);
		if (waitpid(vm->pid, &status, 0) < 0) {
			ERR("wait error (%s)\n", strerror(errno));
		}
		switch (vm->state) {
		case INIT:
			break;
		case LOAD:
			if (vm->infd != -1) {
				close(vm->infd);
				vm->infd = -1;
			}
			if (WIFEXITED(status) &&
			    WEXITSTATUS(status) == 0) {
				exec_bhyve(vm);
				vm->state = RUN;
				call_plugins(vm_ent);
			} else {
				ERR("failed loading vm %s\n", vm->conf->name);
				cleanup_vm(vm);
				call_plugins(vm_ent);
			}
			break;
		case RESTART:
			cleanup_vm(vm);
			call_plugins(vm_ent);

			EV_SET(&ev, 1, EVFILT_TIMER, EV_ADD,
			       NOTE_SECONDS, MAX(vm->conf->boot_delay,3),
			       vm_ent);
			kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL);
			vm->state = INIT;
			break;
		case RUN:
			if (WIFEXITED(status) &&
			    (vm->conf->boot == ALWAYS ||
			     WEXITSTATUS(status) == 0)) {
				if (start_vm(vm) < 0)
					ERR("failed to start vm %s\n", vm->conf->name);
				else
					call_plugins(vm_ent);
				break;
			}
			/* RUN THROUGH */
		case STOP:
			cleanup_vm(vm);
			call_plugins(vm_ent);
			break;
		case REMOVE:
			cleanup_vm(vm);
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
			INFO("%s\n", "recieved SIGTERM quitting.");
			return 0;
		case SIGHUP:
			INFO("%s\n", "reload config files");
			reload_virtual_machines();
			goto wait;
		}
		break;
	default:
		// unknown event
		return -1;
	}

	goto wait;

	return 0;
}

int
stop_virtual_machines()
{
	struct kevent ev;
	struct vm *vm;
	struct vm_entry *vm_ent;
	int status, count = 0;

	SLIST_FOREACH(vm_ent, &vm_list, next) {
		vm = &vm_ent->vm;
		if (vm->state == RUN || vm->state == LOAD) {
			count++;
			kill(vm->pid, SIGTERM);
		}
	}

	while (count > 0) {
		if (kevent(gl_conf.kq, NULL, 0, &ev, 1, NULL) < 0) {
			if (errno == EINTR) continue;
			return -1;
		}
		if (ev.filter == EVFILT_PROC) {
			vm_ent = ev.udata;
			vm = &vm_ent->vm;
			if (vm == NULL || vm->pid != ev.ident) {
				// maybe plugin's child process
				ev.flags = EV_DELETE;
				kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL);
				if (waitpid(ev.ident, &status, 0) < 0)
					ERR("wait error (%s)\n",
					    strerror(errno));
				continue;
			}
			ev.flags = EV_DELETE;
			kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL);
			if (waitpid(vm->pid, &status, 0) < 0)
				ERR("wait error (%s)\n", strerror(errno));
			cleanup_vm(vm);
			call_plugins(vm_ent);
			count--;
		}
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	int fd;
	sigset_t nmask, omask;

	LOG_OPEN_PERROR();

	sigemptyset(&nmask);
	sigaddset(&nmask, SIGTERM);
	sigaddset(&nmask, SIGINT);
	sigaddset(&nmask, SIGHUP);
	sigprocmask(SIG_BLOCK, &nmask, &omask);

	INFO("%s\n", "start");

	fd = kqueue();
	if (fd < 0) {
		ERR("%s\n", "can not open kqueue");
		return 1;
	}
	gl_conf.kq = fd;

	fd = open(gl_conf.config_dir, O_DIRECTORY|O_RDONLY);
	if (fd < 0) {
		ERR("can not open %s\n", gl_conf.config_dir);
		return 1;
	}
	gl_conf.config_fd = fd;

	fd = open(gl_conf.plugin_dir, O_DIRECTORY|O_RDONLY);
	if (fd < 0) {
		ERR("can not open %s\n", gl_conf.plugin_dir);
		return 1;
	}
	gl_conf.plugin_fd = fd;

	if (load_plugins() < 0 ||
	    load_config_files(&vm_conf_list) < 0 ||
	    start_virtual_machines())
		return 1;

	event_loop();

	stop_virtual_machines();
	close(gl_conf.kq);
	close(gl_conf.plugin_fd);
	close(gl_conf.config_fd);
	remove_plugins();
	INFO("%s\n", "quit");
	LOG_CLOSE();
	return 0;
}
