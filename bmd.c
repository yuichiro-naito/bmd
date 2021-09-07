#include <sys/dirent.h>
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <sys/nv.h>

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "conf.h"
#include "log.h"
#include "parser.h"
#include "vars.h"
#include "vm.h"
#include "command.h"

#define MAX(x, y) ((x) > (y) ? (x) : (y))

/*
  Entry of plugins.
  The individual entries refer to the installed plugin.
 */
struct plugin_entry {
	struct plugin_desc desc;
	void *handle;
	SLIST_ENTRY(plugin_entry) next;
};

/*
  Plugin data is for each plugin and virtual machine.
 */
struct plugin_data {
	struct plugin_entry *ent;
	void *data;
	SLIST_ENTRY(plugin_data) next;
};

/*
  Entry of vm_conf list.
  The individual entories hold the VM configuration.
  Make sure 'conf' is the first element of the structure.
 */
struct vm_conf_entry {
	struct vm_conf conf;
	SLIST_ENTRY(vm_conf_entry) next;
};

/*
  Entry of vm list.
  The individual entries indicate the virtual machine process.
  Make sure 'vm' is the first element of the structure.
 */
struct vm_entry {
	struct vm vm;
	struct vm_conf *new_conf;
	SLIST_HEAD(, plugin_data) pl_data;
	SLIST_ENTRY(vm_entry) next;
};

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
struct global_conf gl_conf = { LOCALBASE "/etc/bmd.d",
	LOCALBASE "/libexec/bmd", "/var/run/bmd.pid",
	"/var/run/bmd.sock",	NULL };

int
wait_for_reading(struct vm_entry *vm_ent)
{
	int i = 0;
	struct kevent ev[2];

	if (vm_ent->vm.outfd != -1)
		EV_SET(&ev[i++], vm_ent->vm.outfd, EVFILT_READ, EV_ADD, 0, 0,
		    vm_ent);
	if (vm_ent->vm.errfd != -1)
		EV_SET(&ev[i++], vm_ent->vm.errfd, EVFILT_READ, EV_ADD, 0, 0,
		    vm_ent);
retry:
	if (kevent(gl_conf.kq, ev, i, NULL, 0, NULL) < 0) {
		if (errno == EINTR)
			goto retry;
		ERR("failed to wait reading fd (%s)\n", strerror(errno));
		return -1;
	}

	return 0;
}

int
stop_waiting_fd(struct vm_entry *vm_ent)
{
	int i = 0;
	struct kevent ev[2];

	if (vm_ent->vm.outfd != -1)
		EV_SET(&ev[i++], vm_ent->vm.outfd, EVFILT_READ, EV_DELETE, 0, 0,
		    vm_ent);
	if (vm_ent->vm.errfd != -1)
		EV_SET(&ev[i++], vm_ent->vm.errfd, EVFILT_READ, EV_DELETE, 0, 0,
		    vm_ent);
retry:
	if (kevent(gl_conf.kq, ev, i, NULL, 0, NULL) < 0) {
		if (errno == EINTR)
			goto retry;
		ERR("failed to delete waiting fd (%s)\n", strerror(errno));
		return -1;
	}

	close(vm_ent->vm.outfd);
	close(vm_ent->vm.errfd);
	vm_ent->vm.outfd = -1;
	vm_ent->vm.errfd = -1;

	return 0;
}

int
set_timer(struct vm_entry *vm_ent, int second)
{
	static int id = 1;
	struct kevent ev;

	EV_SET(&ev, id++, EVFILT_TIMER, EV_ADD | EV_ONESHOT, NOTE_SECONDS,
	    second, vm_ent);
retry:
	if (kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL) < 0) {
		if (errno == EINTR)
			goto retry;
		ERR("failed to set timer (%s)\n", strerror(errno));
		return -1;
	}
	return 0;
}

int
wait_for_process(struct vm_entry *vm_ent)
{
	struct kevent ev;

	EV_SET(&ev, vm_ent->vm.pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT,
	    0, vm_ent);
retry:
	if (kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL) < 0) {
		if (errno == EINTR)
			goto retry;
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
		    ((hdl = fdlopen(fd, RTLD_LAZY)) == NULL))
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
	struct vm *vm = &vm_ent->vm;

	SLIST_FOREACH (pl_data, &vm_ent->pl_data, next)
		if (pl_data->ent->desc.on_status_change)
			(*(pl_data->ent->desc.on_status_change))(vm,
			    &pl_data->data);
}

void
free_vm_entry(struct vm_entry *vm_ent)
{
	struct plugin_data *pl_data, *pln;
	struct net_conf *nc, *nnc;

	SLIST_FOREACH_SAFE (pl_data, &vm_ent->pl_data, next, pln)
		free(pl_data);
	STAILQ_FOREACH_SAFE (nc, &vm_ent->vm.taps, next, nnc)
		free_net_conf(nc);
	free(vm_ent->vm.mapfile);
	free_vm_conf(vm_ent->vm.conf);
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

struct vm_entry *
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
	vm->outfd = -1;
	vm->errfd = -1;
	vm->logfd = -1;
	SLIST_INIT(&vm_ent->pl_data);
	STAILQ_INIT(&vm->taps);
	SLIST_FOREACH (pl_ent, &plugin_list, next) {
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
start_virtual_machine(struct vm_entry *vm_ent)
{
	struct vm *vm = &vm_ent->vm;
	char *name = vm->conf->name;
	int (*vm_func)(struct vm *);

	if (vm->state == LOAD)
		vm_func = &exec_bhyve;
	else {
		INFO("start vm %s\n", name);
		vm_func = &start_vm;
	}

	if ((*vm_func)(vm) < 0) {
		ERR("failed to start vm %s\n", name);
		return -1;
	}

	if (wait_for_process(vm_ent) < 0 || wait_for_reading(vm_ent) < 0) {
		ERR("failed to set kevent for vm %s\n", name);
		/*
		 * Force to kill bhyve.
		 * If this error happens, we can't manage bhyve process at all.
		 */
		kill(vm->pid, SIGKILL);
		waitpid(vm->pid, NULL, 0);
		cleanup_vm(vm);
		return -1;
	}

	call_plugins(vm_ent);
	if (vm->state == LOAD &&
	    set_timer(vm_ent, vm->conf->loader_timeout) < 0) {
		ERR("failed to set timer for vm %s\n", name);
		return -1;
	}

	vm->logfd = open(vm->conf->err_logfile, O_WRONLY | O_APPEND | O_CREAT,
	    0644);

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
retry:
	if (kevent(gl_conf.kq, sigev, 3, NULL, 0, NULL) < 0) {
		if (errno == EINTR)
			goto retry;
		return -1;
	}

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
		if (strcmp(vm_ent->vm.conf->name, name) == 0)
			return vm_ent;
	return NULL;
}

struct vm_entry *
lookup_vm(struct vm_conf *conf)
{
	struct vm_entry *vm_ent;

	SLIST_FOREACH (vm_ent, &vm_list, next)
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

	if (load_config_files(&new_list) < 0)
		return -1;

	/* make sure new_conf is NULL */
	SLIST_FOREACH (vm_ent, &vm_list, next)
		vm_ent->new_conf = NULL;

	SLIST_FOREACH (conf_ent, &new_list, next) {
		conf = &conf_ent->conf;
		vm_ent = lookup_vm(conf);
		if (vm_ent == NULL) {
			vm_ent = create_vm_entry(conf_ent);
			if (vm_ent == NULL)
				return -1;
			vm_ent->new_conf = conf;
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
		} else if (vm_ent->vm.logfd != -1 &&
		    vm_ent->vm.conf->err_logfile != NULL) {
			close(vm_ent->vm.logfd);
			vm_ent->vm.logfd = open(vm_ent->vm.conf->err_logfile,
			    O_WRONLY | O_APPEND | O_CREAT, 0644);
		}
		vm = &vm_ent->vm;
		switch (conf->boot) {
		case NO:
			if (vm->state == LOAD || vm->state == RUN) {
				INFO("stop vm %s\n", conf->name);
				kill(vm->pid, SIGTERM);
				set_timer(vm_ent, conf->stop_timeout);
				vm->state = STOP;
			} else if (vm->state == RESTART)
				vm->state = STOP;
			break;
		case ALWAYS:
		case YES:
			if (vm->state == INIT || vm->state == TERMINATE) {
				vm->conf = conf;
				start_virtual_machine(vm_ent);
			} else if (vm->state == STOP)
				vm->state = RESTART;
			break;
		case ONESHOT:
			// do nothing
			break;
		case INSTALL:
			if (vm->state == INIT || vm->state == TERMINATE) {
				INFO("install vm %s\n", conf->name);
				vm->conf = conf;
				start_virtual_machine(vm_ent);
			}
			break;
		case REBOOT:
			if (vm->state == INIT || vm->state == TERMINATE) {
				vm->conf = conf;
				start_virtual_machine(vm_ent);
			} else if ((vm->state == LOAD || vm->state == RUN) &&
			    compare_vm_conf(conf, vm->conf) != 0) {
				INFO("reboot vm %s\n", conf->name);
				kill(vm->pid, SIGTERM);
				set_timer(vm_ent, conf->stop_timeout);
				vm->state = RESTART;
			} else if (vm->state == STOP)
				vm->state = RESTART;
			break;
		}
		vm_ent->new_conf = conf;
	}

	SLIST_FOREACH (vm_ent, &vm_list, next)
		if (vm_ent->new_conf == NULL) {
			vm = &vm_ent->vm;
			switch (vm->state) {
			case LOAD:
			case RUN:
				INFO("stop vm %s\n", vm->conf->name);
				kill(vm->pid, SIGTERM);
				set_timer(vm_ent, conf->stop_timeout);
				/* GO THROUGH */
			case STOP:
			case REMOVE:
			case RESTART:
				vm->state = REMOVE;
				/* remove vm_conf_entry from the list
				   to keep it until actually freed. */
				if (SLIST_FIRST(&vm_conf_list))
					SLIST_REMOVE(&vm_conf_list,
					    (struct vm_conf_entry *)vm->conf,
					    vm_conf_entry, next);
				break;
			default:
				if (SLIST_FIRST(&vm_list))
					SLIST_REMOVE(&vm_list, vm_ent, vm_entry,
					    next);
				if (SLIST_FIRST(&vm_conf_list))
					SLIST_REMOVE(&vm_conf_list,
					    (struct vm_conf_entry *)vm->conf,
					    vm_conf_entry, next);
				free_vm_entry(vm_ent);
			}

		} else {
			vm_ent->vm.conf = vm_ent->new_conf;
			vm_ent->new_conf = NULL;
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
	struct kevent ev;
	struct vm_entry *vm_ent;
	struct vm *vm;
	int rc, n, size, status;
	char *buf = malloc(BUFSIZE);

	if (buf == NULL) {
		ERR("can not allocate memory %d bytes", BUFSIZE);
		return -1;
	}

	EV_SET(&ev, gl_conf.cmd_sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
retry:
	if (kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL) < 0) {
		if (errno == EINTR)
			goto retry;
		return -1;
	}

wait:
	if (kevent(gl_conf.kq, NULL, 0, &ev, 1, NULL) < 0) {
		if (errno == EINTR)
			goto wait;
		ERR("kevent failure (%s)\n", strerror(errno));
		free(buf);
		return -1;
	}

	vm_ent = ev.udata;
	vm = &vm_ent->vm;
	switch (ev.filter) {
	case EVFILT_READ:
		if (ev.ident == gl_conf.cmd_sock) {
			if ((n = accept_command_socket(ev.ident)) < 0)
				break;
			recv_command(n);
			close(n);
			break;
		}
		while ((size = read(ev.ident, buf, BUFSIZE)) < 0)
			if (errno != EINTR && errno != EAGAIN)
				break;
		if (size == 0) {
			close(ev.ident);
			EV_SET(&ev, ev.ident, EVFILT_READ, EV_DELETE, 0, 0,
			    NULL);
			kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL);
			if (vm->outfd == ev.ident)
				vm->outfd = -1;
			if (vm->errfd == ev.ident)
				vm->errfd = -1;
			break;
		} else if (size > 0 && vm->logfd != -1) {
			n = 0;
			while (n < size) {
				if ((rc = write(vm->logfd, buf + n, size - n)) <
				    0)
					if (errno != EINTR && errno != EAGAIN)
						break;
				if (rc > 0)
					n += rc;
			}
		}
		break;
	case EVFILT_TIMER:
		if (vm->state == INIT) {
			/* delayed boot */
			start_virtual_machine(vm_ent);
		} else if (vm->state == LOAD || vm->state == STOP ||
		    vm->state == REMOVE || vm->state == RESTART) {
			/* loader timout or stop timeout */
			/* force to kill process */
			ERR("timeout kill vm %s\n", vm->conf->name);
			kill(vm->pid, SIGKILL);
		}
		break;
	case EVFILT_PROC:
		if (waitpid(ev.ident, &status, 0) < 0)
			ERR("wait error (%s)\n", strerror(errno));
		if (vm == NULL || vm->pid != ev.ident)
			// Maybe plugin set this event
			break;
		switch (vm->state) {
		case LOAD:
			if (vm->infd != -1) {
				close(vm->infd);
				vm->infd = -1;
			}
			if (vm->outfd != -1) {
				close(vm->outfd);
				vm->outfd = -1;
			}
			if (vm->errfd != -1) {
				close(vm->errfd);
				vm->errfd = -1;
			}
			if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
				start_virtual_machine(vm_ent);
			else {
				ERR("failed loading vm %s (status:%d)\n",
				    vm->conf->name, WEXITSTATUS(status));
				stop_waiting_fd(vm_ent);
				cleanup_vm(vm);
				call_plugins(vm_ent);
			}
			break;
		case RESTART:
			stop_waiting_fd(vm_ent);
			cleanup_vm(vm);
			call_plugins(vm_ent);

			vm->state = INIT;
			set_timer(vm_ent, MAX(vm->conf->boot_delay, 3));
			break;
		case RUN:
			if (vm->conf->boot != INSTALL && WIFEXITED(status) &&
			    (vm->conf->boot == ALWAYS ||
				WEXITSTATUS(status) == 0)) {
				start_virtual_machine(vm_ent);
				break;
			}
			/* RUN THROUGH */
		case STOP:
			INFO("stop vm %s\n", vm->conf->name);
			stop_waiting_fd(vm_ent);
			cleanup_vm(vm);
			call_plugins(vm_ent);
			break;
		case REMOVE:
			stop_waiting_fd(vm_ent);
			cleanup_vm(vm);
			call_plugins(vm_ent);
			SLIST_REMOVE(&vm_list, vm_ent, vm_entry, next);
			free_vm_entry(vm_ent);
			break;
		case INIT:
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
		free(buf);
		return -1;
	}

	goto wait;
end:
	free(buf);
	return 0;
}

int
stop_virtual_machines()
{
	struct kevent ev;
	struct vm *vm;
	struct vm_entry *vm_ent;
	int status, count = 0;

	SLIST_FOREACH (vm_ent, &vm_list, next) {
		vm = &vm_ent->vm;
		if (vm->state == LOAD || vm->state == RUN) {
			count++;
			kill(vm->pid, SIGTERM);
			set_timer(vm_ent, vm->conf->stop_timeout);
		}
	}

	while (count > 0) {
		if (kevent(gl_conf.kq, NULL, 0, &ev, 1, NULL) < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (ev.filter == EVFILT_PROC) {
			vm_ent = ev.udata;
			vm = &vm_ent->vm;
			if (waitpid(ev.ident, &status, 0) < 0)
				ERR("wait error (%s)\n", strerror(errno));
			if (vm == NULL || vm->pid != ev.ident)
				// maybe plugin's child process
				continue;
			stop_waiting_fd(vm_ent);
			cleanup_vm(vm);
			call_plugins(vm_ent);
			count--;
		} else if (ev.filter == EVFILT_TIMER) {
			vm_ent = ev.udata;
			vm = &vm_ent->vm;
			/* force to kill process */
			ERR("timeout kill vm %s\n", vm->conf->name);
			kill(vm->pid, SIGKILL);
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
	FILE *fp;
	int fg = 0;

	while ((ch = getopt(argc, argv, "b:iFf:p:")) != -1) {
		switch (ch) {
		case 'b':
			gl_conf.vm_name = strdup(optarg);
			fg = 1;
			break;
		case 'i':
			gl_conf.install = 1;
			break;
		case 'F':
			fg = 1;
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
		default:
			fprintf(stderr,
			    "usage: %s [-F] [-f pid file] "
			    "[-p plugin directory] \n"
			    "\t[-c vm config directory]\n"
			    "\t[-b vm name] [-i]\n",
			    argv[0]);
			return -1;
		}
	}

	if ((gl_conf.foreground = fg) == 0) {
		daemon(0, 0);

		fp = fopen(gl_conf.pid_path, "w");
		if (fp) {
			fprintf(fp, "%d\n", getpid());
			fclose(fp);
		}
	}

	return 0;
}

int
direct_run()
{
	int fd;
	char *path;
	int status;
	struct vm_conf *conf;
	struct vm_conf_entry *conf_ent;
	struct vm_entry *vm_ent;
	struct vm *vm;

	fd = open(gl_conf.plugin_dir, O_DIRECTORY | O_RDONLY);
	if (fd < 0) {
		ERR("can not open %s\n", gl_conf.plugin_dir);
		return 1;
	}
	gl_conf.plugin_fd = fd;

	INFO("%s\n", "start daemon");

	if (load_plugins() < 0)
		return 1;

	if (asprintf(&path, "%s/%s", gl_conf.config_dir, gl_conf.vm_name) < 0)
		return 1;
	fd = open(path, O_RDONLY);
	free(path);
	if (fd < 0) {
		fprintf(stderr, "can not open %s/%s\n", gl_conf.config_dir,
		    gl_conf.vm_name);
		return 1;
	}
	conf = parse_file(fd, gl_conf.vm_name);
	close(fd);
	if (conf == NULL)
		return 1;
	free(conf->comport);
	conf->comport = strdup("stdio");
	if (gl_conf.install)
		conf->boot = INSTALL;

	conf_ent = realloc(conf, sizeof(*conf_ent));
	if (conf_ent == NULL) {
		free_vm_conf(conf);
		return 1;
	}

	vm_ent = create_vm_entry(conf_ent);
	if (vm_ent == NULL) {
		free_vm_conf(conf);
		return 1;
	}
	vm = &vm_ent->vm;

	if (start_vm(vm) < 0)
		goto err;
	call_plugins(vm_ent);
	if (waitpid(vm->pid, &status, 0) < 0)
		goto err;

	if (vm->state == LOAD) {
		if (exec_bhyve(vm) < 0)
			goto err;
		call_plugins(vm_ent);
		if (waitpid(vm->pid, &status, 0) < 0)
			goto err;
	}

	cleanup_vm(vm);
	call_plugins(vm_ent);
	free_vm_entry(vm_ent);
	remove_plugins();
	return 0;
err:
	cleanup_vm(vm);
	call_plugins(vm_ent);
	free_vm_entry(vm_ent);
	remove_plugins();
	return 1;
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

int
usage(int argc, char *argv[])
{
	printf("usage: %s boot <name>| install <vm name> | shutdown <vm name>| reload <name> | list\n", argv[0]);
	return 1;
}

int
do_command(int argc, char *argv[])
{
	int s, ret = 0;
	nvlist_t *cmd, *res = NULL;

	if (argc < 2)
		return usage(argc, argv);

	cmd = nvlist_create(0);

	if (strcmp(argv[1], "start") == 0)
		argv[1] = "boot";
	else if (strcmp(argv[1], "stop") == 0)
		argv[1] = "shutdown";

	if (argc == 2 && strcmp(argv[1], "list") == 0) {
		nvlist_add_string(cmd, "command", argv[1]);
	} else if (argc == 3 && (strcmp(argv[1], "boot") == 0 ||
				 strcmp(argv[1], "install") == 0 ||
				 strcmp(argv[1], "reload") == 0 ||
				 strcmp(argv[1], "shutdown") == 0)) {
		nvlist_add_string(cmd, "command", argv[1]);
		nvlist_add_string(cmd, "name", argv[2]);
	} else {
		return usage(argc, argv);
	}

	if ((s = connect_to_server(&gl_conf)) < 0) {
		printf("can not connect to %s\n", gl_conf.cmd_sock_path);
		return 1;
	}

	nvlist_send(s, cmd);

	res = nvlist_recv(s, 0);
	if (res == NULL) {
		printf("server returns null\n");
		goto end;
	}

	if (nvlist_get_bool(res, "error")) {
		printf("%s\n", nvlist_get_string(res, "reason"));
		goto end;
	}

	if (argc == 2 && strcmp(argv[1], "list") == 0) {
		size_t i, count;
		const struct nvlist * const *list;
		list = nvlist_get_nvlist_array(res, "vm_list", &count);
		for (i = 0; i < count ; i++) {
			printf("%20s %s\n",
			       nvlist_get_string(list[i], "name"),
			       nvlist_get_string(list[i], "state")
				);
		}
	}

end:
	close(s);
	nvlist_destroy(cmd);
	nvlist_destroy(res);
	return ret;
}

int
main(int argc, char *argv[])
{
	sigset_t nmask, omask;

	if (strendswith(argv[0], "ctl") == 0)
		return do_command(argc, argv);

	if (parse_opt(argc, argv) < 0)
		return 1;

	if (gl_conf.vm_name != NULL)
		return direct_run();

	if (gl_conf.foreground)
		LOG_OPEN_PERROR();
	else
		LOG_OPEN();

	sigemptyset(&nmask);
	sigaddset(&nmask, SIGTERM);
	if (gl_conf.foreground)
		sigaddset(&nmask, SIGINT);
	sigaddset(&nmask, SIGHUP);
	sigprocmask(SIG_BLOCK, &nmask, &omask);

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

	if (install)
		vm_ent->vm.conf->boot = INSTALL;

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

int
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

	if ((fd = openat(gl_conf.config_fd, vm->conf->filename, O_RDONLY)) < 0) {
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

	SLIST_REMOVE(&vm_conf_list, (struct vm_conf_entry*)vm->conf,
		     vm_conf_entry, next);
	SLIST_INSERT_HEAD(&vm_conf_list, conf_ent, next);
	free_vm_conf(vm->conf);
	vm->conf = conf = &conf_ent->conf;

	switch (vm->state) {
	case LOAD:
	case RUN:
		INFO("stop vm %s\n", conf->name);
		kill(vm->pid, SIGTERM);
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

int
boot_command(int s, const nvlist_t *nv)
{
	return boot0_command(s, nv, false);
}

int
install_command(int s, const nvlist_t *nv)
{
	return boot0_command(s, nv, true);
}

int
list_command(int s, const nvlist_t *nv)
{
	size_t i, count=0;
	const char *reason;
	nvlist_t *res, *p;
	const nvlist_t **list = NULL;
	struct vm_entry *vm_ent;
	bool error = false;
	static char *state_string[] = {
		"STOP", "LOAD", "RUN", "STOP",
		"TERMINATING", "TERMINATING", "REBOOTING"
	};


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

int
shutdown_command(int s, const nvlist_t *nv)
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

	if (vm_ent->vm.state != LOAD && vm_ent->vm.state != RUN)
		goto ret;

	kill(vm_ent->vm.pid, SIGTERM);
	set_timer(vm_ent, vm_ent->vm.conf->stop_timeout);
	vm_ent->vm.state = STOP;

ret:
	res = nvlist_create(0);
	nvlist_add_bool(res, "error", error);
	if (error)
		nvlist_add_string(res, "reason", reason);
	nvlist_send(s, res);
	nvlist_destroy(res);
	return 0;
}
