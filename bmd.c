#include <sys/dirent.h>
#include <sys/event.h>
#include <sys/nv.h>
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

#include "server.h"
#include "conf.h"
#include "log.h"
#include "parser.h"
#include "vars.h"
#include "vm.h"
#include "bmd.h"

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
	"/var/run/bmd.pid", "/var/run/bmd.sock", NULL, -1, -1, -1, 0, -1 };

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

	if (vm_ent->vm.outfd != -1)
		EV_SET(&ev[i++], vm_ent->vm.outfd, EVFILT_READ, EV_DELETE, 0, 0,
		    vm_ent);
	if (vm_ent->vm.errfd != -1)
		EV_SET(&ev[i++], vm_ent->vm.errfd, EVFILT_READ, EV_DELETE, 0, 0,
		    vm_ent);
	while (kevent(gl_conf.kq, ev, i, NULL, 0, NULL) < 0)
		if (errno != EINTR) {
			ERR("failed to delete waiting fd (%s)\n",
			    strerror(errno));
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

	EV_SET(&ev, vm_ent->vm.pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT,
	    0, vm_ent);
	while(kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL) < 0)
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
	vm_ent->type = VMENTRY;
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
		poweroff_vm(vm);
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
		if (strcmp(vm_ent->vm.conf->name, name) == 0)
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
		vm_ent = lookup_vm_by_name(conf->name);
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
		vm_ent->new_conf = conf;
		vm = &vm_ent->vm;
		if (conf->reboot_on_change &&
		    compare_vm_conf(conf, vm->conf) != 0) {
			if (vm->state == LOAD || vm->state == RUN) {
				INFO("reboot vm %s\n", conf->name);
				acpi_poweroff_vm(&vm_ent->vm);
				set_timer(vm_ent, conf->stop_timeout);
				vm->state = RESTART;
			} else if (vm->state == STOP)
				vm->state = RESTART;
			continue;
		}
		if (vm_ent->new_conf->boot == vm_ent->vm.conf->boot)
			continue;
		switch (conf->boot) {
		case NO:
			if (vm->state == LOAD || vm->state == RUN) {
				INFO("stop vm %s\n", conf->name);
				acpi_poweroff_vm(&vm_ent->vm);
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
		}
	}

	SLIST_FOREACH (vm_ent, &vm_list, next)
		if (vm_ent->new_conf == NULL) {
			vm = &vm_ent->vm;
			conf = vm->conf;
			switch (vm->state) {
			case LOAD:
			case RUN:
				INFO("stop vm %s\n", conf->name);
				acpi_poweroff_vm(&vm_ent->vm);
				set_timer(vm_ent, conf->stop_timeout);
				/* FALLTHROUGH */
			case STOP:
			case REMOVE:
			case RESTART:
				vm->state = REMOVE;
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
	vm = &vm_ent->vm;
	switch (ev.filter) {
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
		if (vm_ent != NULL && vm_ent->type == SOCKBUF) {
			sb = (struct sock_buf *)vm_ent;
			switch (recv_sock_buf(sb)) {
			case 2:
				if (recv_command(sb) == 0)
					clear_sock_buf(sb);
				/* FALLTHROUGH */
			case 1:
				break;
			default:
				destroy_sock_buf(sb);
				EV_SET(&ev, ev.ident, EVFILT_READ, EV_DELETE,
				       0, 0, NULL);
				while (kevent(gl_conf.kq, &ev, 1, NULL, 0,
					      NULL) < 0)
					if (errno != EINTR)
						break;
			}
			break;
		}
		if (write_err_log(ev.ident, vm) == 0) {
			EV_SET(&ev, ev.ident, EVFILT_READ, EV_DELETE, 0, 0,
			       NULL);
			while (kevent(gl_conf.kq, &ev, 1, NULL, 0, NULL) < 0)
				if (errno != EINTR)
					break;
		}
		break;
	case EVFILT_TIMER:
		if (vm->state == INIT) {
			/* delayed boot */
			start_virtual_machine(vm_ent);
		} else if (vm->state == LOAD || vm->state == STOP ||
		    vm->state == REMOVE || vm->state == RESTART) {
			/* loader timout or stop timeout */
			/* force to poweroff */
			ERR("timeout kill vm %s\n", vm->conf->name);
			poweroff_vm(vm);
		}
		break;
	case EVFILT_PROC:
		if (waitpid(ev.ident, &status, 0) < 0)
			ERR("wait error (%s)\n", strerror(errno));
		if (vm_ent == NULL || vm->pid != ev.ident)
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
			if (vm->conf->install == false && WIFEXITED(status) &&
			    (vm->conf->boot == ALWAYS ||
				WEXITSTATUS(status) == 0)) {
				start_virtual_machine(vm_ent);
				break;
			}
			/* FALLTHROUGH */
		case STOP:
			INFO("stop vm %s\n", vm->conf->name);
			stop_waiting_fd(vm_ent);
			cleanup_vm(vm);
			call_plugins(vm_ent);
			vm->conf->install = false;
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
		return -1;
	}

	goto wait;
end:
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
			acpi_poweroff_vm(&vm_ent->vm);
			set_timer(vm_ent, vm->conf->stop_timeout);
		}
	}

	while (count > 0) {
		if (kevent(gl_conf.kq, NULL, 0, &ev, 1, NULL) < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		vm_ent = ev.udata;
		vm = &vm_ent->vm;
		if (ev.filter == EVFILT_PROC) {
			if (waitpid(ev.ident, &status, 0) < 0)
				ERR("wait error (%s)\n", strerror(errno));
			if (vm_ent == NULL || vm->pid != ev.ident)
				// maybe plugin's child process
				continue;
			stop_waiting_fd(vm_ent);
			cleanup_vm(vm);
			call_plugins(vm_ent);
			count--;
		} else if (ev.filter == EVFILT_TIMER) {
			/* force to poweroff VM */
			ERR("timeout kill vm %s\n", vm->conf->name);
			poweroff_vm(vm);
		} else if (ev.filter == EVFILT_READ) {
			if (vm_ent->type == SOCKBUF) {
				destroy_sock_buf((struct sock_buf *)vm_ent);
				EV_SET(&ev, ev.ident, EVFILT_READ, EV_DELETE,
				       0, 0, NULL);
				while (kevent(gl_conf.kq, &ev, 1, NULL, 0,
					      NULL) < 0)
					if (errno != EINTR)
						break;
				continue;
			}
			if (write_err_log(ev.ident, vm) == 0) {
				EV_SET(&ev, ev.ident, EVFILT_READ, EV_DELETE,
				       0, 0, NULL);
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
	FILE *fp;
	int fg = 0;

	while ((ch = getopt(argc, argv, "Ff:p:m:")) != -1) {
		switch (ch) {
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
