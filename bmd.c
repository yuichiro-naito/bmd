#include <sys/param.h>
#include <sys/dirent.h>
#include <sys/event.h>
#include <sys/procctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <pwd.h>

#include "bmd.h"
#include "log.h"
#include "server.h"
#include "vm.h"
#include "bmd_plugin.h"

/*
  List of VM configurations.
 */
struct vm_conf_list vm_conf_list = LIST_HEAD_INITIALIZER();

/*
  List of virtual machines.
 */
struct vm_list vm_list = SLIST_HEAD_INITIALIZER();
static struct plugin_list plugin_list = SLIST_HEAD_INITIALIZER();

/*
  All Events
*/
static struct event_list event_list = LIST_HEAD_INITIALIZER();

/*
  Global event queue
 */
static int eventq;

/*
  Global command socket
 */
static int cmd_sock;

/*
  Last Timer Event ID
 */
static int timer_id = 0;

/*
  Received SIGTERM flag
 */
static int sigterm = 0;

/*
  Direct run mode
 */
static bool direct_run_mode = false;

static int reload_virtual_machines(void);
static void stop_virtual_machine(struct vm_entry *);
static void free_vm_entry(struct vm_entry *);

static int
create_eventq(void)
{
#if __FreeBSD_version >= 1400088 || \
	(__FreeBSD_version < 1400000 && __FreeBSD_version >= 1302505)
	if ((eventq = kqueue1(O_CLOEXEC)) < 0) {
#else
	if ((eventq = kqueue()) < 0) {
#endif
		ERR("%s\n", "cannot open kqueue");
		return -1;
	}
	return 0;
}

static int
kevent_set(struct kevent *kev, int n)
{
	int rc;
	while ((rc = kevent(eventq, kev, n, NULL, 0, NULL)) < 0)
		if (errno != EINTR)
			return -1;
	return rc;
}

static int
kevent_get(struct kevent *kev, int n, struct timespec *timeout)
{
	int rc;
	while ((rc = kevent(eventq, NULL, 0 , kev, n, timeout)) < 0)
		if (errno != EINTR)
			return -1;
	return rc;
}

static bool
vm_output(struct event *ev, void *data)
{
	struct kevent *k = &ev->kev;
	struct vm_entry *e = data;

	return  ev->data == e && k->filter == EVFILT_READ && (
		(int)k->ident == VM_OUTFD(e) || (int)k->ident == VM_ERRFD(e));
}

static bool
vm_output_and_timers(struct event *ev, void *data)
{
	struct kevent *k = &ev->kev;
	struct vm_entry *e = data;

	return ev->data == e && (
		k->filter == EVFILT_TIMER ||
		(k->filter == EVFILT_READ &&
		 ((int)k->ident == VM_OUTFD(e) || (int)k->ident == VM_ERRFD(e)))
		);
}

static bool
sock_buf(struct event *ev, void *data)
{
	return (ev->data == data);
}

/*
 * The 'vm_entry' function should be an alias for 'sock_buf'. But It's hard to
 * be replaced by #define. Because the 'vm_entry' key word is widely used in
 * this source.
 */
static bool
vm_entry(struct event *ev, void *data)
{
	return (ev->data == data);
}

static void
stop_waiting_for(bool (*fn)(struct event *, void *), void *data)
{
	int i = 0;
	struct event *ev, *evn;
	struct kevent kev[5];

	LIST_FOREACH_SAFE (ev, &event_list, next, evn) {
		if (!fn(ev, data))
			continue;
		kev[i] = ev->kev;
		kev[i].flags = EV_DELETE;
		i++;
		if (i >= (int)nitems(kev)) {
			if (kevent_set(kev, i) < 0)
				ERR("failed to remove kevent (%s)\n",
				    strerror(errno));
			i = 0;
		}
		LIST_REMOVE(ev, next);
		free(ev);
	}
	if (i > 0 && kevent_set(kev, i) < 0)
		ERR("failed to remove kevent (%s)\n", strerror(errno));
}

static int
register_event0(enum EVENT_TYPE type, struct kevent *kev, event_call_back cb,
	       void *data)
{
	struct event *ev;

	if ((ev = malloc(sizeof(*ev))) == NULL)
		return -1;

	kev->udata = ev;
	ev->type = type;
	ev->kev = *kev;
	ev->cb = cb;
	ev->data = data;

	if (kevent_set(kev, 1) < 0) {
		free(ev);
		return -1;
	}

	LIST_INSERT_HEAD(&event_list, ev, next);
	return 0;
}

#define register_event(b, c, d) register_event0(EVENT, (b), (c), (d))
#define register_plugin_event(b, c, d) register_event0(PLUGIN, (b), (c), (d))

int
register_events(struct kevent *kev, event_call_back *cb, void **data, int n)
{
	int i;
	struct event **ev;

	if (n <= 0)
		return 0;

	if ((ev = malloc(sizeof(struct event *) * n)) == NULL)
		return -1;

	for (i = 0; i < n; i++)
		ev[i] = malloc(sizeof(struct event));

	for (i = 0; i < n; i++) {
		if (ev[i] == NULL)
			goto err;
		kev[i].udata = ev[i];
		ev[i]->type = EVENT;
		ev[i]->kev = kev[i];
		ev[i]->cb = cb[i];
		ev[i]->data = data[i];
	}

	if (kevent_set(kev, n) < 0)
		goto err;

	for (i = 0; i < n; i++)
		LIST_INSERT_HEAD(&event_list, ev[i], next);
	free(ev);
	return 0;
err:
	for (i = 0; i < n; i++)
		free(ev[i]);
	free(ev);
	return -1;
}

static int
count_plugin_process_events(void)
{
	int n = 0;
	struct event *ev;

	LIST_FOREACH (ev, &event_list, next)
		if (ev->type == PLUGIN && ev->kev.filter == EVFILT_PROC)
			n++;
	return n;
}

int
plugin_wait_for_process(pid_t pid, plugin_call_back cb, void *data)
{
	struct kevent kev;

	EV_SET(&kev, pid, EVFILT_PROC, EV_ADD | EV_ONESHOT,
	       NOTE_EXIT, 0, NULL);

	if (register_plugin_event(&kev, cb, data) < 0) {
		ERR("failed to wait plugin process (%s)\n", strerror(errno));
		return -1;
	}
	return 0;
}

int
plugin_set_timer(int second, plugin_call_back cb, void *data)
{
	struct kevent kev;

	EV_SET(&kev, ++timer_id, EVFILT_TIMER,
	       EV_ADD | EV_ONESHOT, NOTE_SECONDS, second, NULL);

	if (register_plugin_event(&kev, cb, data) < 0) {
		ERR("failed to plugin set timer (%s)\n", strerror(errno));
		return -1;
	}
	return 0;
}

static struct plugin_data *
lookup_plugin_data(PLUGIN_DESC *desc, struct vm_entry *vm_ent)
{
	struct plugin_data *pd;

	SLIST_FOREACH (pd, &VM_PLUGIN_DATA(vm_ent), next)
		if (strcmp(pd->ent->desc.name, desc->name) == 0 &&
		    (pd->ent->desc.prestart == desc->prestart ||
		     pd->ent->desc.poststop == desc->poststop))
			break;
	return pd;
}

static void
init_plugin_results(struct vm_entry *vm_ent)
{
	unsigned int i;
	struct plugin_data *pd;

	SLIST_FOREACH (pd, &VM_PLUGIN_DATA(vm_ent), next)
		for (i = 0; i < nitems(pd->results); i++)
			memset(&pd->results[i], 0, sizeof(pd->results[i]));
}

static void
print_prestart_error(struct vm_entry *vm_ent)
{
	struct plugin_data *pd;

	SLIST_FOREACH (pd, &VM_PLUGIN_DATA(vm_ent), next)
		if (pd->results[0].called &&
		    pd->prestart_result.state < 0)
			ERR("%s: plugin '%s' prevents from starting VM",
			    VM_CONF(vm_ent)->name,
			    pd->ent->desc_name);
}

static int
get_plugin_state(struct vm_entry *vm_ent, unsigned int i)
{
	int rc = 0;
	struct plugin_data *pd;

	SLIST_FOREACH (pd, &VM_PLUGIN_DATA(vm_ent), next)
		if (pd->results[i].called) {
			if (pd->prestart_result.state == 0)
				continue;
			if (pd->prestart_result.state > 0)
				return 1;
			if (pd->prestart_result.state < 0)
				rc = -1;
		}
	return rc;
}

static int
get_prestart_state(struct vm_entry *vm_ent)
{
	return get_plugin_state(vm_ent, 0);
}

static int
get_poststop_state(struct vm_entry *vm_ent)
{
	return get_plugin_state(vm_ent, 1);
}

int
plugin_start_virtualmachine(PLUGIN_DESC *desc, struct vm *v)
{
	int st;
	struct vm_entry *vm_ent = (struct vm_entry*)v;
	struct plugin_data *pd;

	if ((pd = lookup_plugin_data(desc, vm_ent)) == NULL)
		return -1;

	pd->prestart_result.state = 0;

	if ((st = get_prestart_state(vm_ent)) > 0)
		return 0;

	if (st == 0)
		return start_virtual_machine(vm_ent);

	print_prestart_error(vm_ent);
	stop_virtual_machine(vm_ent);
	return 0;
}

int
plugin_stop_virtualmachine(PLUGIN_DESC *desc, struct vm *v)
{
	struct vm_entry *vm_ent = (struct vm_entry*)v;
	struct plugin_data *pd;

	if ((pd = lookup_plugin_data(desc, vm_ent)) == NULL)
		return -1;

	pd->prestart_result.state = -1;

	if (get_prestart_state(vm_ent) > 0)
		return 0;

	print_prestart_error(vm_ent);
	stop_virtual_machine(vm_ent);
	return 0;
}

int
plugin_logger(int priority, PLUGIN_DESC *desc, const char *fmt, ...)
{
	va_list ap;
	char *s;
	va_start(ap, fmt);
	if (vasprintf(&s, fmt, ap) >= 0) {
		LOGGER(priority, "%s: %s\n", desc->name, s);
		free(s);
	}
	va_end(ap);
	return 0;
}

int
send_fd(int sock, int fd)
{
	int rc;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char result;

	result = fd < 0 ? 0 : 1;
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = &result;
	iov.iov_len = sizeof(result);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (result) {
		msg.msg_controllen = CMSG_SPACE(sizeof(int));
		msg.msg_control = calloc(1, msg.msg_controllen);
		if (msg.msg_control == NULL)
			return -1;

		cmsg = msg.msg_control;
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
		memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
	}

	while ((rc = sendmsg(sock, &msg, 0)) < 0)
		if (errno != EINTR && errno != EAGAIN)
			break;
	if (result)
		free(msg.msg_control);
	return rc;
}

int
recv_fd(int sock)
{
	int rc, fd;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov;
	char result = 0;

	memset(&msg, 0, sizeof(msg));
	memset(&iov, 0, sizeof(iov));
	iov.iov_base = &result;
	iov.iov_len = sizeof(result);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_controllen = CMSG_SPACE(sizeof(int));
	msg.msg_control = calloc(1, msg.msg_controllen);
	if (msg.msg_control == NULL)
		return -1;

	while ((rc = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC)) < 0)
		if (errno != EINTR && errno != EAGAIN)
			break;

	if (rc < 0 || result == 0)
		goto err;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg->cmsg_level != SOL_SOCKET ||
	    cmsg->cmsg_type != SCM_RIGHTS)
		goto err;

	memcpy(&fd, CMSG_DATA(cmsg), sizeof(int));

	free(msg.msg_control);
	return fd;
err:
	free(msg.msg_control);
	return -1;

}

int
send_ack(int sock)
{
	int rc;
	static const char *buf = "ack";

	while ((rc = send(sock, buf, strlen(buf) + 1, 0)) < 0)
		if (errno != EINTR && errno != EAGAIN)
			break;

	return rc;
}

int
recv_ack(int sock)
{
	int rc;
	char buf[8];

	while ((rc = recv(sock, buf, sizeof(buf), 0)) < 0)
		if (errno != EINTR && errno != EAGAIN)
			break;

	return rc;
}

static int
open_err_logfile(struct vm_conf *conf)
{
	int fd;
	pid_t pid;
	int socks[2];
	struct stat st;
	int64_t group;
	struct passwd *pwd;

	if (socketpair(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, socks) < 0)
		return -1;

	if ((pid = fork()) < 0) {
		close(socks[0]);
		close(socks[1]);
		return -1;
	}

	if (pid == 0) {
		close(socks[0]);
		if (conf->owner > 0) {
			if ((group = conf->group) == -1)
				group = (pwd = getpwuid((uid_t)conf->owner)) ?
					pwd->pw_gid : GID_NOBODY;

			setgid((gid_t)group);
			setuid((uid_t)conf->owner);
		}

		while ((fd = open(conf->err_logfile,
				  O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC,
				  0644)) < 0)
			if (errno != EINTR)
				break;

		if (fd >= 0 &&
		    (fstat(fd, &st) < 0 || (! S_ISREG(st.st_mode)))) {
			close(fd);
			fd = -1;
		}

		send_fd(socks[1], fd);
		recv_ack(socks[1]);
		close(socks[1]);
		exit(0);
	}

	close(socks[1]);

	fd = recv_fd(socks[0]);
	send_ack(socks[0]);
	while (waitpid(pid, NULL, 0) < 0)
		if (errno != EINTR)
			break;

	close(socks[0]);
	if (fd < 0)
		ERR("%s: failed to open %s\n", conf->name, conf->err_logfile);
	return fd;
}

static int
on_read_vm_output(int fd, void *data)
{
	struct vm_entry *vm_ent = data;
	struct event *ev, *evn;
	struct kevent *kev;

	if (write_err_log(fd, VM_PTR(vm_ent)) == 0) {
		LIST_FOREACH_SAFE (ev, &event_list, next, evn) {
			kev = &ev->kev;
			if (ev->data != vm_ent || (int)kev->ident != fd ||
			    kev->filter != EVFILT_READ)
				continue;
			/*
			 * No need to remove fd from kqueue.
			 * It's already closed.
			 */
			LIST_REMOVE(ev, next);
			free(ev);
		}
	}
	return 0;
}

static int
wait_for_vm_output(struct vm_entry *vm_ent)
{
	int i = 0;
	struct kevent kev[2];
	static event_call_back cb[2] = {on_read_vm_output, on_read_vm_output};
	void *data[2];

	if (VM_OUTFD(vm_ent) != -1) {
		EV_SET(&kev[i], VM_OUTFD(vm_ent), EVFILT_READ, EV_ADD, 0, 0,
		       NULL);
		data[i] = vm_ent;
		i++;
	}
	if (VM_ERRFD(vm_ent) != -1) {
		EV_SET(&kev[i], VM_ERRFD(vm_ent), EVFILT_READ, EV_ADD, 0, 0,
		       NULL);
		data[i] = vm_ent;
		i++;
	}

	if (register_events(kev, cb, data, i) < 0) {
		ERR("failed to wait vm fds (%s)\n", strerror(errno));
		return -1;
	}

	return 0;
}

static void
free_events(void)
{
	struct event *ev, *evn;

	LIST_FOREACH_SAFE (ev, &event_list, next, evn)
		free(ev);
	LIST_INIT(&event_list);
}

static int
on_timer(int ident __unused, void *data)
{
	struct vm_entry *vm_ent = data;

	switch (VM_STATE(vm_ent)) {
	case TERMINATE:
		/* delayed boot */
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
	case PRESTART:
	case POSTSTOP:
		/* ignore timer */
		break;
	}
	return 0;
}

/*
 * Set event timer.
 */
int
set_timer(struct vm_entry *vm_ent, int second)
{
	struct kevent kev;

	EV_SET(&kev, ++timer_id, EVFILT_TIMER,
	       EV_ADD | EV_ONESHOT, NOTE_SECONDS, second, NULL);

	if (register_event(&kev, on_timer, vm_ent) < 0) {
		ERR("failed to set timer (%s)\n", strerror(errno));
		return -1;
	}
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

static int
call_prestart_plugins(struct vm_entry *vm_ent)
{
	int rc, ret = INT_MIN;
	bool called = false;
	struct plugin_data *pd;

	VM_STATE(vm_ent) = PRESTART;

	SLIST_FOREACH (pd, &VM_PLUGIN_DATA(vm_ent), next)
		if (pd->ent->desc.prestart) {
			rc = (pd->ent->desc.prestart)(VM_PTR(vm_ent),
						      pd->pl_conf);
			pd->prestart_result.called = true;
			pd->prestart_result.state = rc;
			called = true;
			if (rc > ret)
				ret = rc;
		}
	return called ? ret : 0;
}

static int
call_poststop_plugins(struct vm_entry *vm_ent)
{
	int rc, ret = INT_MIN;
	bool called = false;
	struct plugin_data *pd;

	VM_STATE(vm_ent) = POSTSTOP;

	SLIST_FOREACH (pd, &VM_PLUGIN_DATA(vm_ent), next)
		if (pd->ent->desc.poststop) {
			rc = (pd->ent->desc.poststop)(VM_PTR(vm_ent),
						      pd->pl_conf);
			pd->poststop_result.called = true;
			pd->poststop_result.state = rc;
			called = true;
			if (rc > ret)
				ret = rc;
		}
	return called ? ret : 0;
}

static int
on_vm_exit(int ident __unused, void *data)
{
	int status;
	struct vm_entry *vm_ent = data;
	char *rs;

	if (waitpid(VM_PID(vm_ent), &status, 0) < 0)
		ERR("wait error (%s)\n", strerror(errno));
	switch (VM_STATE(vm_ent)) {
	case LOAD:
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
			VM_CLOSE(vm_ent, INFD);
			stop_waiting_for(vm_output, vm_ent);
			start_virtual_machine(vm_ent);
		} else {
			ERR("failed loading vm %s (status:%d)\n",
			    VM_CONF(vm_ent)->name, WEXITSTATUS(status));
			if (VM_LD_METHOD(vm_ent))
				VM_LD_CLEANUP(vm_ent);
			if (call_poststop_plugins(vm_ent) > 0)
				return 0;
			stop_virtual_machine(vm_ent);
		}
		break;
	case RESTART:
		stop_virtual_machine(vm_ent);
		set_timer(vm_ent, MAX(VM_CONF(vm_ent)->boot_delay, 3));
		break;
	case RUN:
		if (VM_CONF(vm_ent)->install == false &&
		    WIFEXITED(status) &&
		    (VM_CONF(vm_ent)->boot == ALWAYS ||
		     (strcmp(VM_CONF(vm_ent)->backend, "bhyve") == 0 &&
		      WEXITSTATUS(status) == 0))) {
			VM_STATE(vm_ent) = PRESTART;
			start_virtual_machine(vm_ent);
			break;
		}
		/* FALLTHROUGH */
	case STOP:
		rs = reason_string(status);
		INFO("vm %s is stopped%s\n", VM_CONF(vm_ent)->name,
		     (rs == NULL ? "" : rs));
		free(rs);
		/* FALLTHROUGH */
	case PRESTART:
	case POSTSTOP:
		if (call_poststop_plugins(vm_ent) > 0)
			return 0;
		stop_virtual_machine(vm_ent);
		VM_CONF(vm_ent)->install = false;
		break;
	case REMOVE:
		INFO("vm %s is stopped\n", VM_CONF(vm_ent)->name);
		if (call_poststop_plugins(vm_ent) > 0)
			return 0;
		stop_virtual_machine(vm_ent);
		SLIST_REMOVE(&vm_list, vm_ent, vm_entry, next);
		free_vm_entry(vm_ent);
		break;
	case TERMINATE:
		break;
	}

	return 0;
}

static int
wait_for_vm(struct vm_entry *vm_ent)
{
	struct kevent kev;

	EV_SET(&kev, VM_PID(vm_ent), EVFILT_PROC, EV_ADD | EV_ONESHOT,
	       NOTE_EXIT, 0, NULL);

	if (register_event(&kev, on_vm_exit, vm_ent) < 0) {
		ERR("failed to wait process (%s)\n", strerror(errno));
		return -1;
	}

	return 0;
}

int
set_sock_buf_wait_flags(struct sock_buf *sb, short recv_f, short send_f)
{
	int i = 0;
	struct event *e, *ev[2] = {NULL, NULL};
	struct kevent kev[2];

	LIST_FOREACH (e, &event_list, next) {
		if (e->data != sb)
			continue;
		switch (e->kev.filter) {
		case EVFILT_READ:
			ev[0] = e;
			kev[i] = e->kev;
			kev[i].flags = recv_f;
			i++;
			break;
		case EVFILT_WRITE:
			ev[1] = e;
			kev[i] = e->kev;
			kev[i].flags = send_f;
			i++;
			break;
		default:
			break;
		}
		if (i >= 2)
			break;
	}

	if (i == 0)
		return 0;

	if (kevent_set(kev, i) < 0) {
		ERR("failed to change cmd socket event (%s)\n",
		    strerror(errno));
		return -1;
	}

	if (ev[0])
		ev[0]->kev.flags =  recv_f;

	if (ev[1])
		ev[1]->kev.flags =  send_f;

	return 0;
}

static int
on_recv_sock_buf(int ident __unused, void *data)
{
	struct sock_buf *sb = data;

	switch (recv_sock_buf(sb)) {
	case 2:
		if (recv_command(sb) == 0) {
			clear_sock_buf(sb);
			set_sock_buf_wait_flags(sb, EV_DISABLE, EV_ENABLE);
			break;
		}
		/* FALLTHROUGH */
	case 1:
		break;
	default:
		stop_waiting_for(sock_buf, sb);
		destroy_sock_buf(sb);
	}
	return 0;
}

static int
on_send_sock_buf(int ident __unused, void *data)
{
	struct sock_buf *sb = data;

	switch (send_sock_buf(sb)) {
	case 2:
		clear_send_sock_buf(sb);
		set_sock_buf_wait_flags(sb,  EV_ENABLE, EV_DISABLE);
		/* FALLTHROUGH */
	case 1:
		break;
	default:
		stop_waiting_for(sock_buf, sb);
		destroy_sock_buf(sb);
		break;
	}
	return 0;
}

static int
wait_for_sock_buf(struct sock_buf *sb)
{
	struct kevent kev[2];
	static event_call_back cb[2] = {on_recv_sock_buf, on_send_sock_buf};
	void *data[2] = {sb, sb};

	EV_SET(&kev[0], sb->fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	EV_SET(&kev[1], sb->fd, EVFILT_WRITE, EV_ADD, EV_DISABLE, 0, NULL);

	if (register_events(kev, cb, data, 2) < 0) {
		ERR("failed to wait socket buffer (%s)\n", strerror(errno));
		return -1;
	}

	return 0;
}

static int
on_accept_cmd_sock(int ident __unused, void *data __unused)
{
	struct sock_buf *sb;
	int n, sock = cmd_sock;

	if ((n = accept_command_socket(sock)) < 0)
		return -1;

	if ((sb = create_sock_buf(n)) == NULL) {
		ERR("%s\n","failed to allocate socket buffer");
		close(n);
		return -1;
	}

	if (wait_for_sock_buf(sb) < 0) {
		destroy_sock_buf(sb);
		return -1;
	}

	return 0;
}

static int
wait_for_cmd_sock(int sock)
{
	struct kevent kev;

	EV_SET(&kev, sock, EVFILT_READ, EV_ADD, 0, 0, NULL);

	if (register_event(&kev, on_accept_cmd_sock, NULL) < 0) {
		ERR("failed to wait socket recv (%s)\n", strerror(errno));
		return -1;
	}

	return 0;
}

static void
free_plugin_entry(struct plugin_entry *pe)
{
	if (pe == NULL)
		return;
	if (pe->desc.method) {
		free(pe->vm_name);
		free(pe->desc.method);
	}
	if (pe->desc.loader_method) {
		free(pe->lm_name);
		free(pe->desc.loader_method);
	}
	free(pe->desc_name);
	free(pe);
}

static int
dummy0(struct vm *vm __unused, nvlist_t *pl_ent __unused)
{
	return 0;
}

static int
dummy1(struct vm *vm __unused, nvlist_t *pl_ent __unused)
{
	return 1;
}

static void
dummy2(struct vm *vm __unused, nvlist_t *pl_ent __unused)
{
	return;
}

#define set_default(o, m, f)   (o)->m = (o)->m ? (o)->m : (f)

static struct plugin_entry *
create_plugin_entry(struct plugin_desc *desc)
{
	char *dname, *vname, *lname;
	struct plugin_entry *pe;
	struct vm_method *vm;
	struct loader_method *lm;

	dname = strdup(desc->name);
	pe = calloc(1, sizeof(*pe));
	if (dname == NULL || pe == NULL)
		goto err0;

	memcpy(&pe->desc, desc, sizeof(pe->desc));
	pe->desc.name = dname;
	pe->desc_name = dname;

	if (desc->method) {
		vname = strdup(desc->method->name);
		vm = malloc(sizeof(*vm));
		if (vname == NULL || vm == NULL)
			goto err1;
		memcpy(vm, desc->method, sizeof(*vm));

		set_default(vm, vm_start, dummy0);
		set_default(vm, vm_reset, dummy0);
		set_default(vm, vm_poweroff, dummy0);
		set_default(vm, vm_acpi_poweroff, dummy0);
		set_default(vm, vm_cleanup, dummy2);

		vm->name = vname;
		pe->vm_name = vname;
		pe->desc.method = vm;
	} else {
		vname = NULL;
		vm = NULL;
		pe->desc.method = NULL;
	}

	if (desc->loader_method) {
		lname = strdup(desc->loader_method->name);
		lm = malloc(sizeof(*lm));
		if (lname == NULL || lm == NULL)
			goto err2;
		memcpy(lm, desc->loader_method, sizeof(*lm));

		set_default(lm, ld_load, dummy1);
		set_default(lm, ld_cleanup, dummy2);

		lm->name = lname;
		pe->lm_name = lname;
		pe->desc.loader_method = lm;
	} else {
		lname = NULL;
		lm = NULL;
		pe->desc.loader_method = NULL;
	}

	return pe;

err2:
	free(lname);
	free(lm);
err1:
	free(vname);
	free(vm);
err0:
	free(dname);
	free(pe);
	return NULL;
}
#undef set_default

static int
add_plugin(int dirfd, const char *fname)
{
	int fd;
	void *hdl;
	struct plugin_desc *desc;
	struct plugin_entry *pl_ent;

	while ((fd = openat(dirfd, fname, O_RDONLY)) < 0)
		if (errno != EINTR)
			break;
	if (fd < 0)
		return -1;

	if ((hdl = fdlopen(fd, RTLD_NOW)) == NULL) {
		ERR("failed to open plugin %s\n", fname);
		goto err0;
	}

	if ((desc = dlsym(hdl, "plugin_desc")) == NULL ||
	    desc->version != PLUGIN_VERSION ||
	    (pl_ent = create_plugin_entry(desc)) == NULL) {
		ERR("invalid plugin %s\n", fname);
		goto err1;
	}

	if (desc->initialize && (*(desc->initialize))() < 0) {
		ERR("failed to initialize plugin %s %s\n", desc->name, fname);
		goto err2;
	}

	pl_ent->handle = hdl;
	SLIST_INSERT_HEAD(&plugin_list, pl_ent, next);
	INFO("load plugin %s %s\n", desc->name, fname);

	close(fd);
	return 0;
err2:
	free(pl_ent);
err1:
	dlclose(hdl);
err0:
	close(fd);
	return -1;
}

int
register_vm_method(struct vm_method *vm)
{
	struct plugin_desc desc;
	struct plugin_entry *pe;

	memset(&desc, 0, sizeof(desc));
	desc.name = vm->name;
	desc.method = vm;
	if ((pe = create_plugin_entry(&desc)) == NULL)
		return -1;

	SLIST_INSERT_HEAD(&plugin_list, pe, next);
	return 0;
}

int
register_loader_method(struct loader_method *lm)
{
	struct plugin_desc desc;
	struct plugin_entry *pe;

	memset(&desc, 0, sizeof(desc));
	desc.name = lm->name;
	desc.loader_method = lm;

	if ((pe = create_plugin_entry(&desc)) == NULL)
		return -1;

	SLIST_INSERT_HEAD(&plugin_list, pe, next);
	return 0;
}

int
load_plugins(const char *plugin_dir)
{
	DIR *d;
	struct dirent *ent;
	struct plugin_desc desc;
	struct plugin_entry *pl_ent;
	static int loaded = 0;

	if (loaded != 0)
		return 0;

	memset(&desc, 0, sizeof(desc));
	desc.name = "bhyve";
	desc.method = &bhyve_method;
	desc.loader_method = &bhyveload_method;

	if ((pl_ent = create_plugin_entry(&desc)) == NULL)
		return -1;

	SLIST_INSERT_HEAD(&plugin_list, pl_ent, next);

	if (register_loader_method(&grub2load_method) < 0 ||
	    register_loader_method(&uefiload_method) < 0 ||
	    register_loader_method(&csmload_method) < 0)
		return -1;

	if ((d = opendir(plugin_dir)) == NULL) {
		ERR("cannot open %s\n", plugin_dir);
		return -1;
	}

	while ((ent = readdir(d)) != NULL) {
		if (ent->d_namlen < 4 || ent->d_name[0] == '.' ||
		    strcmp(&ent->d_name[ent->d_namlen - 3], ".so") != 0)
			continue;
		if (add_plugin(dirfd(d), ent->d_name) >= 0)
			loaded++;
	}

	closedir(d);

	return 0;
}

int
remove_plugins(void)
{
	struct plugin_entry *pl_ent, *pln;

	SLIST_FOREACH_SAFE (pl_ent, &plugin_list, next, pln) {
		if (pl_ent->desc.finalize)
			(*pl_ent->desc.finalize)();
		dlclose(pl_ent->handle);
		free_plugin_entry(pl_ent);
	}
	SLIST_INIT(&plugin_list);

	return 0;
}

void
call_plugins(struct vm_entry *vm_ent)
{
	struct plugin_data *pd;

	if (VM_PID(vm_ent) == -1)
		return;

	SLIST_FOREACH (pd, &VM_PLUGIN_DATA(vm_ent), next)
		if (pd->ent->desc.on_status_change)
			(pd->ent->desc.on_status_change)(VM_PTR(vm_ent),
							 pd->pl_conf);
}

int
call_plugin_parser(struct plugin_data_list *head,
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

static void
free_vm_entry(struct vm_entry *vm_ent)
{
	struct net_conf *nc, *nnc;

	STAILQ_FOREACH_SAFE (nc, VM_TAPS(vm_ent), next, nnc)
		free_net_conf(nc);
	/*
	  Basically no events are left on this timing.
	  Delete & free them for safty.
	*/
	stop_waiting_for(vm_entry, vm_ent);
	free(VM_MAPFILE(vm_ent));
	free(VM_BOOTROM(vm_ent));
	free(VM_VARSFILE(vm_ent));
	free(VM_ASCOMPORT(vm_ent));
	free_vm_conf_entry(VM_CONF_ENT(vm_ent));
	free_vm_conf_entry(VM_NEWCONF(vm_ent));
	free(vm_ent);
}

static void
free_vm_list(void)
{
	struct vm_entry *vm_ent, *vmn;

	SLIST_FOREACH_SAFE (vm_ent, &vm_list, next, vmn)
		free_vm_entry(vm_ent);
	SLIST_INIT(&vm_list);
}

void
free_plugin_data(struct plugin_data_list *head)
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
	if (conf_ent == NULL)
		return;
	free_plugin_data(&conf_ent->pl_data);
	free_vm_conf(&conf_ent->conf);
}

int
create_plugin_data(struct plugin_data_list *head)
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

static int
set_vm_method(struct vm_entry *vm_ent, struct vm_conf_entry *conf_ent)
{
	struct plugin_data *pd;
	struct vm_method *m;
	const char *backend = conf_ent->conf.backend;

	SLIST_FOREACH (pd, &conf_ent->pl_data, next)
		if ((m = pd->ent->desc.method) != NULL &&
		    strcmp(m->name, backend) == 0) {
			VM_METHOD(vm_ent) = m;
			VM_PLCONF(vm_ent) = pd->pl_conf;
			return 0;
		}

	return -1;
}

static int
set_loader_method(struct vm_entry *vm_ent, struct vm_conf_entry *conf_ent)
{
	struct plugin_data *pd;
	struct loader_method *m;
	const char *loader = conf_ent->conf.loader;

	if (loader == NULL) {
		VM_LD_METHOD(vm_ent) = NULL;
		return 0;
	}

	SLIST_FOREACH (pd, &conf_ent->pl_data, next)
		if ((m = pd->ent->desc.loader_method) != NULL &&
		    strcmp(m->name, loader) == 0) {
			VM_LD_METHOD(vm_ent) = m;
			VM_PLCONF(vm_ent) = pd->pl_conf;
			return 0;
		}

	return -1;
}

bool
vm_method_exists(char *name)
{
	struct plugin_entry *pl_ent;
	struct vm_method *m;

	SLIST_FOREACH (pl_ent, &plugin_list, next)
		if ((m = pl_ent->desc.method) && strcmp(m->name, name) == 0)
			return true;

	return false;
}

bool
loader_method_exists(char *name)
{
	struct plugin_entry *pl_ent;
	struct loader_method *m;

	SLIST_FOREACH (pl_ent, &plugin_list, next)
		if ((m = pl_ent->desc.loader_method) &&
		    strcmp(m->name, name) == 0)
			return true;

	return false;
}

static struct vm_entry *
create_vm_entry(struct vm_conf_entry *conf_ent)
{
	struct vm_entry *vm_ent;

	if ((vm_ent = calloc(1, sizeof(struct vm_entry))) == NULL)
		return NULL;
	if (set_vm_method(vm_ent, conf_ent) < 0 ||
	    set_loader_method(vm_ent, conf_ent) < 0) {
		free(vm_ent);
		return NULL;
	}
	VM_CONF(vm_ent) = &conf_ent->conf;
	VM_STATE(vm_ent) = TERMINATE;
	VM_PID(vm_ent) = -1;
	VM_INFD(vm_ent) = -1;
	VM_OUTFD(vm_ent) = -1;
	VM_ERRFD(vm_ent) = -1;
	VM_LOGFD(vm_ent) = -1;
	STAILQ_INIT(VM_TAPS(vm_ent));
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
static int
assign_comport(struct vm_entry *vm_ent)
{
	int i, n, max = -1;
	struct dirent **names;
	char *new_com;
	struct vm_entry *e;
	struct vm_conf *conf = VM_CONF(vm_ent);
	struct stat sb;

	if (conf->comport == NULL)
		return 0;

	/* Already assigned */
	if (VM_ASCOMPORT(vm_ent))
		return 0;

	/* If no need to assign comport, copy from `struct vm_conf.comport`. */
	if (strcasecmp(conf->comport, "auto"))
		return (VM_ASCOMPORT(vm_ent) = strdup(conf->comport)) ? 0 : -1;

	/* Get maximum nmdm number of all VMs. */
	SLIST_FOREACH (e, &vm_list, next) {
		max = MAX(get_nmdm_number(VM_CONF(e)->comport), max);
		max = MAX(get_nmdm_number(VM_ASCOMPORT(e)), max);
	}

	/* Get maximum nmdm number in "/dev" directory. */
	if ((n = scandir("/dev", &names, nmdm_selector, NULL)) < 0)
		return -1;

	for (i = 0; i < n; i++) {
		max = MAX(get_nmdm_number(names[i]->d_name), max);
		free(names[i]);
	}
	free(names);

	if (max < gl_conf->nmdm_offset - 1)
		max = gl_conf->nmdm_offset - 1;

	if (asprintf(&new_com, "/dev/nmdm%dB", max + 1) < 0)
		return -1;

	/* Create nmdm device to reserve it. */
	if (stat(new_com, &sb) < 0) {
		ERR("failed to stat %s (%s)\n",  new_com, strerror(errno));
		free(new_com);
		return -1;
	}
	VM_ASCOMPORT(vm_ent) = new_com;

	return 0;
}

static void
cleanup_virtual_machine(struct vm_entry *vm_ent)
{
	remove_taps(VM_PTR(vm_ent));
	VM_CLEANUP(vm_ent);
	VM_STATE(vm_ent) = TERMINATE;
}

int
plugin_cleanup_virtualmachine(PLUGIN_DESC *desc, struct vm *v)
{
	struct vm_entry *vm_ent = (struct vm_entry*)v;
	struct plugin_data *pd;

	if ((pd = lookup_plugin_data(desc, vm_ent)) == NULL)
		return -1;

	pd->poststop_result.state = 0;

	if (get_poststop_state(vm_ent) > 0)
		return 0;

	stop_virtual_machine(vm_ent);
	return 0;
}

static int
load_virtual_machine(struct vm_entry *vm_ent)
{
	int rc;
	struct vm_conf *conf = VM_CONF(vm_ent);
	char *name = conf->name;

	if (VM_LD_METHOD(vm_ent) == NULL)
		return 1;

	if ((rc = VM_LD_LOAD(vm_ent)) < 0) {
		ERR("failed to load vm %s\n", name);
		cleanup_virtual_machine(vm_ent);
		return -1;
	}
	if (rc == 0) {
		if (wait_for_vm(vm_ent) < 0 ||
		    wait_for_vm_output(vm_ent) < 0)
			return -2;
		call_plugins(vm_ent);
		if (conf->loader_timeout > 0 &&
		    set_timer(vm_ent,
			      conf->loader_timeout) < 0) {
			ERR("failed to set timer for vm %s\n",
			    name);
			return -1;
		}
		return 0;
	}
	return rc;
}

int
start_virtual_machine(struct vm_entry *vm_ent)
{
	int rc;
	struct vm_conf *conf;
	char *name;

	if (VM_NEWCONF(vm_ent) != NULL) {
		free_vm_conf_entry(VM_CONF_ENT(vm_ent));
		VM_CONF(vm_ent) = &VM_NEWCONF(vm_ent)->conf;
		VM_NEWCONF(vm_ent) = NULL;
	}

	conf = VM_CONF(vm_ent);
	name = conf->name;

	if (set_vm_method(vm_ent, VM_CONF_ENT(vm_ent)) < 0) {
		ERR("no backend for vm %s\n", name);
		return -1;
	}

	if (VM_STATE(vm_ent) == REMOVE) {
		if (call_poststop_plugins(vm_ent) > 0)
			return 0;
		stop_virtual_machine(vm_ent);
		SLIST_REMOVE(&vm_list, vm_ent, vm_entry, next);
		free_vm_entry(vm_ent);
		return 0;
	}

	if (assign_comport(vm_ent) < 0) {
		ERR("failed to assign comport for vm %s\n", name);
		return -1;
	}

	if (VM_STATE(vm_ent) == TERMINATE) {
		init_plugin_results(vm_ent);
		if (assign_taps(VM_PTR(vm_ent)) < 0)
			return -1;
		if (activate_taps(VM_PTR(vm_ent)) < 0) {
			remove_taps(VM_PTR(vm_ent));
			return -1;
		}
		if ((rc = call_prestart_plugins(vm_ent)) > 0)
			return 0;
		if (rc < 0) {
			ERR("%s\n", "failed to call prestart plugins");
			remove_taps(VM_PTR(vm_ent));
			return -1;
		}
	}
	if (VM_STATE(vm_ent) == TERMINATE ||
	    VM_STATE(vm_ent) == PRESTART) {
		rc = load_virtual_machine(vm_ent);
		if (rc <= -2)
			goto force_kill;
		if (rc <= 0)
			return rc;
		/* FALLTHROUGH */
	}

	if (VM_LD_METHOD(vm_ent))
		VM_LD_CLEANUP(vm_ent);

	if (VM_START(vm_ent) < 0) {
		ERR("failed to start vm %s\n", name);
		cleanup_virtual_machine(vm_ent);
		return -1;
	}

	if (wait_for_vm(vm_ent) < 0 || wait_for_vm_output(vm_ent) < 0)
		goto force_kill;

	if (VM_STATE(vm_ent) == RUN)
		INFO("start vm %s\n", name);

	call_plugins(vm_ent);

	if (conf->err_logfile && VM_LOGFD(vm_ent) == -1)
		VM_LOGFD(vm_ent) = open_err_logfile(conf);

	return 0;

force_kill:
	ERR("failed to set kevent for vm %s\n", name);
	/*
	 * Force to kill bhyve.
	 * If this error happens,
	 * we can't manage bhyve process at all.
	 */
	VM_POWEROFF(vm_ent);
	waitpid(VM_PID(vm_ent), NULL, 0);
	cleanup_virtual_machine(vm_ent);
	return -1;
}

static int
on_sigterm(int ident __unused, void *data __unused)
{
	INFO("%s\n", "stopping daemon");
	sigterm++;
	return 0;
}

static int
on_sighup(int ident __unused, void *data __unused)
{
	INFO("%s\n", "reload config file");
	reload_virtual_machines();
	return 0;
}

static int
start_virtual_machines(void)
{
	struct vm_conf_entry *conf_ent;
	struct vm_entry *vm_ent;
	struct kevent sigev[3];
	static event_call_back cb[3] = {on_sigterm, on_sigterm, on_sighup};
	static void *data[3] = {NULL, NULL, NULL};

	EV_SET(&sigev[0], SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&sigev[1], SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&sigev[2], SIGHUP, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);

	if (register_events(sigev, cb, data, 3) < 0)
		return -1;

	LIST_FOREACH (conf_ent, &vm_conf_list, next) {
		if ((vm_ent = create_vm_entry(conf_ent)) == NULL)
			return -1;
		if (VM_CONF(vm_ent)->boot == NO)
			continue;
		if (VM_CONF(vm_ent)->boot_delay > 0) {
			if (set_timer(vm_ent, VM_CONF(vm_ent)->boot_delay) < 0)
				ERR("failed to set boot delay timer for vm %s\n",
				    VM_CONF(vm_ent)->name);
			continue;
		}
		start_virtual_machine(vm_ent);
	}

	return 0;
}

static void
stop_virtual_machine(struct vm_entry *vm_ent)
{
	stop_waiting_for(vm_output_and_timers, vm_ent);
	cleanup_virtual_machine(vm_ent);
	call_plugins(vm_ent);
	if (direct_run_mode)
		sigterm++;
	VM_PID(vm_ent) = -1;
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

void
copy_plugin_data(struct vm_conf_entry *dst, struct vm_conf_entry *src)
{
	struct plugin_data *da, *db;

	for (da = SLIST_FIRST(&dst->pl_data), db = SLIST_FIRST(&src->pl_data);
	     da != NULL && db != NULL && da->ent == db->ent;
	     da = SLIST_NEXT(da, next), db = SLIST_NEXT(db, next))
		if (da->ent->desc.on_reload_config)
			da->ent->desc.on_reload_config(da->pl_conf,
						       db->pl_conf);
}

static int
reload_virtual_machines(void)
{
	struct vm_conf *conf;
	struct vm_conf_entry *conf_ent;
	struct vm_entry *vm_ent, *vmn;
	struct vm_conf_list new_list = LIST_HEAD_INITIALIZER();

	if (load_config_file(&new_list, false) < 0)
		return -1;

	/* make sure tmp_conf_ent is NULL */
	SLIST_FOREACH (vm_ent, &vm_list, next)
		VM_TMPCONF(vm_ent) = NULL;

	LIST_FOREACH (conf_ent, &new_list, next) {
		conf = &conf_ent->conf;
		vm_ent = lookup_vm_by_name(conf->name);
		if (vm_ent == NULL) {
			if ((vm_ent = create_vm_entry(conf_ent)) == NULL)
				return -1;
			VM_TMPCONF(vm_ent) = conf_ent;
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
		}
		if (VM_LOGFD(vm_ent) != -1 &&
		    VM_CONF(vm_ent)->err_logfile != NULL) {
			VM_CLOSE(vm_ent, LOGFD);
			VM_LOGFD(vm_ent) = open_err_logfile(conf);
		}
		copy_plugin_data(conf_ent, VM_CONF_ENT(vm_ent));
		VM_TMPCONF(vm_ent) = conf_ent;
		if (conf->boot != NO && conf->reboot_on_change &&
		    compare_vm_conf_entry(conf_ent, VM_CONF_ENT(vm_ent)) != 0) {
			switch (VM_STATE(vm_ent)) {
			case TERMINATE:
				set_timer(vm_ent, MAX(conf->boot_delay, 1));
				break;
			case LOAD:
			case RUN:
				INFO("reboot vm %s\n", conf->name);
				VM_ACPI_POWEROFF(vm_ent);
				set_timer(vm_ent, conf->stop_timeout);
				VM_STATE(vm_ent) = RESTART;
				break;
			case STOP:
				VM_STATE(vm_ent) = RESTART;
			default:
				break;
			}
			continue;
		}
		if (VM_TMPCONF(vm_ent)->conf.boot == VM_CONF(vm_ent)->boot)
			continue;
		switch (conf->boot) {
		case NO:
			if (VM_STATE(vm_ent) == LOAD ||
			    VM_STATE(vm_ent) == RUN) {
				INFO("acpi power off vm %s\n", conf->name);
				VM_ACPI_POWEROFF(vm_ent);
				set_timer(vm_ent, conf->stop_timeout);
				VM_STATE(vm_ent) = STOP;
			} else if (VM_STATE(vm_ent) == RESTART)
				VM_STATE(vm_ent) = STOP;
			break;
		case ALWAYS:
		case YES:
			if (VM_STATE(vm_ent) == TERMINATE) {
				VM_NEWCONF(vm_ent) = conf_ent;
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
		if (VM_TMPCONF(vm_ent) == NULL) {
			switch (VM_STATE(vm_ent)) {
			case LOAD:
			case RUN:
				conf = VM_CONF(vm_ent);
				INFO("acpi power off vm %s\n", conf->name);
				VM_ACPI_POWEROFF(vm_ent);
				set_timer(vm_ent, conf->stop_timeout);
				/* FALLTHROUGH */
			case STOP:
			case REMOVE:
			case RESTART:
			case PRESTART:
			case POSTSTOP:
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
			if (VM_CONF_ENT(vm_ent) == VM_TMPCONF(vm_ent)) {
				/* tmp_conf_ent is created just before
				   in this function. */
				VM_TMPCONF(vm_ent) = NULL;
				continue;
			}
			free_vm_conf_entry(VM_NEWCONF(vm_ent));
			VM_NEWCONF(vm_ent) = VM_TMPCONF(vm_ent);
			VM_TMPCONF(vm_ent) = NULL;
		}

	LIST_INIT(&vm_conf_list);
	LIST_CONCAT(&vm_conf_list, &new_list, vm_conf_entry, next);

	return 0;
}

static int
event_loop(void)
{
	struct kevent ev;
	struct event *event;
	int n, do_remove;
	struct timespec *to, timeout;

	while (sigterm == 0) {
		to = calc_timeout(COMMAND_TIMEOUT_SEC, &timeout);
		if ((n = kevent_get(&ev, 1, to)) < 0) {
			ERR("kevent failure (%s)\n", strerror(errno));
			return -1;
		}
		if (n == 0) {
			close_timeout_sock_buf(COMMAND_TIMEOUT_SEC);
			continue;
		}
		if (ev.udata == NULL) {
			ERR("recieved unexpcted event! (%d)", ev.filter);
			continue;
		}
		event = ev.udata;
		do_remove = (event->kev.flags & EV_ONESHOT) ? 1 : 0;
		if (event->cb && (*event->cb)(ev.ident, event->data) < 0)
			ERR("%s\n", "callback failed");
		if (do_remove) {
			LIST_REMOVE(event, next);
			free(event);
		}
	}

	return 0;
}

static int
stop_virtual_machines(void)
{
	struct kevent ev;
	struct event *event;
	struct vm_entry *vm_ent;
	int do_remove, count = 0;

	SLIST_FOREACH (vm_ent, &vm_list, next) {
		if (VM_STATE(vm_ent) == LOAD || VM_STATE(vm_ent) == RUN) {
			count++;
			VM_ACPI_POWEROFF(vm_ent);
			set_timer(vm_ent, VM_CONF(vm_ent)->stop_timeout);
		}
	}

	while (count_plugin_process_events() + count > 0) {
		if (kevent_get(&ev, 1, NULL) < 0)
			return -1;
		if (ev.udata == NULL)
			continue;
		event = ev.udata;
		if (event->type == EVENT && event->kev.filter == EVFILT_PROC)
			count--;
		do_remove = (event->kev.flags & EV_ONESHOT) ? 1 : 0;
		if (event->cb && (*event->cb)(ev.ident, event->data) < 0)
			ERR("%s\n", "callback failed");
		if (do_remove) {
			LIST_REMOVE(event, next);
			free(event);
		}
	}
#if __FreeBSD_version < 1400059
	// waiting for vm memory is actually freed in the kernel.
	sleep(3);
#endif

	return 0;
}

static int
parse_opt(int argc, char *argv[])
{
	int ch;

	while ((ch = getopt(argc, argv, "Ff:P:p:m:v")) != -1) {
		switch (ch) {
		case 'F':
			gl_conf->foreground = 1;
			break;
		case 'f':
			free(gl_conf->config_file);
			gl_conf->config_file = strdup(optarg);
			break;
		case 'P':
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
		case 'v':
			printf("BMD (Bhyve Management Daemon) version %s\n",
			       BMD_VERSION);
			exit(0);
		default:
			fprintf(stderr,
			    "usage: %s [-F] [-f config file] "
			    "[-p plugin directory] \n"
			    "\t[-m unix domain socket permission] \n"
			    "\t[-P pid file]\n"
			    "\t[-v]\n",
			    argv[0]);
			return -1;
		}
	}

	if (gl_conf->foreground == 0)
		daemon(0, 0);

	return 0;
}

static bool
strendswith(const char *t, const char *s)
{
	const char *p;

	return ((p = strstr(t, s)) != NULL) && (strlen(p) == strlen(s));
}

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
		free_gl_conf();
		return 1;
	}

	if (strendswith(argv[0], "ctl"))
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
		WARN("%s\n", "cannot protect from OOM killer");

	if (load_config_file(&vm_conf_list, true) < 0 ||
	    create_eventq() < 0)
		return 1;

	if ((cmd_sock = create_command_server(gl_conf)) < 0) {
		ERR("cannot bind %s\n", gl_conf->cmd_socket_path);
		return 1;
	}

	if (gl_conf->foreground == 0 &&
	    (fp = fopen(gl_conf->pid_path, "w")) != NULL) {
		fprintf(fp, "%d\n", getpid());
		fclose(fp);
	}

	INFO("%s\n", "start daemon");

	if (start_virtual_machines() < 0 ||
	    wait_for_cmd_sock(cmd_sock) < 0)
		ERR("%s\n", "failed to start virtual machines");
	else
		event_loop();

	unlink(gl_conf->cmd_socket_path);
	close(cmd_sock);

	stop_virtual_machines();
	free_vm_list();
	close(eventq);
	free_events();
	remove_plugins();
	free_id_list();
	free_global_vars();
	free_gl_conf();
	INFO("%s\n", "quit daemon");
	LOG_CLOSE();
	return 0;
}

int
direct_run(const char *name, bool install, bool single)
{
	struct vm_conf *conf;
	struct vm_conf_entry *conf_ent;
	struct vm_entry *vm_ent;
	struct kevent sigev[3];
	static event_call_back cb[3] = {on_sigterm, on_sigterm, on_sighup};
	static void *data[3] = {NULL, NULL, NULL};
	LOG_OPEN_PERROR();

	direct_run_mode = true;

	if (create_eventq() < 0)
		return 1;

	conf_ent = lookup_vm_conf(name);
	if (conf_ent == NULL) {
		ERR("no such VM %s\n", name);
		return 1;
	}

	conf = &conf_ent->conf;
	free(conf->comport);
	conf->comport = strdup("stdio");
	conf->install = install;
	conf->boot = ONESHOT;
	set_single_user(conf, single);

	vm_ent = create_vm_entry(conf_ent);
	if (vm_ent == NULL) {
		free_vm_conf_entry(conf_ent);
		return 1;
	}

	EV_SET(&sigev[0], SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&sigev[1], SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&sigev[2], SIGHUP, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);

	if (register_events(sigev, cb, data, 3) < 0)
		return 1;

	if (start_virtual_machine(vm_ent) < 0)
		goto err;

	event_loop();

	free_vm_entry(vm_ent);
	free_events();
	remove_plugins();
	free_id_list();
	close(eventq);
	free_global_vars();
	free_gl_conf();
	return 0;
err:
	stop_virtual_machine(vm_ent);
	free_vm_entry(vm_ent);
	free_events();
	remove_plugins();
	free_id_list();
	close(eventq);
	free_global_vars();
	free_gl_conf();
	return 1;
}

int
compare_vm_conf_entry(struct vm_conf_entry *a, struct vm_conf_entry *b)
{
	int rc;
	struct plugin_data *pa, *pb;

	if ((rc = compare_vm_conf(&a->conf, &b->conf)) != 0)
		return rc;

	for (pa = SLIST_FIRST(&a->pl_data), pb = SLIST_FIRST(&b->pl_data);
	     pa != NULL && pb != NULL;
	     pa = SLIST_NEXT(pa, next), pb = SLIST_NEXT(pb, next))
		if ((rc = compare_nvlist(pa->pl_conf, pb->pl_conf)) != 0)
			return rc;

	return 0;
}
