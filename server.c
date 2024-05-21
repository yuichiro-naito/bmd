#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/ucred.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <netinet/in.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <pwd.h>

#include "bmd.h"
#include "log.h"
#include "server.h"
#include "vm.h"

static struct sock_list sock_list = LIST_HEAD_INITIALIZER();

/**
   Note: Don't use a pointer to refer to the sock_buf structure. Use
   sock_buf_id instead. The same pointer value will often be reused after
   freeing and reallocating the strsucture. We can't know if the sock_buf is
   freed and re-allocated or keeps existing, from the pointer value.
   For the same reason, Don't use a pointer to refer to the com_opener
   structure. Use com_opener_id instead.
 */
LIST_HEAD(com_opener_head, com_opener);
struct com_opener {
	LIST_ENTRY(com_opener) next;
	com_opener_id id;
	int fd;
	int sock;
	sock_buf_id sid;
	pid_t pid;
	nvlist_t *res;
};
static struct com_opener_head com_opener_list = LIST_HEAD_INITIALIZER();

static struct sock_buf *
lookup_sock_buf(sock_buf_id id)
{
	struct sock_buf *p;
	LIST_FOREACH (p, &sock_list, next)
		if (p->id == id)
			return p;
	return NULL;
}

struct sock_buf *
create_sock_buf(int fd)
{
	struct sock_buf *r;
	socklen_t sz;
	static sock_buf_id id = 0;

	if ((r = calloc(1, sizeof(*r))) == NULL)
		return NULL;
	r->id = id++;
	r->fd = fd;
	time(&r->event_time);
	r->cid = -1;

	sz = sizeof(r->peer);
	if  (getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, &r->peer, &sz) < 0)
		r->peer.cr_uid = UID_NOBODY;

	r->res_fd = -1;
	LIST_INSERT_HEAD(&sock_list, r, next);
	return r;
}

static void
destroy_com_opener(struct com_opener *cp)
{
	struct sock_buf *sb;

	LIST_REMOVE(cp, next);
	if ((sb = lookup_sock_buf(cp->sid)) != NULL)
		sb->cid = -1;
	free(cp);
}

static void
stop_com_opener(struct com_opener *cp)
{
	kill(cp->pid, SIGTERM);
}
void
destroy_sock_buf(struct sock_buf *p)
{
	struct com_opener *cp;

	if (p == NULL)
		return;
	LIST_REMOVE(p, next);
	if (p->cid != -1 && (cp = lookup_com_opener(p->cid)))
		stop_com_opener(cp);
	close(p->fd);
	if (p->res_fd != -1)
		close(p->res_fd);
	free(p->buf);
	free(p->res_buf);
	free(p);
}

struct timespec *
calc_timeout(int timeout, struct timespec *ts)
{
	struct sock_buf *p;
	long t;
	time_t s;

	if (LIST_EMPTY(&sock_list) || ts == NULL)
		return NULL;

	s = LIST_FIRST(&sock_list)->event_time;
	LIST_FOREACH (p, &sock_list, next)
		if (p->event_time < s)
			s = p->event_time;

	if ((t = s + timeout - time(NULL)) < 0)
		return NULL;

	ts->tv_sec = t;
	ts->tv_nsec = 0;
	return ts;
}

void
close_timeout_sock_buf(int timeout)
{
	struct sock_buf *p, *n;
	time_t now = time(NULL);

	LIST_FOREACH_SAFE (p, &sock_list, next, n)
		if (p->event_time + timeout <= now) {
			if (p->cid == -1)
				destroy_sock_buf(p);
			else
				p->event_time = now;
		}
}

void
clear_sock_buf(struct sock_buf *p)
{
	free(p->buf);
	p->buf = NULL;
	p->read_state = 0;
	p->buf_size = 0;
	p->read_size = 0;
	p->read_bytes = 0;
}

void
clear_send_sock_buf(struct sock_buf *p)
{
	free(p->res_buf);
	p->sent_size = 0;
	p->res_fd = -1;
	p->res_buf = NULL;
	p->res_size = 0;
	p->res_bytes = 0;
}

/**
 * return value:
 * -1 : error
 *  0 : closed
 *  1 : continue
 *  2 : finished sending
 */
int
send_sock_buf(struct sock_buf *p)
{
	int size, rc;
	ssize_t n;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct iovec iov[2];
	char size_buf[4];

	if (p->res_size == 0 || p->sent_size == p->res_size + sizeof(size_buf))
		return 2;

	memset(&msg, 0, sizeof(msg));
	if (p->sent_size < sizeof(size_buf)) {
		size = htonl(p->res_size);
		memcpy(size_buf, &size, sizeof(size_buf));
		iov[0].iov_base = size_buf + p->sent_size;
		iov[0].iov_len = sizeof(size_buf) - p->sent_size;
		iov[1].iov_base = p->res_buf;
		iov[1].iov_len = p->res_size;
		msg.msg_iov = iov;
		msg.msg_iovlen = 2;
	} else {
		iov[0].iov_base = p->res_buf + p->sent_size - sizeof(size_buf);
		iov[0].iov_len = p->res_size - p->sent_size + sizeof(size_buf);
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
	}

	msg.msg_flags = MSG_DONTWAIT;

	if (p->res_fd != -1) {
		msg.msg_controllen = CMSG_SPACE(sizeof(int));
		msg.msg_control = calloc(1, msg.msg_controllen);
		if (msg.msg_control == NULL)
			return -1;

		cmsg = msg.msg_control;
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(p->res_fd));
		memcpy(CMSG_DATA(cmsg), &p->res_fd, sizeof(p->res_fd));
	}

retry:
	if ((n = sendmsg(p->fd, &msg, MSG_DONTWAIT)) < 0) {
		switch (errno) {
		case EINTR:
			goto retry;
		case EAGAIN:
			rc = 1;
			goto ret;
		default:
			rc = -1;
			goto ret;
		}
	}
	if (n == 0) {
		rc = 0;
		goto ret;
	}
	time(&p->event_time);
	p->sent_size += n;
	rc = (p->sent_size == p->res_bytes + sizeof(size_buf)) ? 2 : 1;
ret:
	if (p->res_fd != -1) {
		free(msg.msg_control);
		close(p->res_fd);
		p->res_fd = -1;
	}
	return rc;
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
	uint32_t t;
	char buf[1];

	if (sb->read_state == 0) {
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

	time(&sb->event_time);
	nread += n;
	if (sb->read_state == 0) {
		sb->read_size = nread;
		if (nread == size) {
			sb->read_state = 1;
			memcpy(&t, sb->size, sizeof(uint32_t));
			sb->buf_size = ntohl(t);
			if (sb->buf_size > 1024 * 1024)
				return -1;
			if ((sb->buf = malloc(sb->buf_size)) == NULL)
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
	struct addrinfo hints, *r;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_LOCAL;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(gc->cmd_socket_path, NULL, &hints, &r))
		return -1;

	while ((s = socket(r->ai_family, r->ai_socktype, r->ai_protocol)) < 0)
		if (errno != EAGAIN && errno != EINTR)
			goto err;

	while (connect(s, r->ai_addr, r->ai_addrlen) < 0)
		if (errno != EAGAIN && errno != EINTR)
			goto err;

	freeaddrinfo(r);
	return s;
err:
	freeaddrinfo(r);
	if (s != -1)
		close(s);
	return -1;
}

int
create_command_server(const struct global_conf *gc)
{
	int s;
	void *set = NULL;
	struct stat st;
	struct addrinfo hints, *r;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_LOCAL;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if (getaddrinfo(gc->cmd_socket_path, NULL, &hints, &r))
		return -1;

	while ((s = socket(r->ai_family, r->ai_socktype | SOCK_CLOEXEC,
			   r->ai_protocol)) < 0)
		if (errno != EAGAIN && errno != EINTR)
			goto err;

	while (bind(s, r->ai_addr, r->ai_addrlen) < 0)
		if (errno != EAGAIN && errno != EINTR)
			goto err;

	while (listen(s, 5) < 0)
		if (errno != EAGAIN && errno != EINTR)
			goto err;

	if (gc->unix_domain_socket_mode == NULL ||
	    stat(gc->cmd_socket_path, &st) < 0 ||
	    (set = setmode(gc->unix_domain_socket_mode)) == NULL) {
		freeaddrinfo(r);
		return s;
	}

	if (chmod(gc->cmd_socket_path, getmode(set, st.st_mode)) < 0)
		goto err;

	freeaddrinfo(r);
	free(set);
	return s;
err:
	freeaddrinfo(r);
	free(set);
	if (s != -1)
		close(s);
	return -1;
}

int
accept_command_socket(int s0)
{
	int s;

	while ((s = accept4(s0, NULL, 0, SOCK_CLOEXEC)) < 0)
		if (errno != EAGAIN && errno != EINTR)
			return -1;

	return s;
}

static int
search_and_replace_vm_conf(struct vm_entry *vm_ent)
{
	char *name = VM_CONF(vm_ent)->name;
	struct vm_conf_entry *conf_ent, *cen, *ret = NULL;
	struct vm_conf_list list = LIST_HEAD_INITIALIZER();

	if (load_config_file(&list, false) < 0) {
		ERR("%s\n", "failed to load VM config files");
		return -1;
	}

	LIST_FOREACH_SAFE (conf_ent, &list, next, cen)
		if (strcmp(conf_ent->conf.name, name) == 0)
			ret = conf_ent;
		else
			free_vm_conf_entry(conf_ent);

	if (ret == NULL) {
		INFO("%s\n", "discard the last loaded configurations\n");
		return -1;
	}

	if (compare_vm_conf_entry(ret, VM_CONF_ENT(vm_ent)) != 0) {
		LIST_REMOVE(VM_CONF_ENT(vm_ent), next);
		LIST_INSERT_HEAD(&vm_conf_list, ret, next);
		free_vm_conf_entry(VM_CONF_ENT(vm_ent));
		VM_CONF(vm_ent) = &ret->conf;
		INFO("changes are found. update %s configuration\n", name);
	} else {
		free_vm_conf_entry(ret);
		INFO("no changes are found for %s. keep existing configurations.\n", name);
	}


	return 0;
}

static char *
get_peer_comport(const char *comport)
{
	int i;
	char *peer;

	/* A null modem device has at least 11 characters. */
	if (comport == NULL ||
	    (i = strlen(comport) - 1 ) < 10)
		return 0;

	if ((peer = strdup(comport)) == NULL)
		return NULL;

	switch (peer[i]) {
	case 'A':
		peer[i] = 'B';
		break;
	case 'B':
		peer[i] = 'A';
		break;
	default:
		break;
	}

	return peer;
}

static int
chown_comport(const char *comport, struct xucred *ucred)
{
	int i, rc;
	struct stat st;
	char *fn = get_peer_comport(comport);

	if (fn == NULL)
		return 0;

	for (i = 0; i < 5; i++) {
		if (stat(fn, &st) < 0 ||
		    chown(fn, ucred->cr_uid, st.st_gid) < 0) {
			rc = -1;
			usleep(1000);
			continue;
		}
		rc = 0;
		break;
	}

	free(fn);
	return rc;
}

static int
open_comport(const char *comport)
{
	int fd;
	char *fn;

	if ((fn = get_peer_comport(comport)) == NULL)
		return -1;
	if ((fd = open(fn, O_RDWR)) < 0)
		goto err;
	if (flock(fd, LOCK_EX | LOCK_NB) < 0)
		goto err2;

	free(fn);
	return fd;
err2:
	close(fd);
err:
	free(fn);
	return -1;
}

struct com_opener *
lookup_com_opener(com_opener_id id)
{
	struct com_opener *p;
	LIST_FOREACH (p, &com_opener_list, next)
		if (p->id == id)
			return p;
	return NULL;
}

static struct com_opener *
create_com_opener(sock_buf_id sid)
{
	struct com_opener *cp;
	static com_opener_id id = 0;

	if ((cp = malloc(sizeof(*cp))) == NULL)
		return NULL;
	cp->id = id++;
	cp->sid = sid;
	LIST_INSERT_HEAD(&com_opener_list, cp, next);
	return cp;
}

static int
on_read_open_comport(int ident, void *data)
{
	struct com_opener *cp = data;

	cp->fd = recv_fd(ident);
	send_ack(ident);

	return 0;
}

static int
on_exit_open_comport(int ident __unused, void *data)
{
	int status;
	struct com_opener *cp = data;
	struct sock_buf *sb;
	nvlist_t *res = cp->res;

	while (waitpid(cp->pid, &status, 0) < 0)
		if (errno != EINTR)
			break;
	if (! WIFEXITED(status) || WEXITSTATUS(status) != 0)
		cp->fd = -1;

	close(cp->sock);

	/* check if sock_buf is already closed. */
	if ((sb = lookup_sock_buf(cp->sid)) == NULL) {
		nvlist_destroy(res);
		if (cp->fd >= 0)
			close(cp->fd);
		destroy_com_opener(cp);
		return 0;
	}
	sb->res_fd = cp->fd;

	sb->res_buf = nvlist_pack(res, &sb->res_size);
	if (sb->res_buf == NULL) {
		nvlist_destroy(res);
		res = nvlist_create(0);
		nvlist_add_bool(res, "error", true);
		nvlist_add_string(res, "reason", "nvlist_pack error");
		sb->res_buf = nvlist_pack(res, &sb->res_size);
		if (sb->res_buf == NULL) {
			nvlist_destroy(res);
			destroy_com_opener(cp);
			return -1;
		}
	}
	sb->res_bytes = 0;
	nvlist_destroy(res);
	destroy_com_opener(cp);
	clear_sock_buf(sb);
	set_sock_buf_wait_flags(sb, EV_DISABLE, EV_ENABLE);

	return 0;
}

static int
delayed_open_comport(struct sock_buf *sb, const char *comport, nvlist_t *res)
{
	pid_t pid;
	int socks[2];
	struct com_opener *cp;
	struct kevent kev[2];
	static event_call_back cb[2] = {on_read_open_comport, on_exit_open_comport};
	void *data[2];
	sigset_t nmask;

	if ((cp = create_com_opener(sb->id)) == NULL)
		return -1;

	if (socketpair(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, socks) < 0) {
		destroy_com_opener(cp);
		return -1;
	}

	if ((pid = fork()) < 0) {
		close(socks[0]);
		close(socks[1]);
		destroy_com_opener(cp);
		return -1;
	}

	if (pid == 0) {
		sigemptyset(&nmask);
		sigaddset(&nmask, SIGTERM);
		sigprocmask(SIG_UNBLOCK, &nmask, NULL);
		close(socks[0]);
		send_fd(socks[1], open_comport(comport));
		recv_ack(socks[1]);
		close(socks[1]);
		exit(0);
	}

	close(socks[1]);
	cp->pid = pid;
	cp->res = res;
	cp->sock = socks[0];
	cp->sid = sb->id;
	EV_SET(&kev[0], socks[0], EVFILT_READ, EV_ADD | EV_ONESHOT, 0, 0,
	       NULL);
	EV_SET(&kev[1], pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT, 0,
	       NULL);
	data[0] = cp;
	data[1] = cp;

	if (register_events(kev, cb, data, 2) < 0) {
		ERR("failed to open comport (%s)\n", strerror(errno));
		kill(pid, SIGKILL);
		while (waitpid(pid, NULL, 0) < 0)
			if (errno != EINTR)
				break;
		destroy_com_opener(cp);
		close(socks[0]);
		return -1;
	}

	sb->cid = cp->id;
	return 0;
}

static int
check_owner(struct vm_entry *vm_ent, struct xucred *ucred)
{
	int64_t owner = VM_CONF(vm_ent)->owner;
	int64_t group = VM_CONF(vm_ent)->group;
	int i;

	if (ucred->cr_uid == 0 || ucred->cr_uid == (uid_t)owner)
		return 0;

	if (group == -1)
		return -1;

	for (i = 0; i < ucred->cr_ngroups; i++)
		if (ucred->cr_groups[i] == (gid_t)group)
			return 0;

	return -1;
}

/*
 * The argument `style` must be one of followings.
 *  -  0 = boot
 *  -  1 = install
 */
static nvlist_t *
boot0_command(struct sock_buf *s __unused, const nvlist_t *nv, int style,
    struct xucred *ucred)
{
	const char *name, *reason;
	struct vm_entry *vm_ent = NULL;
	nvlist_t *res;
	bool error = false;

	if (style < 0) {
		error = true;
		reason = "internal error";
	}

	if ((name = nvlist_get_string(nv, "name")) == NULL ||
	    (vm_ent = lookup_vm_by_name(name)) == NULL ||
	    (check_owner(vm_ent, ucred) != 0)) {
		error = true;
		reason = "VM not found";
		goto ret;
	}

	if (style < 2 && VM_STATE(vm_ent) != TERMINATE) {
		error = true;
		reason = "already running";
		goto ret;
	}

	if (search_and_replace_vm_conf(vm_ent) < 0) {
		error = true;
		reason = "failed to load config file";
		goto ret;
	}

	switch (style) {
	case 0:
		break;
	case 1:
		VM_CONF(vm_ent)->install = true;
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
boot_command(struct sock_buf *s, const nvlist_t *nv,  struct xucred *ucred)
{
	return boot0_command(s, nv, 0, ucred);
}

static nvlist_t *
install_command(struct sock_buf *s, const nvlist_t *nv,  struct xucred *ucred)
{
	return boot0_command(s, nv, 1, ucred);
}

static nvlist_t *
showcomport_command(struct sock_buf *s, const nvlist_t *nv,
		    struct xucred *ucred)
{
	const char *name, *reason;
	struct vm_entry *vm_ent;
	int rc = -1;
	nvlist_t *res;
	bool error = false;
	char *comport;

	res = nvlist_create(0);

	if ((name = nvlist_get_string(nv, "name")) == NULL ||
	    (vm_ent = lookup_vm_by_name(name)) == NULL ||
	    (check_owner(vm_ent, ucred) != 0)) {
		error = true;
		reason = "VM not found";
		goto ret;
	}

	comport = VM_ASCOMPORT(vm_ent) ? VM_ASCOMPORT(vm_ent) : VM_CONF(vm_ent)->comport;

	if (VM_STATE(vm_ent) == PRESTART || VM_STATE(vm_ent) == LOAD ||
	    VM_STATE(vm_ent) == RUN) {
		chown_comport(comport, ucred);

		if ((rc = delayed_open_comport(s, comport, res)) < 0) {
			error = true;
			reason = "failed to open comport";
			goto ret;
		}
	}

	nvlist_add_string(res, "comport", comport ? comport : "(null)");

ret:
	nvlist_add_bool(res, "error", error);
	if (error)
		nvlist_add_string(res, "reason", reason);
	return rc == 0 ? NULL : res;
}

static nvlist_t *
showvgaport_command(struct sock_buf *s __unused, const nvlist_t *nv __unused,
    struct xucred *ucred)
{
	const char *name, *reason;
	struct vm_entry *vm_ent;
	nvlist_t *res;
	bool error = false;
	char vgaport[128];

	res = nvlist_create(0);

	if ((name = nvlist_get_string(nv, "name")) == NULL ||
	    (vm_ent = lookup_vm_by_name(name)) == NULL ||
	    (check_owner(vm_ent, ucred) != 0)) {
		error = true;
		reason = "VM not found";
		goto ret;
	}

	if (VM_CONF(vm_ent)->fbuf->enable &&
	    snprintf(vgaport, sizeof(vgaport), "%s %d",
		     VM_CONF(vm_ent)->fbuf->ipaddr,
		     VM_CONF(vm_ent)->fbuf->port) > 0)
		nvlist_add_string(res, "vgaport", vgaport);
	else
		nvlist_add_string(res, "vgaport", "(disabled)");

ret:
	nvlist_add_bool(res, "error", error);
	if (error)
		nvlist_add_string(res, "reason", reason);
	return res;
}

static nvlist_t *
list_command(struct sock_buf *s __unused, const nvlist_t *nv __unused,
	     struct xucred *ucred)
{
	size_t i, count = 0;
	const char *reason;
	nvlist_t *res, *p;
	nvlist_t **list = NULL;
	struct vm_entry *vm_ent;
	bool error = false;
	struct passwd *pwd;
	const static char *state_string[] = { "STOP", "LOAD", "RUN",
					      "TERMINATING", "TERMINATING", "REBOOTING",
					      "PRESTART", "POSTSTOP"};

	res = nvlist_create(0);

	SLIST_FOREACH (vm_ent, &vm_list, next) {
		if (check_owner(vm_ent, ucred) != 0)
			continue;
		count++;
	}

	if (count == 0)
		goto ret;

	if ((list = malloc(count * sizeof(nvlist_t *))) == NULL) {
		error = true;
		reason = "cannot allocate memory";
		goto ret;
	}

	i = 0;
	SLIST_FOREACH (vm_ent, &vm_list, next) {
		if (check_owner(vm_ent, ucred) != 0)
			continue;
		p = nvlist_create(0);
		nvlist_add_stringf(p, "id", "%u", VM_CONF(vm_ent)->id);
		nvlist_add_string(p, "name", VM_CONF(vm_ent)->name);
		nvlist_add_stringf(p, "ncpu", "%d", VM_CONF(vm_ent)->ncpu);
		nvlist_add_string(p, "memory", VM_CONF(vm_ent)->memory);
		nvlist_add_string(p, "loader",
				  VM_CONF(vm_ent)->loader ?
				  VM_CONF(vm_ent)->loader :
				  VM_CONF(vm_ent)->backend);
		nvlist_add_string(p, "state", state_string[VM_STATE(vm_ent)]);
		if ((pwd = getpwuid(VM_CONF(vm_ent)->owner)) == NULL)
			nvlist_add_string(p, "owner", "nobody");
		else
			nvlist_add_string(p, "owner", pwd->pw_name);
		list[i++] = p;
	}

	nvlist_move_nvlist_array(res, "vm_list", list, count);
ret:
	nvlist_add_bool(res, "error", error);
	if (error)
		nvlist_add_string(res, "reason", reason);
	return res;
}

static nvlist_t *
vm_down_command(struct sock_buf *s __unused, const nvlist_t *nv __unused,
		int how, struct xucred *ucred)
{
	const char *name, *reason;
	struct vm_entry *vm_ent;
	struct vm_conf *conf;
	nvlist_t *res;
	bool error = false;

	if ((name = nvlist_get_string(nv, "name")) == NULL ||
	    (vm_ent = lookup_vm_by_name(name)) == NULL ||
	    (check_owner(vm_ent, ucred) != 0)) {
		error = true;
		reason = "VM not found";
		goto ret;
	}

	if (VM_STATE(vm_ent) != LOAD && VM_STATE(vm_ent) != RUN)
		goto ret;

	conf = VM_CONF(vm_ent);
	switch (how) {
	case 0:
		INFO("stop vm %s\n", conf->name);
		VM_ACPI_POWEROFF(vm_ent);
		set_timer(vm_ent, conf->stop_timeout);
		VM_STATE(vm_ent) = STOP;
		break;
	case 1:
		INFO("reset vm %s\n", conf->name);
		VM_RESET(vm_ent);
		break;
	case 2:
		INFO("poweroff vm %s\n", conf->name);
		VM_POWEROFF(vm_ent);
		VM_STATE(vm_ent) = STOP;
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
shutdown_command(struct sock_buf *s, const nvlist_t *nv,  struct xucred *ucred)
{
	return vm_down_command(s, nv, 0, ucred);
}

static nvlist_t *
reset_command(struct sock_buf *s, const nvlist_t *nv,  struct xucred *ucred)
{
	return vm_down_command(s, nv, 1, ucred);
}

static nvlist_t *
poweroff_command(struct sock_buf *s, const nvlist_t *nv,  struct xucred *ucred)
{
	return vm_down_command(s, nv, 2, ucred);
}

typedef nvlist_t *(*cfunc)(struct sock_buf *s, const nvlist_t *nv,
			   struct xucred *ucred);

struct command_entry {
	const char *name;
	cfunc func;
};

/* must be sorted by name */
static struct command_entry command_list[] = {
	{ "boot", &boot_command },
	{ "install", &install_command },
	{ "list", &list_command },
	{ "poweroff", &poweroff_command },
	{ "reset", &reset_command },
	{ "showcomport", &showcomport_command },
	{ "showvgaport", &showvgaport_command },
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
	const char *reason = "unknown command";
	nvlist_t *nv, *res = NULL;
	cfunc func;

	if ((nv = nvlist_unpack(sb->buf, sb->buf_size, 0)) == NULL)
		return -1;

	if ((cmd = nvlist_get_string(nv, "command")) == NULL)
		goto err;

	if ((func = get_command_function(cmd)) == NULL)
		goto err;

	res = (*func)(sb, nv, &sb->peer);
	if (res == NULL) {
		nvlist_destroy(nv);
		return 1;
	}

	sb->res_fd = nvlist_exists_number(res, FD_KEY) ?
		nvlist_take_number(res, FD_KEY) : -1;

	sb->res_buf = nvlist_pack(res, &sb->res_size);
	if (sb->res_buf == NULL) {
		reason = "nvlist_pack error";
		goto err;
	}
	sb->res_bytes = 0;

	nvlist_destroy(res);
	nvlist_destroy(nv);
	return 0;
err:
	nvlist_destroy(res);
	nvlist_destroy(nv);
	res = nvlist_create(0);
	nvlist_add_bool(res, "error", true);
	nvlist_add_string(res, "reason", reason);
	sb->res_buf = nvlist_pack(res, &sb->res_size);
	if (sb->res_buf == NULL) {
		nvlist_destroy(res);
		return -1;
	}
	sb->res_bytes = 0;
	nvlist_destroy(res);
	return 0;
}
