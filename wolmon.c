/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2025 Yuichiro Naito
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/queue.h>
#include <sys/wait.h>
#include <net/bpf.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include <capsicum_helpers.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include "bmd.h"
#include "bmd_plugin.h"
#include "log.h"

static LIST_HEAD(, wol_monitor) monitor_list = LIST_HEAD_INITIALIZER();
struct wol_monitor {
	LIST_ENTRY(wol_monitor) next;
	pid_t pid;
	int outfd;
	bool timer_is_set;
};

SLIST_HEAD(watch_targets, watch_target);
struct watch_target {
	SLIST_ENTRY(watch_target) next;
	bool unique;
	char *interface;
	struct ether_addr mac;
	size_t tag_len;
	char *tag;
};

SLIST_HEAD(capture_interfaces, capture_interface);
struct capture_interface {
	SLIST_ENTRY(capture_interface) next;
	int fd;
	const char *interface;
	struct kevent kev;
	struct nm_desc *nmd;
	struct netmap_ring *rx, *tx;
	int (*callback)(int, struct watch_targets *, struct capture_interface *);
};

#define MAX_WOL_MONITORS 10
static int nwolmon = 0;
static unsigned int wolmonid = 0;

#define BUFSIZE		   262144

#define GET_BRIDGE_NAME(n) ((n)->bridge) ? ((n)->bridge) : ((n)->vale)

#define WOL_FOREACH(v, n)                               \
	SLIST_FOREACH((v), &vm_list, next)              \
		NET_CONF_FOREACH((n), get_vm_conf((v))) \
			if (is_wol_enable((n)))

/*
  BPF instructions for WoL packet filter. This is compiled from
  "ether dst ff:ff:ff:ff:ff:ff" by `tcpdump -d`.
 */

static struct bpf_insn wol_filter[] = {
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 2),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0xffffffff, 0, 3),
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0xffff, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, BUFSIZE),
	BPF_STMT(BPF_RET + BPF_K, 0),
};

static struct watch_target *
lookup_watch_target(const struct ether_addr *addr, const char *interface,
    struct watch_targets *wl)
{
	struct watch_target *t;

	SLIST_FOREACH(t, wl, next)
		if (memcmp(&t->mac, addr, sizeof(t->mac)) == 0 &&
		    strcmp(t->interface, interface) == 0)
			return t;

	return NULL;
}

static void
free_watch_targets(struct watch_targets *wl)
{
	struct watch_target *t, *tn;

	SLIST_FOREACH_SAFE(t, wl, next, tn)
		free(t);
	SLIST_INIT(wl);
}

static struct watch_target *
create_watch_target(struct vm_entry *v, struct net_conf *n)
{
	struct watch_target *t;

	if ((t = malloc(sizeof(*t))) ==NULL)
		return NULL;
	if (ether_aton_r(n->mac, &t->mac) == NULL) {
		free(t);
		return NULL;
	}
	t->interface = GET_BRIDGE_NAME(n);
	t->tag = VM_CONF(v)->name;
	t->tag_len = strlen(t->tag);
	t->unique = true;

	return t;
}

static uint32_t
read_uint32(const char *p)
{
	uint32_t r;
	memcpy(&r, p, sizeof(r));
	return ntohl(r);
}

static uint16_t
read_uint16(const char *p)
{
	uint16_t r;
	memcpy(&r, p, sizeof(r));
	return ntohs(r);
}

static uint8_t
read_uint8(const char *p)
{
	uint8_t r = *p;
	return r;
}

static int
parse_wol(const char *buf, size_t size, struct ether_addr *addr)
{
	const struct ether_addr *t = (const struct ether_addr *)buf;
	int i;

	if (size < ETHER_ADDR_LEN * 17 || !ETHER_IS_BROADCAST(t[0].octet))
		return -1;

	for (i = 2; i < 17; i++)
		if (memcmp(&t[1], &t[i], ETHER_ADDR_LEN))
			return -1;
	*addr = t[1];
	return 0;
}

static int
parse_udp(const char *buf, size_t size, struct ether_addr *addr)
{
	const char *np = buf;
	struct udphdr udp;

	if (size < sizeof(udp))
		return -1;

	udp.uh_sport = read_uint16(np);
	udp.uh_dport = read_uint16(np + 2);
	udp.uh_ulen = read_uint16(np + 4);
	udp.uh_sum = read_uint16(np + 6);
	np += sizeof(udp);

	return parse_wol(np, size - (np - buf), addr);
}
static int
parse_ipv4(const char *buf, size_t size, struct ether_addr *addr)
{
	const char *np = buf;
	struct ip ip;

	if (size < sizeof(ip))
		return -1;

	ip.ip_v = read_uint8(np) >> 4;
	ip.ip_hl = read_uint8(np) & 0xf;
	ip.ip_p = read_uint8(np + offsetof(struct ip, ip_p));
	np += ip.ip_hl * 4;

	if (ip.ip_p != IPPROTO_UDP)
		return -1;

	return parse_udp(np, size - (np - buf), addr);
}

static int
parse_ipv6(const char *buf, size_t size, struct ether_addr *addr)
{
	const char *np = buf;
	struct ip6_hdr ip6;

	if (size < sizeof(ip6))
		return -1;

	ip6.ip6_flow = read_uint32(np);
	ip6.ip6_plen = read_uint16(np + 4);
	ip6.ip6_nxt = read_uint8(np + 6);
	ip6.ip6_hops = read_uint8(np + 7);
	np += sizeof(ip6);

	if (ip6.ip6_nxt != IPPROTO_UDP)
		return -1;

	return parse_udp(np, size - (np - buf), addr);
}

static int
parse_packet(const char *buf, size_t size, struct ether_addr *addr)
{
	const char *np = buf;
	struct ether_header ether;

	if (size < sizeof(ether))
		return -1;

	memcpy(ether.ether_dhost, np, ETHER_ADDR_LEN);
	np += ETHER_ADDR_LEN;
	memcpy(ether.ether_shost, np, ETHER_ADDR_LEN);
	np += ETHER_ADDR_LEN;
	ether.ether_type = read_uint16(np);
	np += sizeof(uint16_t);

	if (!ETHER_IS_BROADCAST(ether.ether_dhost))
		return -1;

	switch (ether.ether_type) {
	case ETHERTYPE_IP:
		return parse_ipv4(np, size - (np - buf), addr);
	case ETHERTYPE_IPV6:
		return parse_ipv6(np, size - (np - buf), addr);
	default:
		return parse_wol(np, size - (np - buf), addr);
	}
	return -1;
}

static int
parse_bpf(const char *buf, size_t size, struct ether_addr *addr)
{
	const char *np = buf;
	struct bpf_hdr bpf;

	if (size < sizeof(bpf))
		return -1;

	memcpy(&bpf, buf, sizeof(bpf));
	np += bpf.bh_hdrlen;

	return parse_packet(np, size - (np - buf), addr);
}

static int
notify(int sock, struct ether_addr *addr, struct watch_targets *wl,
    struct capture_interface *ci)
{
	struct watch_target *t;
	struct iovec iov[2];
	static char nl[] = "\n";

	if ((t = lookup_watch_target(addr, ci->interface, wl)) == NULL)
		return 0;

	INFO("WOL %02x:%02x:%02x:%02x:%02x:%02x received for %s\n",
	    t->mac.octet[0], t->mac.octet[1], t->mac.octet[2], t->mac.octet[3],
	    t->mac.octet[4], t->mac.octet[5], t->tag);

	iov[0].iov_base = t->tag;
	iov[0].iov_len = t->tag_len;
	iov[1].iov_base = nl;
	iov[1].iov_len = strlen(nl);

	return writev(sock, iov, 2);
}

static int
capture_bpf(int sock, struct watch_targets *wl, struct capture_interface *ci)
{
	ssize_t sz;
	char buf[BUFSIZE];
	struct ether_addr addr;

	if ((sz = read(ci->fd, buf, sizeof(buf))) < 0)
		return -1;
	/* Don't warn a non WoL packet. */
	if (parse_bpf(buf, sz, &addr) < 0)
		return 0;

	return notify(sock, &addr, wl, ci);
}

static ssize_t
netmap_recv(struct capture_interface *ci, char *buf, size_t len)
{
	struct netmap_slot *slot = NULL;
	struct netmap_ring *ring;
	ssize_t totlen = 0;
	uint32_t head;
	char *nm_buf;
	size_t nm_buf_len;

	ring = ci->rx;
	head = ring->head;

	do {
		if (head == ring->tail)
			return 0;

		slot = ring->slot + head;
		nm_buf = NETMAP_BUF(ring, slot->buf_idx);
		nm_buf_len = slot->len;

		for (;;) {
			size_t copylen = MIN(nm_buf_len, len);

			memcpy(buf, nm_buf, copylen);
			nm_buf += copylen;
			nm_buf_len -= copylen;
			buf += copylen;
			len -= copylen;
			totlen += copylen;

			if (nm_buf_len == 0)
				break;
		}

		head = nm_ring_next(ring, head);

	} while (slot->flags & NS_MOREFRAG);

	/* Release slots to netmap. */
	ring->head = ring->cur = head;

	return (totlen);
}

static int
capture_netmap(int sock, struct watch_targets *wl, struct capture_interface *ci)
{
	ssize_t sz;
	char buf[BUFSIZE];
	struct ether_addr addr;

	if ((sz = netmap_recv(ci, buf, sizeof(buf))) < 0)
		return -1;
	if (sz == 0)
		return 0;
	/* Don't report a parser error. Netmap doesn't have packet filters,
	   so it may receive packets other than WoL. */
	if (parse_packet(buf, sz, &addr) < 0)
		return 0;

	return notify(sock, &addr, wl, ci);
}

static void
free_capture_interfaces(struct capture_interfaces *cl)
{
	struct capture_interface *ci, *cin;
	SLIST_FOREACH_SAFE(ci, cl, next, cin) {
		if (ci->nmd)
			nm_close(ci->nmd);
		else
			close(ci->fd);
		free(ci);
	}
	SLIST_INIT(cl);
}

static int
bind_if_to_bpf(const char *ifname, int bpf)
{
	static struct bpf_program wol_program = { nitems(wol_filter),
		wol_filter };
	struct ifreq ifr;
	u_int dlt;

	memset(&ifr, 0, sizeof(ifr));
	if (ioctl(bpf, BIOCSBLEN, &(u_int[]) { BUFSIZE }[0]) < 0 ||
	    strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name)) >=
		sizeof(ifr.ifr_name) ||
	    ioctl(bpf, BIOCSETIF, &ifr) < 0 || ioctl(bpf, BIOCGDLT, &dlt) < 0 ||
	    dlt != DLT_EN10MB || ioctl(bpf, BIOCPROMISC) < 0 ||
	    ioctl(bpf, BIOCIMMEDIATE, &(u_int[]) { 1 }[0]) < 0 ||
	    ioctl(bpf, BIOCSETF, &wol_program) < 0)
		return -1;

	return 0;
}

static struct capture_interface *
create_bpf(const char *interface)
{
	struct capture_interface *ci;

	if ((ci = malloc(sizeof(*ci))) == NULL)
		return NULL;

	ci->fd = open("/dev/bpf0", O_RDONLY);
	if (ci->fd < 0) {
		ERR("wolmon: /dev/bpf0: %s\n", strerror(errno));
		free(ci);
		return NULL;
	}

	if (bind_if_to_bpf(interface, ci->fd) < 0) {
		ERR("wolmon: failed to bind interface '%s'\n", interface);
		free(ci);
		return NULL;
	}

	ci->interface = interface;
	ci->nmd = NULL;
	ci->callback = capture_bpf;
	EV_SET(&ci->kev, ci->fd, EVFILT_READ, EV_ADD, 0, 0, ci);

	return ci;
}

static struct capture_interface *
create_netmap(const char *interface)
{
	struct capture_interface *ci;
	struct nm_desc *nmd;
	char *valeport;

	if ((ci = malloc(sizeof(*ci))) == NULL)
		return NULL;

	if (asprintf(&valeport, "%s:_wolmon%u", interface, wolmonid) < 0)
		goto err;

	nmd = nm_open(valeport, NULL, NETMAP_NO_TX_POLL, NULL);
	if (nmd == NULL) {
		ERR("wolmon: failed to open netmap! (%s)\n", strerror(errno));
		goto err2;
	}
	free(valeport);
	ci->nmd = nmd;
	ci->fd = nmd->fd;
	ci->tx = NETMAP_TXRING(nmd->nifp, 0);
	ci->rx = NETMAP_RXRING(nmd->nifp, 0);
	ci->interface = interface;
	ci->callback = capture_netmap;
	EV_SET(&ci->kev, ci->fd, EVFILT_READ, EV_ADD, 0, 0, ci);

	return ci;
err2:
	free(valeport);
err:
	free(ci);
	return NULL;
}

static int
create_capture_interface(const char *intf, struct capture_interfaces *l)
{
	struct capture_interface *ci;

	ci = (strncmp(intf, "vale", 4) == 0) ? create_netmap(intf) :
					       create_bpf(intf);

	if (ci == NULL)
		return -1;

	SLIST_INSERT_HEAD(l, ci, next);
	return 0;
}

static int
make_capture_interfaces(struct watch_targets *wl, struct capture_interfaces *cl)
{
	struct watch_target *p, *q;

	SLIST_FOREACH(p, wl, next) {
		if (!p->unique)
			continue;
		q = p;
		/*
		  Do not use SLIST_NEXT(p) here. The last element triggers
		  'SLIST_FOREACH_FROM' starts at the fisrt of the list.
		 */
		SLIST_FOREACH_FROM(q, wl, next) {
			if (q == p)
				continue;
			if (strcmp(p->interface, q->interface) == 0)
				q->unique = false;
		}
	}

	/*
	  Continue to create all capture interfaces, even if some of them
	  failed.
	 */
	SLIST_FOREACH(p, wl, next)
		if (p->unique)
			create_capture_interface(p->interface, cl);

	/* If no interface succeeded, return an error. Otherwise OK.*/
	return SLIST_FIRST(cl) ? 0 : -1;
}

static int
wolmon_main(int sock, struct watch_targets *wl)
{
	int kq, i;
	struct kevent *evs, ev;
	struct capture_interfaces cl;
	struct capture_interface *ci;
	cap_rights_t bpfrights;

	setproctitle("wolmon");

	SLIST_INIT(&cl);
	if (make_capture_interfaces(wl, &cl) < 0) {
		ERR("%s\n", "no monitor interfaces!");
		return 1;
	}

	if ((kq = kqueue()) < 0) {
		ERR("wolmon: kqueue: %s\n", strerror(errno));
		goto err3;
	}

	caph_enter();
	cap_rights_init(&bpfrights, CAP_READ, CAP_EVENT);
	i = 0;
	SLIST_FOREACH(ci, &cl, next) {
		caph_rights_limit(ci->fd, &bpfrights);
		i++;
	}

	evs = malloc(sizeof(struct kevent) * (i + 3));
	if (evs == NULL) {
		ERR("wolmon: %s\n", "failed to allocate memory\n");
		goto err;
	}

	i = 0;
	SLIST_FOREACH(ci, &cl, next)
		evs[i++] = ci->kev;
	EV_SET(&evs[i++], SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&evs[i++], SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&evs[i++], SIGPIPE, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);

	if (kevent(kq, evs, i, NULL, 0, NULL) < 0) {
		free(evs);
		ERR("wolmon: failed to kevent: %s\n", strerror(errno));
		goto err;
	}
	free(evs);

	while (kevent(kq, NULL, 0, &ev, 1, NULL) >= 0) {
		switch (ev.filter) {
		case EVFILT_SIGNAL:
			goto end;
		case EVFILT_READ:
			ci = ev.udata;
			if ((ci->callback)(sock, wl, ci) < 0)
				ERR("wolmon: failed to read (%s)\n",
				    strerror(errno));
		}
	}

end:
	close(kq);
	free_capture_interfaces(&cl);
	LOG_CLOSE();
	return 0;
err:
	close(kq);
err3:
	free_capture_interfaces(&cl);
	LOG_CLOSE();
	return 1;
}

static int
on_read_fd(int fd, void *data __unused)
{
	ssize_t n;
	char **names, **name, buf[1024 + 1];
	struct vm_entry *vm_ent;

	n = read(fd, buf, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = '\0';
		if ((names = split_args(buf)) == NULL)
			return 0;
		for (name = names; *name != NULL; name++)
			if ((vm_ent = lookup_vm_by_name(*name)) &&
			    VM_STATE(vm_ent) == TERMINATE)
				start_virtual_machine(vm_ent);
		free(names);
	}

	return 0;
}

static int
on_monitor_exit(int ident __unused, void *data)
{
	struct wol_monitor *mon = data;

	waitpid(mon->pid, NULL, 0);

	plugin_stop_waiting_read_fd(mon->outfd, mon);
	close(mon->outfd);

	LIST_REMOVE(mon, next);
	free(mon);
	nwolmon--;
	return 0;
}

static int
on_timer(int ident __unused, void *data)
{
	struct wol_monitor *mon = data;

	kill(mon->pid, SIGTERM);
	return 0;
}

static struct wol_monitor *
exec_wol_monitor(struct watch_targets *wl)
{
	pid_t pid;
	int sk[2];
	struct wol_monitor *mon;

	if ((mon = malloc(sizeof(*mon))) == NULL)
		return NULL;

	if (socketpair(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sk) < 0)
		goto err;

	if ((pid = fork()) < 0)
		goto err2;

	if (pid == 0) {
		close(sk[0]);
		exit(wolmon_main(sk[1], wl));
	}
	close(sk[1]);
	mon->pid = pid;
	mon->outfd = sk[0];
	mon->timer_is_set = false;
	wolmonid++;

	return mon;

err2:
	close(sk[0]);
	close(sk[1]);
err:
	free(mon);
	return NULL;
}

static inline struct vm_conf *
get_vm_conf(struct vm_entry *v)
{
	return VM_NEWCONF(v) != NULL ? &VM_NEWCONF(v)->conf : VM_CONF(v);
}

static inline bool
is_wol_enable(struct net_conf *n)
{
	char *b = GET_BRIDGE_NAME(n);
	return (n->wol && n->mac && strlen(n->mac) > 0 && strcmp(b, "none"));
}

static bool
check_wol(void)
{
	struct vm_entry *v;
	struct net_conf *n;

	WOL_FOREACH(v, n)
		return true;

	return false;
}

static int
make_watch_targets(struct watch_targets *list)
{
	struct vm_entry *v;
	struct net_conf *n;
	struct watch_target *t;

	WOL_FOREACH(v, n) {
		if ((t = create_watch_target(v, n)) == NULL)
			goto err;
		SLIST_INSERT_HEAD(list, t, next);
	}

	return 0;
err:
	free_watch_targets(list);
	return -1;
}

static int
kill_monitors(void)
{
	struct wol_monitor *mon;

	LIST_FOREACH(mon, &monitor_list, next)
		if (!mon->timer_is_set)
			if (plugin_set_timer(1, on_timer, mon) == 0)
				mon->timer_is_set = true;
	return 0;
}

int
start_wol_monitor(void)
{
	struct wol_monitor *mon;
	struct watch_targets wl = SLIST_HEAD_INITIALIZER(wl);

	if (!check_wol()) {
		kill_monitors();
		return 0;
	}

	if (nwolmon >= MAX_WOL_MONITORS)
		return 0;

	if (make_watch_targets(&wl) < 0 ||
	    (mon = exec_wol_monitor(&wl)) == NULL) {
		ERR("%s\n", "failed to start wolmon!");
		return -1;
	}

	if (plugin_wait_for_read_fd(mon->outfd, on_read_fd, mon) < 0 ||
	    plugin_wait_for_process(mon->pid, on_monitor_exit, mon) < 0 ||
	    kill_monitors() < 0) {
		ERR("%s\n", "failed to wait for wolmon!");
		kill(mon->pid, SIGTERM);
		on_monitor_exit(mon->pid, mon);
		return -1;
	}

	LIST_INSERT_HEAD(&monitor_list, mon, next);
	nwolmon++;

	free_watch_targets(&wl);
	return 0;
}

int
stop_wol_monitor(void)
{
	struct wol_monitor *mon;

	LIST_FOREACH(mon, &monitor_list, next)
		kill(mon->pid, SIGTERM);

	return 0;
}
