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
#include <sys/types.h>
#include <sys/event.h>

#include <net/bpf.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include <capsicum_helpers.h>
#include <errno.h>
#include <libgen.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../log.h"

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#define BUFSIZE		       262144

#define ETHERTYPE_FREEBSD_WAKE 0x0000 /* FreeBSD wake(8) */
#define ETHERTYPE_AMD_MAGIC    0x0842 /* AMD magic packet format */

/*
  BPF instructions for WoL packet filter. This is compiled from
  "ether dst ff:ff:ff:ff:ff:ff and (ether[12:2] = 0x0842 or ether[12:2] =
   0x0000 or udp port 9)"
 */
static struct bpf_insn wol_filter[] = {
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 2),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0xffffffff, 0, 23),
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0xffff, 0, 21),
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x842, 18, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x0, 17, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x86dd, 0, 6),
	BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 20),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x11, 0, 15),
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 54),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x9, 12, 0),
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 56),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x9, 10, 11),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x800, 0, 10),
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x11, 0, 8),
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 20),
	BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 6, 0),
	BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 14),
	BPF_STMT(BPF_LD + BPF_H + BPF_IND, 14),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x9, 3, 0),
	BPF_STMT(BPF_LD + BPF_H + BPF_IND, 16),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0x9, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, BUFSIZE),
	BPF_STMT(BPF_RET + BPF_K, 0),
};

SLIST_HEAD(watch_targets, watch_target);
struct watch_target {
	SLIST_ENTRY(watch_target) next;
	bool unique;
	char interface[IF_NAMESIZE];
	struct ether_addr mac;
	char tag[0];
};

SLIST_HEAD(capture_interfaces, capture_interface);
struct capture_interface {
	SLIST_ENTRY(capture_interface) next;
	int fd;
	const char *interface;
	struct kevent kev;
	struct nm_desc *nmd;
	struct netmap_ring *rx, *tx;
	int (*callback)(struct capture_interface *);
};

static struct watch_targets watch_list = SLIST_HEAD_INITIALIZER();
static struct capture_interfaces interface_list = SLIST_HEAD_INITIALIZER();

static struct watch_target *
lookup_watch_target(const struct ether_addr *addr, const char *interface)
{
	struct watch_target *t;

	SLIST_FOREACH(t, &watch_list, next)
		if (memcmp(&t->mac, addr, sizeof(t->mac)) == 0 &&
		    strcmp(t->interface, interface) == 0)
			return t;

	return NULL;
}

static void
free_watch_target(void)
{
	struct watch_target *t, *tn;

	SLIST_FOREACH_SAFE(t, &watch_list, next, tn)
		free(t);
	SLIST_INIT(&watch_list);
}

static int
create_watch_target(char *tag, char *intf, char *addr)
{
	struct watch_target *t;

	t = malloc(sizeof(*t) + strlen(tag) + 1);
	if (t == NULL)
		return -1;
	if (ether_aton_r(addr, &t->mac) == NULL) {
		free(t);
		return -1;
	}
	strncpy(t->interface, intf, sizeof(t->interface));
	strcpy(t->tag, tag);
	t->unique = true;

	SLIST_INSERT_HEAD(&watch_list, t, next);
	return 0;
}

static int
get_word(FILE *fp, char *buf, size_t size)
{
	int c;
	bool got_word = false;
	char *p = buf;

	while (p < buf + size - 1) {
		switch (c = fgetc(fp)) {
		case EOF:
			*p++ = '\0';
			return p - buf;
		case ' ':
		case '\t':
		case '\n':
			if (got_word) {
				*p++ = '\0';
				return p - buf;
			}
			break;
		default:
			got_word = true;
			*p++ = c;
		}
	}

	*p++ = '\0';
	return p - buf;
}

static int
parse_params(int fd)
{
	char tag[64], intf[16], addr[3 * 5 + 2 + 1];
	FILE *fp = fdopen(fd, "r");
	if (fp == NULL)
		return -1;

	while (true) {
		if (get_word(fp, tag, sizeof(tag)) == 0 || strlen(tag) == 0)
			break;
		if (strcmp(tag, ".end.") == 0)
			break;
		if (get_word(fp, intf, sizeof(intf)) == 0 ||
		    strlen(intf) == 0 ||
		    get_word(fp, addr, sizeof(addr)) == 0 || strlen(addr) == 0)
			break;
		create_watch_target(tag, intf, addr);
	}

	fdclose(fp, NULL);
	return 0;
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
	static const struct ether_addr bcast = { 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff };
	struct ether_addr target;
	int i;
	if (size < ETHER_ADDR_LEN * 17)
		return -1;
	if (memcmp(buf, &bcast, ETHER_ADDR_LEN))
		return -1;
	memcpy(&target, &buf[ETHER_ADDR_LEN], ETHER_ADDR_LEN);
	for (i = 2; i < 17; i++)
		if (memcmp(&target, &buf[ETHER_ADDR_LEN * i], ETHER_ADDR_LEN))
			return -1;
	*addr = target;
	return 0;
}

static int
parse_udp(const char *buf, size_t size, struct ether_addr *addr)
{
	const char *np = buf;
	struct udphdr udp;

	if (size >= sizeof(udp)) {
		udp.uh_sport = read_uint16(np);
		udp.uh_dport = read_uint16(np + 2);
		udp.uh_ulen = read_uint16(np + 4);
		udp.uh_sum = read_uint16(np + 6);
		np += sizeof(udp);
	} else
		return -1;

	if (udp.uh_dport == 9)
		return parse_wol(np, size - (np - buf), addr);

	return -1;
}
static int
parse_ipv4(const char *buf, size_t size, struct ether_addr *addr)
{
	const char *np = buf;
	struct ip ip;

	if (size >= sizeof(ip)) {
		ip.ip_v = read_uint8(np) >> 4;
		ip.ip_hl = read_uint8(np) & 0xf;
		ip.ip_p = read_uint8(np + offsetof(struct ip, ip_p));
		np += ip.ip_hl * 4;
	} else
		return -1;

	if (np > buf + size)
		return -1;

	if (ip.ip_p == IPPROTO_UDP)
		return parse_udp(np, size - (np - buf), addr);

	return -1;
}

static int
parse_ipv6(const char *buf, size_t size, struct ether_addr *addr)
{
	const char *np = buf;
	struct ip6_hdr ip6;

	if (size >= sizeof(ip6)) {
		ip6.ip6_flow = read_uint32(np);
		ip6.ip6_plen = read_uint16(np + 4);
		ip6.ip6_nxt = read_uint8(np + 6);
		ip6.ip6_hops = read_uint8(np + 7);
		np += sizeof(ip6);
	} else
		return -1;

	if (ip6.ip6_nxt == IPPROTO_UDP)
		return parse_udp(np, size - (np - buf), addr);

	return -1;
}

static int
parse_packet(const char *buf, size_t size, struct ether_addr *addr)
{
	const char *np = buf;
	struct ether_header ether;

	if (size >= sizeof(ether)) {
		memcpy(ether.ether_dhost, np, ETHER_ADDR_LEN);
		np += ETHER_ADDR_LEN;
		memcpy(ether.ether_shost, np, ETHER_ADDR_LEN);
		np += ETHER_ADDR_LEN;
		ether.ether_type = read_uint16(np);
		np += sizeof(uint16_t);
	} else
		return -1;

	if (! ETHER_IS_BROADCAST(ether.ether_dhost))
		return -1;

	switch (ether.ether_type) {
	case ETHERTYPE_FREEBSD_WAKE:
	case ETHERTYPE_AMD_MAGIC:
		return parse_wol(np, size - (np - buf), addr);
	case ETHERTYPE_IP:
		return parse_ipv4(np, size - (np - buf), addr);
	case ETHERTYPE_IPV6:
		return parse_ipv6(np, size - (np - buf), addr);
	}
	return -1;
}

static int
parse_bpf(const char *buf, size_t size, struct ether_addr *addr)
{
	const char *np = buf;
	struct bpf_hdr bpf;

	if (size >= sizeof(bpf)) {
		memcpy(&bpf, buf, sizeof(bpf));
		np += bpf.bh_hdrlen;
	}
	return parse_packet(np, size - (np - buf), addr);
}

static int
notify(struct ether_addr *addr, struct capture_interface *ci)
{
	struct watch_target *t;

	if ((t = lookup_watch_target(addr, ci->interface)) == NULL)
		return 0;

	INFO("WOL %02x:%02x:%02x:%02x:%02x:%02x received for %s\n",
	    t->mac.octet[0], t->mac.octet[1], t->mac.octet[2],
	    t->mac.octet[3], t->mac.octet[4], t->mac.octet[5],
	    t->tag);
	fprintf(stdout, "%s\n", t->tag);
	fflush(stdout);
	return 0;
}

static int
capture_bpf(struct capture_interface *ci)
{
	ssize_t sz;
	char buf[BUFSIZE];
	struct ether_addr addr;

	sz = read(ci->fd, buf, sizeof(buf));
	if (sz < 0)
		return -1;
	if (parse_bpf(buf, sz, &addr) < 0) {
		ERR("%s\n", "parse error");
		return -1;
	}

	return notify(&addr, ci);
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
capture_netmap(struct capture_interface *ci)
{
	ssize_t sz;
	char buf[BUFSIZE];
	struct ether_addr addr;

	sz = netmap_recv(ci, buf, sizeof(buf));
	if (sz < 0)
		return -1;
	if (sz == 0)
		return 0;
	/* Don't report a parser error. Netmap doesn't have packet filters,
	   so it may receive packets other than WoL. */
	if (parse_packet(buf, sz, &addr) < 0)
		return 0;

	return notify(&addr, ci);
}

static void
free_capture_interfaces(void)
{
	struct capture_interface *ci, *cin;
	SLIST_FOREACH_SAFE(ci, &interface_list, next, cin) {
		if (ci->nmd)
			nm_close(ci->nmd);
		else
			close(ci->fd);
		free(ci);
	}
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

static int
create_bpf(const char *interface)
{
	struct capture_interface *ci;

	ci = malloc(sizeof(*ci));
	if (ci == NULL)
		return -1;

	ci->fd = open("/dev/bpf0", O_RDONLY);
	if (ci->fd < 0) {
		ERR("/dev/bpf0: %s\n", strerror(errno));
		free(ci);
		return -1;
	}

	if (bind_if_to_bpf(interface, ci->fd) < 0) {
		ERR("failed to bind %s (%s)\n", interface, strerror(errno));
		free(ci);
		return -1;
	}

	ci->interface = interface;
	ci->nmd = NULL;
	ci->callback = capture_bpf;
	EV_SET(&ci->kev, ci->fd, EVFILT_READ, EV_ADD, 0, 0, ci);

	SLIST_INSERT_HEAD(&interface_list, ci, next);
	return 0;
}

static int
create_netmap(const char *interface)
{
	struct capture_interface *ci;
	struct nm_desc *nmd;
	const char *num;
	char *valeport;

	if ((ci = malloc(sizeof(*ci))) == NULL)
		return -1;

	if ((num = getenv("WOL_MON_ID")) == NULL)
		num = "a"; /* any characters except numbers are OK. */

	if (asprintf(&valeport, "%s:_wolmon%s", interface, num) < 0)
		goto err;

	nmd = nm_open(valeport, NULL, NETMAP_NO_TX_POLL, NULL);
	if (nmd == NULL) {
		ERR("failed to open netmap! (%s)\n", strerror(errno));
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

	SLIST_INSERT_HEAD(&interface_list, ci, next);
	return 0;
err2:
	free(valeport);
err:
	free(ci);
	return -1;
}

static int
create_capture_interface(const char *interface)
{
	if (strncmp(interface, "vale", 4) == 0)
		return create_netmap(interface);

	return create_bpf(interface);
}

static int
number_of_unique_interfaces(void)
{
	int count = 0;
	struct watch_target *p, *q;

	SLIST_FOREACH(p, &watch_list, next) {
		if (!p->unique)
			continue;
		q = p;
		/*
		  Do not use SLIST_NEXT(p) here. The last element triggers
		  'SLIST_FOREACH_FROM' starts at the fisrt of the list.
		 */
		SLIST_FOREACH_FROM(q, &watch_list, next) {
			if (q == p)
				continue;
			if (strcmp(p->interface, q->interface) == 0)
				q->unique = false;
		}
	}

	SLIST_FOREACH(p, &watch_list, next)
		if (p->unique && create_capture_interface(p->interface) >= 0)
			count++;

	return count;
}

static int
usage(int argc __unused, char *argv[] __unused)
{
	fprintf(stderr, "usage: %s -f <filename>\n"
	    "       %s -s <socket number>\n",
	    basename(argv[0]), basename(argv[0]));

	return 1;
}

int
main(int argc, char *argv[])
{
	int kq, i, n, sock = -1;
	struct kevent *evs, ev;
	struct capture_interface *ci;
	sigset_t nmask;
	cap_rights_t bpfrights;
	char *es, *fname = NULL;

	if ((es = getenv("WOL_PARAM_SOCKET")) != NULL) {
		n = strtol(es, NULL, 10);
		sock = (errno == EINVAL) ? -1 : n;
	}

	while ((n = getopt(argc, argv, "f:s:")) != -1) {
		switch (n) {
		case 'f':
			fname = optarg;
			break;
		case 's':
			sock = atoi(optarg);
			break;
		default:
			return usage(argc, argv);
		}
	}

	openlog("bmdwolmon", LOG_PID, LOG_DAEMON);

	if (sock == -1) {
		if (fname == NULL)
			return usage(argc, argv);
		if ((sock = open(fname, O_RDONLY)) < 0) {
			ERR("%s: %s\n", fname, strerror(errno));
			goto err3;
		}
	}

	if ((kq = kqueue()) < 0) {
		ERR("kqueue: %s\n", strerror(errno));
		goto err3;
	}

	INFO("%s\n", "start");
	sigemptyset(&nmask);
	sigaddset(&nmask, SIGTERM);
	sigaddset(&nmask, SIGINT);
	sigaddset(&nmask, SIGPIPE);
	sigprocmask(SIG_UNBLOCK, &nmask, NULL);

	if (parse_params(sock) < 0) {
		ERR("%s\n", "failed to parse");
		goto err2;
	}
	sigprocmask(SIG_BLOCK, &nmask, NULL);
	n = number_of_unique_interfaces();

	caph_enter();
	cap_rights_init(&bpfrights, CAP_READ, CAP_EVENT);
	SLIST_FOREACH(ci, &interface_list, next)
		caph_rights_limit(ci->fd, &bpfrights);

	evs = malloc(sizeof(struct kevent) * (n + 3));
	if (evs == NULL) {
		ERR("%s\n", "malloc failed\n");
		goto err;
	}

	i = 0;
	SLIST_FOREACH(ci, &interface_list, next)
		evs[i++] = ci->kev;
	EV_SET(&evs[i++], SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&evs[i++], SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&evs[i++], SIGPIPE, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);

	if (kevent(kq, evs, i, NULL, 0, NULL) < 0) {
		free(evs);
		ERR("kevent: %s\n", strerror(errno));
		goto err;
	}
	free(evs);

	while (kevent(kq, NULL, 0, &ev, 1, NULL) >= 0) {
		switch (ev.filter) {
		case EVFILT_SIGNAL:
			goto end;
		case EVFILT_READ:
			ci = ev.udata;
			if ((ci->callback)(ci) < 0)
				ERR("read fail: %s\n", strerror(errno));
		}
	}

end:
	INFO("%s\n", "quit");
	free_capture_interfaces();
	free_watch_target();
	close(kq);
	LOG_CLOSE();
	return 0;
err:
	free_capture_interfaces();
err2:
	free_watch_target();
	close(kq);
err3:
	LOG_CLOSE();
	return 1;
}
