/*-
 * Copyright (c) 2013-2015 Sandvine Inc.
 * Copyright (c) 2026, Kevin Bowling <kbowling@FreeBSD.org>
 * Copyright (c) 2026, Yuichiro Naito <naito.yuichiro@gmail.com>
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

#include <sys/param.h>
#include <sys/iov.h>
#include <sys/nv.h>
#include <sys/pciio.h>
#include <sys/queue.h>

#if __FreeBSD_version > 1600023
#include <netlink/netlink.h>
#include <netlink/netlink_snl.h>
#include <netlink/netlink_snl_route_parsers.h>
#define IOV_STATUS_VFS_INITIALIZED "vfs_initialized"
#endif

#include <bitstring.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include "iov_pool.h"
#include "log.h"

#define	_PATH_DEVPCI	"/dev/pci"

/* This should be power of 2 more than 8.
   Bitstr_t is based on an unsigned long array. */
#define DEFAULT_BITMAP_NBITS 64

struct bitmap {
	size_t nbits;
	bitstr_t *bits;
};

static bitmap_t *
bitmap_realloc(bitmap_t *b, size_t nbits)
{
	bitstr_t *p;
	size_t old_s, new_s, nb;

	if (b->nbits >= nbits)
		return b;

	for (nb = MAX(b->nbits, 1); nb < nbits; nb <<= 1)
		;
	old_s = bitstr_size(b->nbits);
	new_s = bitstr_size(nb);

        if ((p = realloc(b->bits, new_s)) == NULL)
		return NULL;

	b->nbits = nbits;
	memset((void *)((intptr_t)p + old_s), 0, new_s - old_s);
	b->bits = p;
	return b;
}

bitmap_t *
create_bitmap(void)
{
	bitmap_t *b;
	bitstr_t *s;
	b = malloc(sizeof(*b));
	s = bit_alloc(DEFAULT_BITMAP_NBITS);
	if (b == NULL || s == NULL)
		goto err;

	b->nbits = DEFAULT_BITMAP_NBITS;
	b->bits = s;
	return b;
 err:
	free(b);
	free(s);
	return NULL;
}

void
free_bitmap(bitmap_t *b)
{
	if (b == NULL)
		return;
	free(b->bits);
	free(b);
}

int
bitmap_set(bitmap_t *b, size_t bit)
{
	bitmap_t *p;

	if ((p = bitmap_realloc(b, bit)) == NULL)
		return -1;

	bit_set(p->bits, bit);
	return 0;
}

int
bitmap_clear(bitmap_t *b, size_t bit)
{
	bitmap_t *p;

	if ((p = bitmap_realloc(b, bit)) == NULL)
		return -1;

	bit_clear(p->bits, bit);
	return 0;
}

int
bitmap_test(bitmap_t *b, size_t bit)
{
	bitmap_t *p;

	if ((p = bitmap_realloc(b, bit)) == NULL)
		return -1;

	return bit_test(p->bits, bit);
}

static int
get_ppt_num(const char *pd, long *r)
{
	long n;
	char *p = NULL;

	if (pd == NULL || strncmp(pd, "ppt", 3) != 0)
		return -1;

	n = strtol(&pd[3], &p, 10);
	if (*p != '\0')
		return -1;

	*r = n;
	return 0;
}

static int
is_ppt_used(const char *pd, bitmap_t *b, bool *result)
{
	long n;

	if (get_ppt_num(pd, &n) < 0)
		return -1;

	*result = bitmap_test(b, n);
	return 0;
}

static int
mark_ppt_used(struct vf_device *vd, bitmap_t *b)
{
	long n;

	if (get_ppt_num(vd->pptdev, &n) < 0)
		return -1;

	vd->ppt = n;
	bitmap_set(b, n);
	return 0;
}

static int
open_device(const char *dev)
{
	const char *fmt = "%s";
	char *p;
	int fd;
	long path_max;

	if ((path_max = pathconf("/dev", _PC_PATH_MAX)) < 0) {
		ERR("%s\n", "Could not get maximum path length");
		return -1;
	}

	if (dev[0] != '/') {
		fmt = "/dev/iov/%s";
		path_max -= strlen(fmt) - 2;
	}

	if (strlen(dev) >= (unsigned long)path_max) {
		ERR("%s\n", "Provided file name too long");
		return -1;
	}

	if (asprintf(&p, fmt, dev) < 0) {
		ERR("%s\n", "Could not allocate memory for device path");
		return -1;
	}

	if ((fd = open(p, O_RDWR)) < 0)
		ERR("Could not open device '%s'\n", dev);

	free(p);
	return (fd);
}

/* Fetch and unpack the current PCI SR-IOV status. */
static nvlist_t *
get_status(int fd)
{
	struct pci_iov_status arg;
	nvlist_t *status;
	void *buf = NULL, *newbuf;
	size_t buflen = 0;
	int rc;

	for (;;) {
		memset(&arg, 0, sizeof(arg));
		arg.status = buf;
		arg.len = buflen;
		if ((rc = ioctl(fd, IOV_GET_STATUS, &arg)) < 0) {
			ERR("%s\n", "Could not fetch SR-IOV status");
			goto err;
		}
		if (arg.error == 0)
			break;
		if (arg.error != EMSGSIZE || arg.len <= buflen) {
			errno = arg.error;
			ERR("%s\n", "Could not fetch SR-IOV status");
			goto err;
		}
		if ((newbuf = realloc(buf, arg.len)) == NULL) {
			ERR("Could not allocate %zu bytes for SR-IOV status\n",
			    arg.len);
			goto err;
		}
		buf = newbuf;
		buflen = arg.len;
	}
	if (arg.len == 0 || arg.len > buflen) {
		ERR("%s\n", "Kernel returned an invalid SR-IOV status length");
		goto err;
	}

	if ((status = nvlist_unpack(buf, arg.len, 0)) == NULL)
		ERR("%s\n", "Could not unpack SR-IOV status");
	free(buf);
	return (status);
err:
	free(buf);
	return NULL;
}
#if __FreeBSD_version > 1600023
static int
get_vf_status(const char *name, nvlist_t **vfs, size_t num_vfs)
{
	struct snl_parsed_link link = { };
	struct snl_errmsg_data e = { };
	struct snl_state ss = { };
	struct snl_writer nw = { };
	struct nlmsghdr *hdr;
	uint32_t seq;
	size_t i;
	int error;

	if (name == NULL) {
		return (-1);
	}

	if (strnlen(name, IFNAMSIZ) == IFNAMSIZ) {
		return (-1);
	}
	if (!snl_init(&ss, NETLINK_ROUTE)) {
		return (-1);
	}

	snl_init_writer(&ss, &nw);
	hdr = snl_create_msg_request(&nw, NL_RTM_GETLINK);
	if (hdr == NULL ||
	    snl_reserve_msg_object(&nw, struct ifinfomsg) == NULL ||
	    !snl_add_msg_attr_string(&nw, IFLA_IFNAME, name) ||
	    !snl_add_msg_attr_u32(&nw, IFLA_EXT_MASK, RTEXT_FILTER_VF) ||
	    (hdr = snl_finalize_msg(&nw)) == NULL) {
		error = ENOMEM;
		goto err;
	}
	seq = hdr->nlmsg_seq;
	if (!snl_send_message(&ss, hdr)) {
		error = EIO;
		goto err;
	}
	error = snl_grow_rxbuf_to_next_message(&ss);
	if (error != 0) {
		goto err;
	}
	hdr = snl_read_reply(&ss, seq);
	if (hdr == NULL) {
		error = EIO;
		goto err;
	}
	if (hdr->nlmsg_type == NLMSG_ERROR) {
		if (!snl_parse_errmsg(&ss, hdr, &e) || e.error == 0)
			error = EBADMSG;
		else
			error = e.error;
		goto err;
	}
	if (hdr->nlmsg_type != NL_RTM_NEWLINK ||
	    !snl_parse_nlmsg(&ss, hdr, &snl_rtm_link_parser, &link)) {
		error = EBADMSG;
		goto err;
	}
	if (!link.iflaf_vf_status.present) {
		error = EOPNOTSUPP;
		goto err;
	}
	if (link.iflaf_vf_status.error != 0) {
		error = link.iflaf_vf_status.error;
		goto err;
	}
	if (link.ifla_num_vf != link.iflaf_vf_status.vfs.count ||
	    link.ifla_num_vf != num_vfs) {
		error = EBADMSG;
		goto err;
	}

	for (i = 0; i < link.iflaf_vf_status.vfs.count; i++) {
		if (nvlist_exists_bool(vfs[i], IOV_STATUS_VFS_INITIALIZED)) {
			nvlist_free_bool(vfs[i], IOV_STATUS_VFS_INITIALIZED);
		}
		nvlist_add_bool(vfs[i], IOV_STATUS_VFS_INITIALIZED,
		    ((struct snl_parsed_vf *)link.iflaf_vf_status.vfs.items[i])
			->initialized);
	}
	snl_free(&ss);
	return (0);

err:
	snl_free(&ss);
	return (-1);
}
#endif

struct vf_device *
assign_ppt_dev(const char *pfdev, bitmap_t *b)
{
	const nvlist_t *vf;
	nvlist_t **vfs;
	const char *ppt;
	struct vf_device *ret = NULL;
	bool used;
	nvlist_t *status;
	size_t i, num_vfs;
	int fd;

	if ((fd = open_device(pfdev)) < 0)
		goto err;
	if ((status = get_status(fd)) == NULL)
		goto err2;

	vfs = NULL;
	num_vfs = 0;
	if (nvlist_exists_nvlist_array(status, IOV_STATUS_VFS_NAME))
		vfs = nvlist_take_nvlist_array(status, IOV_STATUS_VFS_NAME,
		    &num_vfs);

#if __FreeBSD_version > 1600023
	if (get_vf_status(pfdev, vfs, num_vfs) < 0) {
		ERR("%s\n", "failed to get vf status");
		goto err3;
	}
#endif

	for (i = 0; i < num_vfs; i++) {
		vf = vfs[i];
		if (!nvlist_get_bool(vf, IOV_STATUS_PASSTHROUGH_NAME) ||
		    !nvlist_get_bool(vf, IOV_STATUS_ATTACHED_NAME) ||
		    !nvlist_exists_string(vf, IOV_STATUS_BOUND_DRIVER_NAME))
			continue;

		ppt = nvlist_get_string(vf, IOV_STATUS_BOUND_DRIVER_NAME);
		if (nvlist_get_bool(vf, IOV_STATUS_VFS_INITIALIZED) ||
		    is_ppt_used(ppt, b, &used) < 0 || used)
			continue;
		if ((ret = malloc(sizeof(*ret) + strlen(ppt) + 1)) == NULL) {
			ERR("%s\n", "failed to allocate memory");
			goto err3;
		}
		strcpy(ret->pptdev, ppt);
		mark_ppt_used(ret, b);
		break;
	}

#if __FreeBSD_version > 1600023
err3:
#endif
	for (i = 0; i < num_vfs; i++)
		nvlist_destroy(vfs[i]);
	free(vfs);
	nvlist_destroy(status);
err2:
	close(fd);
err:
	return ret;
}

static int
fetch_devs(int fd, const struct pcisel *sel, struct pci_conf **confp,
    size_t *countp)
{
	struct pci_conf_io pc;
	struct pci_conf conf[255], *p;
	struct pci_match_conf patterns[1];
	size_t count;

	bzero(&pc, sizeof(struct pci_conf_io));
	pc.match_buf_len = sizeof(conf);
	pc.matches = conf;
	bzero(&patterns, sizeof(patterns));
	patterns[0].pc_sel = *sel;
	patterns[0].flags = PCI_GETCONF_MATCH_DOMAIN |
		PCI_GETCONF_MATCH_BUS | PCI_GETCONF_MATCH_DEV |
		PCI_GETCONF_MATCH_FUNC;
	pc.num_patterns = 1;
	pc.pat_buf_len = sizeof(patterns);
	pc.patterns = patterns;

	p = NULL;
	count = 0;
	do {
		if (ioctl(fd, PCIOCGETCONF, &pc) == -1) {
			ERR("%s\n", "ioctl(PCIOCGETCONF)");
			return -1;
		}

		if (pc.status == PCI_GETCONF_LIST_CHANGED) {
			free(p);
			p = NULL;
			count = 0;
			pc.offset = 0;
			continue;
		}

		if (pc.status == PCI_GETCONF_ERROR) {
			ERR("%s\n", "error returned from PCIOCGETCONF ioctl");
			return (-1);
		}

		p = reallocf(p, (count + pc.num_matches) * sizeof(*p));
		if (p == NULL) {
			ERR("%s\n", "failed to allocate buffer for PCIOCGETCONF results");
			return (-1);
		}

		memcpy(p + count, conf, pc.num_matches * sizeof(*p));
		count += pc.num_matches;
	} while (pc.status == PCI_GETCONF_MORE_DEVS);

	*confp = p;
	*countp = count;
	return 0;
}

int
lookup_ppt_dev(struct passthru_conf *pc)
{
	int fd, ppt;
	struct pci_conf *conf;
	size_t count;
	struct pcisel sel = {0, pc->bus, pc->slot, pc->func};

	if ((fd = open(_PATH_DEVPCI, O_RDONLY, 0)) < 0)
		goto err;

	if (fetch_devs(fd, &sel, &conf, &count) < 0)
		goto err1;

	if (conf == NULL || count == 0 || strncmp(conf->pd_name, "ppt", 3) != 0)
		goto err2;

	ppt = conf->pd_unit;
	free(conf);
	close(fd);
	return ppt;
 err2:
	free(conf);
 err1:
	close(fd);
 err:
	return -1;
}
