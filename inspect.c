/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Yuichiro Naito
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
#include <sys/dirent.h>
#include <sys/ioccom.h>
#include <sys/mdioctl.h>
#include <sys/mount.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/uio.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bmd_plugin.h"
#include "conf.h"
#include "inspect.h"
#include "vm.h"

static struct inspection *
create_inspection(struct vm_conf *conf)
{
	struct inspection *ins;
	ins = calloc(1, sizeof(*ins));
	if (ins == NULL)
		return NULL;
	ins->md_unit = -1;
	ins->single_user = is_single_user(conf);
	if (asprintf(&ins->mount_point, "/tmp/bmd.ins.%d.XXXXXX", getpid()) <
		0 ||
	    mkdtemp(ins->mount_point) == NULL)
		goto err;

	ins->conf = conf;
	return ins;
err:
	free(ins->mount_point);
	free(ins);
	return NULL;
}

static void
free_inspection(struct inspection *ins)
{
	if (ins == NULL)
		return;
	rmdir(ins->mount_point);
	free(ins->mount_point);
	free(ins->install_cmd);
	free(ins->load_cmd);
	free(ins->block_dev);
	free(ins->ufs_dev);
	free(ins->grub_run_partition);
	free(ins);
}

static int
mdattach(char *path, long *unit)
{
	int fd;
	struct stat sb;
	struct md_ioctl mdio;

	memset(&mdio, 0, sizeof(mdio));
	mdio.md_version = MDIOVERSION;
	mdio.md_type = MD_VNODE;
	mdio.md_options = MD_CLUSTER | MD_COMPRESS | MD_READONLY | MD_AUTOUNIT;
	mdio.md_file = path;

	while ((fd = open(mdio.md_file, O_RDONLY)) < 0)
		if (errno != EINTR)
			break;
	if (fd < 0)
		return -1;
	if (fstat(fd, &sb) == -1 || !S_ISREG(sb.st_mode))
		goto err;
	mdio.md_mediasize = sb.st_size;
	close(fd);

	while ((fd = open(MDCTL_PATH, O_RDWR, 0)) < 0)
		if (errno != EINTR)
			break;
	if (fd < 0)
		return -1;
	if (ioctl(fd, MDIOCATTACH, &mdio) < 0)
		goto err;
	close(fd);

	*unit = (long)mdio.md_unit;
	return 0;
err:
	close(fd);
	return -1;
}

static int
mddetach(long unit)
{
	int fd, rc = 0;
	struct md_ioctl mdio;

	memset(&mdio, 0, sizeof(mdio));
	mdio.md_version = MDIOVERSION;
	mdio.md_unit = (unsigned)unit;

	while ((fd = open(MDCTL_PATH, O_RDWR, 0)) < 0)
		if (errno != EINTR)
			break;
	if (fd < 0)
		return -1;

	if (ioctl(fd, MDIOCDETACH, &mdio) < 0)
		rc = -1;

	close(fd);
	return rc;
}

#define IOV_ENTRY_DECONST(v)                                    \
	{                                                       \
		.iov_base = strdup(v), .iov_len = strlen(v) + 1 \
	}
#define IOV_LAST_ENTRY(v) (v)[nitems(v) - 1]

static int
mount_iso(struct inspection *ins)
{
	int rc;
	struct iovec *p, iov[] = { IOV_ENTRY_DECONST("fstype"),
		IOV_ENTRY_DECONST("cd9660"), IOV_ENTRY_DECONST("fspath"),
		IOV_ENTRY_DECONST(ins->mount_point), IOV_ENTRY_DECONST("from"),
		IOV_ENTRY_DECONST("/dev/mdNNNNNNNNNN") };

	ARRAY_FOREACH(p, iov)
		if (p->iov_base == NULL) {
			rc = -1;
			goto ret;
		}

	/* XXX: The last .iov_len will be a bit longer. */
	if (snprintf(IOV_LAST_ENTRY(iov).iov_base, IOV_LAST_ENTRY(iov).iov_len,
		"/dev/md%d", (unsigned)ins->md_unit) < 0) {
		rc = -1;
		goto ret;
	}

	rc = nmount(iov, nitems(iov), MNT_RDONLY);
ret:
	ARRAY_FOREACH(p, iov)
		free(p->iov_base);

	return rc;
}

static int
mount_ufs(struct inspection *ins, char *path)
{
	int rc;
	struct iovec *p, iov[] = { IOV_ENTRY_DECONST("fstype"),
		IOV_ENTRY_DECONST("ufs"), IOV_ENTRY_DECONST("fspath"),
		IOV_ENTRY_DECONST(ins->mount_point), IOV_ENTRY_DECONST("from"),
		IOV_ENTRY_DECONST(path) };

	ARRAY_FOREACH(p, iov)
		if (p->iov_base == NULL) {
			rc = -1;
			goto ret;
		}

	rc = nmount(iov, nitems(iov), MNT_RDONLY);
ret:
	ARRAY_FOREACH(p, iov)
		free(p->iov_base);

	return rc;
}
#undef IOV_ENTRY_DECONST
#undef IOV_LAST_ENTRY

/* match [0-9]+\.[0-9]+ */
static bool
match_version_number(char *name)
{
	char *p, *q;

	for (p = name; *p != '\0'; p++)
		if (*p < '0' || *p > '9')
			break;

	if (p == name || *p++ != '.')
		return false;

	for (q = p; *q != '\0'; q++)
		if (*q < '0' || *q > '9')
			break;

	if (q == p || *q != '\0')
		return false;

	return true;
}

static bool
is_directory(int df, struct dirent *e)
{
	struct stat s;
	return (fstatat(df, e->d_name, &s, AT_RESOLVE_BENEATH) == 0 &&
	    S_ISDIR(s.st_mode));
}

bool
is_file(const char *path)
{
	struct stat s;
	return (stat(path, &s) == 0 && S_ISREG(s.st_mode));
}

static int
inspect_netbsd_iso(struct inspection *ins)
{
	char *path;
	const char *com = get_comport(ins->conf) ? " -h com0" : "";

	if (asprintf(&path, "%s/" NETBSD_KERNEL, ins->mount_point) < 0)
		goto err;

	if (!is_file(path) || (asprintf(&ins->install_cmd,
		    "knetbsd%s -r cd0a /" NETBSD_KERNEL "\nboot\n", com)) < 0)
		goto err2;

	free(path);
	return 0;
err2:
	free(path);
err:
	return -1;
}

static int
inspect_openbsd_iso(struct inspection *ins)
{
	DIR *d;
	struct dirent *e;
	char *path, *npath;
	size_t len, olen, mplen;
	const char *com = get_comport(ins->conf) ? " -h com0" : "";

	if ((path = strdup(ins->mount_point)) == NULL)
		return -1;

	len = olen = mplen = strlen(ins->mount_point);

	/* look for a version number directory (i.e. "6.9", "7.0", etc.) */
	if ((d = opendir(path)) == NULL)
		goto err;
	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] == '.')
			continue;
		if (is_directory(dirfd(d), e) &&
		    match_version_number(e->d_name)) {
			if (asprintf(&npath, "%s/%s", path, e->d_name) < 0)
				goto err2;
			free(path);
			path = npath;
			len += e->d_namlen + 1;
			break;
		}
	}
	closedir(d);

	if (len == olen)
		goto err;

	olen = len;
	if ((d = opendir(path)) == NULL)
		goto err;

	/* look for an architecture name directory */
	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] == '.')
			continue;
		if (is_directory(dirfd(d), e)) {
			if (asprintf(&npath, "%s/%s/%s", path, e->d_name,
				OPENBSD_RAMDISK_KERNEL) < 0)
				goto err2;
			free(path);
			path = npath;
			len += e->d_namlen + strlen(OPENBSD_RAMDISK_KERNEL) + 2;
			break;
		}
	}
	closedir(d);

	if (len == olen)
		goto err;

	/* look for bsd.rd */
	if (!is_file(path) ||
	    asprintf(&ins->install_cmd, "kopenbsd%s %s\nboot\n", com,
		&path[mplen]) < 0)
		goto err;

	free(path);
	return 0;
err2:
	closedir(d);
err:
	free(path);
	return -1;
}

static int
inspect_iso_image(struct inspection *ins)
{
	struct iso_conf *ic;

	if ((ic = get_iso_conf(ins->conf)) == NULL)
		return -1;

	ins->iso_path = ic->path;

	if (mdattach(ins->iso_path, &ins->md_unit) < 0)
		return -1;

	if (mount_iso(ins) < 0)
		goto err;

	if (inspect_netbsd_iso(ins) < 0 && inspect_openbsd_iso(ins) < 0)
		goto err2;

	unmount(ins->mount_point, 0);
	mddetach(ins->md_unit);
	return 0;
err2:
	unmount(ins->mount_point, 0);
err:
	mddetach(ins->md_unit);
	return -1;
}

static int
match_diskname(struct dirent *e, char *diskname)
{
	char *p;
	size_t len = strlen(diskname);

	if (strncmp(e->d_name, diskname, len) != 0)
		return 0;

	p = &e->d_name[len];
	if (*p != 'p' && *p != 's')
		return 0;

	for (p++; *p != '\0'; p++)
		if (*p < '0' || *p > '9')
			return 0;

	return 1;
}

static int
mount_blockdev(struct inspection *ins)
{
	DIR *d;
	struct dirent *e;
	size_t len;
	char *dirname, *diskname, *p;

	if ((dirname = strdup(ins->block_dev)) == NULL)
		return -1;
	len = strlen(dirname);

	for (p = &dirname[len]; p >= dirname; p--)
		if (*p == '/')
			break;
	if (p == dirname)
		return -1;

	*p = '\0';
	diskname = &p[1];

	if ((d = opendir(dirname)) == NULL)
		goto err;
	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] == '.')
			continue;
		if (match_diskname(e, diskname)) {
			if (asprintf(&p, "%s/%s", dirname, e->d_name) < 0)
				break;
			if (mount_ufs(ins, p) == 0 &&
			    (ins->ufs_dev = strdup(e->d_name)) != NULL) {
				free(p);
				goto ret;
			}
			free(p);
		}
	}

	closedir(d);
err:
	free(dirname);
	return -1;
ret:
	closedir(d);
	free(dirname);
	return 0;
}

static void
inspect_openbsd_partition(struct inspection *ins)
{
	size_t len;
	char *p;

	/* set default partition number */
	set_string(&ins->grub_run_partition, "1");

	if (ins->ufs_dev == NULL)
		return;
	len = strlen(ins->ufs_dev);

	for (p = &ins->ufs_dev[len - 1]; p >= ins->ufs_dev; p--)
		if (*p < '0' || *p > '9')
			break;
	if (p == ins->ufs_dev)
		return;

	if (*p == 'p')
		set_string(&ins->grub_run_partition, p + 1);
}

static int
inspect_openbsd_disk(struct inspection *ins)
{
	char *path;
	const char *com = get_comport(ins->conf) ? " -h com0" : "";
	const char *sgl = ins->single_user ? " -s" : "";

	inspect_openbsd_partition(ins);

	/* look for /bsd.upgrade */
	if (asprintf(&path, "%s/" OPENBSD_UPGRADE_KERNEL, ins->mount_point) < 0)
		goto err;

	if (is_file(path) &&
	    (asprintf(&ins->load_cmd,
		"kopenbsd%s -r sd0a (hd0,%s)/" OPENBSD_UPGRADE_KERNEL
		"\nboot\n", com, ins->grub_run_partition)) >= 0)
		goto ret;
	free(path);

	/* look for /bsd */
	if (asprintf(&path, "%s/" OPENBSD_KERNEL, ins->mount_point) < 0)
		goto err;

	if (!is_file(path) || (asprintf(&ins->load_cmd,
		    "kopenbsd%s%s -r sd0a (hd0,%s)/" OPENBSD_KERNEL "\nboot\n",
		    sgl, com, ins->grub_run_partition)) < 0)
		goto err2;

ret:
	free(path);
	return 0;
err2:
	free(path);
err:
	return -1;
}

static int
inspect_netbsd_disk(struct inspection *ins)
{
	char *path;
	const char *com = get_comport(ins->conf) ? " -h com0" : "";
	const char *sgl = ins->single_user ? " -s" : "";

	if (asprintf(&path, "%s/" NETBSD_KERNEL, ins->mount_point) < 0)
		goto err;

	if (!is_file(path) || asprintf(&ins->load_cmd,
		"knetbsd%s%s -r dk0a /" NETBSD_KERNEL "\nboot\n", sgl, com) < 0)
		goto err2;

	free(path);
	return 0;
err2:
	free(path);
err:
	return -1;
}

static int
inspect_disk_image(struct inspection *ins)
{
	struct disk_conf *dc;

	if ((dc = get_disk_conf(ins->conf)) == NULL)
		return -1;
	ins->disk_path = dc->path;

	if (strncmp(ins->disk_path, "/dev", 4) != 0) {
		if (mdattach(ins->disk_path, &ins->md_unit) < 0 ||
		    asprintf(&ins->block_dev, "/dev/md%d",
			(unsigned)ins->md_unit) < 0)
			return -1;
	} else {
		if ((ins->block_dev = strdup(ins->disk_path)) == NULL)
			return -1;
	}

	if (mount_blockdev(ins) < 0)
		goto err;

	if (inspect_netbsd_disk(ins) < 0 && inspect_openbsd_disk(ins) < 0)
		goto err2;

	unmount(ins->mount_point, 0);
	if (ins->md_unit != -1)
		mddetach(ins->md_unit);
	return 0;
err2:
	unmount(ins->mount_point, 0);
err:
	if (ins->md_unit != -1)
		mddetach(ins->md_unit);
	return -1;
}

char *
inspect(struct vm_conf *conf)
{
	char *cmd;
	struct inspection *ins;

	if ((ins = create_inspection(conf)) == NULL)
		return NULL;

	if (is_install(conf)) {
		if (inspect_iso_image(ins) < 0)
			goto err;
		cmd = ins->install_cmd;
		ins->install_cmd = NULL;
	} else {
		if (inspect_disk_image(ins) < 0 && inspect_with_grub(ins) < 0)
			goto err;
		cmd = ins->load_cmd;
		ins->load_cmd = NULL;
	}
	free_inspection(ins);
	return cmd;
err:
	free_inspection(ins);
	return NULL;
}
