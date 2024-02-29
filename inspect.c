#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/dirent.h>
#include <sys/ioccom.h>
#include <sys/mdioctl.h>
#include <sys/mount.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bmd_plugin.h"
#include "conf.h"
#include "vm.h"
#include "inspect.h"

static struct inspection *
create_inspection(struct vm_conf *conf)
{
	struct inspection *ins;
	ins = calloc(1, sizeof(*ins));
	if (ins == NULL)
		return NULL;
	ins->md_unit = -1;
	ins->single_user = conf->single_user;
        if (asprintf(&ins->mount_point,
		     "/tmp/bmd.ins.%d.XXXXXX", getpid()) < 0 ||
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
mdattach(char *path, int *unit)
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

	*unit = mdio.md_unit;
	return 0;
err:
	close(fd);
	return -1;
}

static int
mddetach(unsigned unit)
{
	int fd, rc = 0;
	struct md_ioctl mdio;

	memset(&mdio, 0, sizeof(mdio));
	mdio.md_version = MDIOVERSION;
	mdio.md_unit = unit;

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

static void
set_iovec(struct iovec *iov, char *val)
{
	iov->iov_base = val;
	iov->iov_len = strlen(val) + 1;
}

static int
mount_iso(struct inspection *ins)
{
	int rc, i;
	char *md_path;
	struct iovec iov[6];

	if (asprintf(&md_path, "/dev/md%d", ins->md_unit) < 0)
		return -1;

	memset(iov, 0, sizeof(iov));
	rc = i = 0;
	set_iovec(&iov[i++], "fstype");
	set_iovec(&iov[i++], "cd9660");
	set_iovec(&iov[i++], "fspath");
	set_iovec(&iov[i++], ins->mount_point);
	set_iovec(&iov[i++], "from");
	set_iovec(&iov[i++], md_path);
	if (nmount(iov, i, MNT_RDONLY) < 0)
		rc = -1;

	free(md_path);
	return rc;
}

static int
mount_ufs(struct inspection *ins, char *path)
{
	int i = 0;
	struct iovec iov[6];

	memset(iov, 0, sizeof(iov));
	set_iovec(&iov[i++], "fstype");
	set_iovec(&iov[i++], "ufs");
	set_iovec(&iov[i++], "fspath");
	set_iovec(&iov[i++], ins->mount_point);
	set_iovec(&iov[i++], "from");
	set_iovec(&iov[i++], path);
	return nmount(iov, i, MNT_RDONLY);
}

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
	int fd;
	bool rc;

	while ((fd = openat(df, e->d_name, O_RDONLY)) < 0)
		if (errno != EINTR)
			break;
	if (fd < 0)
		return 0;
	rc = (fstat(fd, &s) == 0 && S_ISDIR(s.st_mode));
	close(fd);

	return rc;
}

static bool
is_file(char *path)
{
	struct stat s;
	return (stat(path, &s) == 0 && S_ISREG(s.st_mode));
}

static int
inspect_netbsd_iso(struct inspection *ins)
{
	int rc;
	char *path;
	const char *cmd;

	if (asprintf(&path, "%s/" NETBSD_KERNEL, ins->mount_point) < 0)
		return -1;

	cmd = "knetbsd -h com0 -r cd0a /" NETBSD_KERNEL "\nboot\n";
	rc = (is_file(path) && (ins->install_cmd = strdup(cmd)) != NULL) ? 0 : -1;
	free(path);
	return rc;
}

static int
inspect_openbsd_iso(struct inspection *ins)
{
	DIR *d;
	struct dirent *e;
	char *path, *npath;
	size_t len, olen, mplen;

	if ((path = strdup(ins->mount_point)) == NULL)
		return -1;

	len = olen = mplen = strlen(ins->mount_point);

	/* look for a version number directory (i.e. "6.9", "7.0", etc.) */
	if ((d = opendir(path)) == NULL)
		goto err;
	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] == '.')
			continue;
		if (is_directory(dirfd(d), e) && match_version_number(e->d_name)) {
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
	    asprintf(&ins->install_cmd,
		     "kopenbsd -h com0 %s\nboot\n", &path[mplen]) < 0)
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

	ic = STAILQ_FIRST(&ins->conf->isoes);
	if (ic == NULL)
		return -1;

	ins->iso_path = ic->path;

	if (mdattach(ins->iso_path, &ins->md_unit) < 0)
		return -1;

	if (mount_iso(ins) < 0)
		goto err;

	if (inspect_netbsd_iso(ins) < 0 &&
	    inspect_openbsd_iso(ins) < 0)
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

	dirname = strdup(ins->block_dev);
	if (dirname == NULL)
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

	inspect_openbsd_partition(ins);

	/* look for /bsd.upgrade */
	if (asprintf(&path, "%s/" OPENBSD_UPGRADE_KERNEL, ins->mount_point) < 0)
		goto err;

	if (is_file(path) &&
	    (asprintf(&ins->load_cmd,
		      "kopenbsd -h com0 -r sd0a (hd0,%s)/"
		      OPENBSD_UPGRADE_KERNEL "\nboot\n",
		      ins->grub_run_partition)) > 0)
		goto ret;
	free(path);

	/* look for /bsd */
	if (asprintf(&path, "%s/" OPENBSD_KERNEL, ins->mount_point) < 0)
		goto err;

	if (is_file(path) &&
	    (asprintf(&ins->load_cmd,
		      "kopenbsd %s -h com0 -r sd0a (hd0,%s)/"
		      OPENBSD_KERNEL "\nboot\n",
		      ins->single_user ? "-s" : "",
		      ins->grub_run_partition)) > 0)
		goto ret;
	free(path);
err:
	return -1;
ret:
	free(path);
	return 0;
}

static int
inspect_netbsd_disk(struct inspection *ins)
{
	char *path;
	const char *cmd;

	if (asprintf(&path, "%s/" NETBSD_KERNEL, ins->mount_point) < 0)
		goto err;

	cmd = ins->single_user ?
		"knetbsd -s -h com0 -r dk0a /" NETBSD_KERNEL "\nboot\n" :
		"knetbsd -h com0 -r dk0a /" NETBSD_KERNEL "\nboot\n";
	if (is_file(path) &&
	    (ins->load_cmd = strdup(cmd)) != NULL) {
		free(path);
		return 0;
	}

	free(path);
err:
	return -1;
}

static int
inspect_disk_image(struct inspection *ins)
{
	struct disk_conf *dc;

	dc = STAILQ_FIRST(&ins->conf->disks);
	if (dc == NULL)
		return -1;
	ins->disk_path = dc->path;

	if (strncmp(ins->disk_path, "/dev", 4) != 0) {
		if (mdattach(ins->disk_path, &ins->md_unit) < 0 ||
		    asprintf(&ins->block_dev, "/dev/md%d", ins->md_unit) < 0)
			return -1;
	} else {
		if ((ins->block_dev = strdup(ins->disk_path)) == NULL)
			return -1;
	}

	if (mount_blockdev(ins) < 0)
		goto err;

	if (inspect_netbsd_disk(ins) < 0 &&
	    inspect_openbsd_disk(ins) < 0)
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
	char *rc = NULL;
	struct inspection *ins;

	ins = create_inspection(conf);
	if (ins == NULL)
		return rc;

	if (conf->install) {
		if (inspect_iso_image(ins) == 0) {
			rc = ins->install_cmd;
			ins->install_cmd = NULL;
		}
	} else {
		if (inspect_disk_image(ins) == 0 ||
		    inspect_with_grub(ins) == 0) {
			rc = ins->load_cmd;
			ins->load_cmd = NULL;
		}
	}

	free_inspection(ins);
	return rc;
}
