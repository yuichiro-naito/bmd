#include <sys/param.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/mdioctl.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>

#include "vars.h"
#include "conf.h"

#define NETBSD_KERNEL   "/netbsd"
#define OPENBSD_KERNEL  "/bsd"
#define OPENBSD_RAMDISK_KERNEL  "/bsd.rd"
#define OPENBSD_UPGRADE_KERNEL  "/bsd.upgrade"
#define MDCTL_PATH  "/dev/" MDCTL_NAME

struct inspection {
	int single_user;
	unsigned md_unit;
	struct vm_conf *conf;
	char *mount_point;       /* needs to be freed */
	char *iso_path;
	char *disk_path;
	char *block_dev;         /* needs to be freed */
	char *ufs_dev;           /* needs to be freed */
	char *install_cmd;       /* needs to be freed */
	char *load_cmd;          /* needs to be freed */
};

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
	free(ins);
}

static int
mdattach(char *path, unsigned *unit)
{
	int fd;
        struct stat sb;
	struct md_ioctl mdio;

	memset(&mdio, 0, sizeof(mdio));
	mdio.md_version = MDIOVERSION;
	mdio.md_type = MD_VNODE;
	mdio.md_options = MD_CLUSTER | MD_COMPRESS | MD_READONLY | MD_AUTOUNIT;
	mdio.md_file = path;

	if ((fd = open(mdio.md_file, O_RDONLY)) < 0)
		return -1;
	if (fstat(fd, &sb) == -1 || !S_ISREG(sb.st_mode))
		goto err;
	mdio.md_mediasize = sb.st_size;
	close(fd);

	if ((fd = open(MDCTL_PATH, O_RDWR, 0)) < 0)
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
	int fd, rc=0;
	struct md_ioctl mdio;

	memset(&mdio, 0, sizeof(mdio));
	mdio.md_version = MDIOVERSION;
	mdio.md_unit = unit;

	if ((fd = open(MDCTL_PATH, O_RDWR, 0)) < 0)
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
	int rc,i;
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
	int rc,i;
	struct iovec iov[6];

	memset(iov, 0, sizeof(iov));
	rc = i = 0;
	set_iovec(&iov[i++], "fstype");
	set_iovec(&iov[i++], "ufs");
	set_iovec(&iov[i++], "fspath");
	set_iovec(&iov[i++], ins->mount_point);
	set_iovec(&iov[i++], "from");
	set_iovec(&iov[i++], path);
	if (nmount(iov, i, MNT_RDONLY) < 0)
		rc = -1;

	return rc;
}

/* mach [0-9]+\.[0-9]+ */
static int
match_version_number(char *name)
{
	char *p,*q;

	for (p = name; *p != '\0'; p++)
		if (*p < '0' || *p > '9')
			break;

	if (p == name || *p++ != '.')
		return 0;

	for (q = p; *q != '\0'; q++)
		if (*q < '0' || *q > '9')
			break;

	if (q == p || *q != '\0')
		return 0;

	return 1;
}

static bool
is_directory(int df, struct dirent *e)
{
	struct stat s;
	int fd, rc;

	if ((fd = openat(df, e->d_name, O_RDONLY)) < 0)
		return 0;
	rc = (fstat(fd, &s) == 0 && S_ISDIR(s.st_mode)) ? true : false;
	close(fd);

	return rc;
}

static bool
is_file(char *path)
{
	struct stat s;
	return (stat(path, &s) == 0 && S_ISREG(s.st_mode)) ? true : false;
}

static int
inspect_netbsd_iso(struct inspection *ins)
{
	int rc;
	char *path, *cmd;

	if (asprintf(&path, "%s" NETBSD_KERNEL, ins->mount_point) < 0)
		return -1;

	cmd = "knetbsd -h com0 -r cd0a " NETBSD_KERNEL "\nboot\n";
	rc = (is_file(path) && (ins->install_cmd = strdup(cmd)) != NULL) ? 0 : -1;
	free(path);
	return rc;
}

static int
inspect_openbsd_iso(struct inspection *ins)
{
	DIR *d;
	struct dirent *e;
	char *path;
	size_t len, olen, mplen;

	if ((path = malloc(PATH_MAX)) == NULL)
		return -1;

	len = olen = mplen = strlen(ins->mount_point);
	if (len >= PATH_MAX)
		goto err;

	strcpy(path, ins->mount_point);

	/* look for a version number directory (i.e. "6.9", "7.0", etc.) */
	if ((d = opendir(path)) == NULL)
		goto err;
	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] == '.')
			continue;
		if (is_directory(dirfd(d), e) && match_version_number(e->d_name)) {
			if (len + e->d_namlen + 2 >= PATH_MAX)
				goto err2;
			strcat(path, "/");
			len += 1;
			strcat(path, e->d_name);
			len += e->d_namlen;
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
			if (len + e->d_namlen + 2 >= PATH_MAX)
				goto err2;
			strcat(path, "/");
			len += 1;
			strcat(path, e->d_name);
			len += e->d_namlen;
			break;
		}
	}
	closedir(d);

	if (len == olen)
		goto err;

	/* look for bsd.rd */
	if (len + strlen(OPENBSD_RAMDISK_KERNEL) > PATH_MAX)
		goto err;
	strcat(path, OPENBSD_RAMDISK_KERNEL);
	len += strlen(OPENBSD_RAMDISK_KERNEL);

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
		if (strncmp(e->d_name, diskname, strlen(diskname)) == 0) {
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


static int
inspect_openbsd_disk(struct inspection *ins)
{
	char *path, *cmd;

	/* look for /bsd.upgrade */
	if (asprintf(&path, "%s" OPENBSD_UPGRADE_KERNEL, ins->mount_point) < 0)
		goto err;

	cmd = "kopenbsd -h com0 -r sd0a " OPENBSD_UPGRADE_KERNEL "\nboot\n";
	if (is_file(path) && (ins->load_cmd = strdup(cmd)) != NULL)
		goto ret;
	free(path);

	/* look for /bsd */
	if (asprintf(&path, "%s" OPENBSD_KERNEL, ins->mount_point) < 0)
		goto err;

	cmd = ins->single_user ?
		"kopenbsd -s -h com0 -r sd0a " OPENBSD_KERNEL "\nboot\n" :
		"kopenbsd -h com0 -r sd0a " OPENBSD_KERNEL "\nboot\n";

	if (is_file(path) &&
	    (ins->load_cmd = strdup(cmd)) != NULL)
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
	char *path, *cmd;

	if (asprintf(&path, "%s" NETBSD_KERNEL, ins->mount_point) < 0)
		goto err;

	cmd = ins->single_user ?
		"knetbsd -s -h com0 -r dk0a " NETBSD_KERNEL "\nboot\n" :
		"knetbsd -h com0 -r dk0a " NETBSD_KERNEL "\nboot\n";
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
	return 0;
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
		if (inspect_disk_image(ins) == 0) {
			rc = ins->load_cmd;
			ins->load_cmd = NULL;
		}
	}

	free_inspection(ins);
	return rc;
}
