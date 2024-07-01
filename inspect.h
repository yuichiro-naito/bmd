#ifndef _INSPECT_H
#define _INSPECT_H

#define NETBSD_KERNEL   "netbsd"
#define OPENBSD_KERNEL  "bsd"
#define OPENBSD_RAMDISK_KERNEL  "bsd.rd"
#define OPENBSD_UPGRADE_KERNEL  "bsd.upgrade"
#define MDCTL_PATH  "/dev/" MDCTL_NAME

_Static_assert(sizeof(unsigned) <= sizeof(uint32_t),
    "unsigned must be shorter than uint32_t");
struct inspection {
	int single_user;
	long md_unit;		/* unsigned <= uint32_t < md_unit */
	struct vm_conf *conf;
	char *mount_point;       /* needs to be freed */
	char *iso_path;
	char *disk_path;
	char *block_dev;         /* needs to be freed */
	char *ufs_dev;           /* needs to be freed */
	char *install_cmd;       /* needs to be freed */
	char *load_cmd;          /* needs to be freed */
	char *grub_run_partition;	/* needs to be freed */
};

int inspect_with_grub(struct inspection *);
char *inspect(struct vm_conf *);
bool is_file(const char *);

#endif
