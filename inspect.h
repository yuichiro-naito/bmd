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
