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
#ifndef _CONF_H_
#define _CONF_H_

#include <stdbool.h>
#include <stdio.h>

#include "bmd_plugin.h"

#ifndef LOCALBASE
#define LOCALBASE "/usr/local"
#endif

/* The maximum ethernet address format is "xx:xx:xx:xx:xx:xx".
   17 bytes long. */
#define ETHER_FORMAT_LEN (3 * 5 + 2)

#define NCOM 4

struct global_conf {
	char *config_file;
	char *plugin_dir;
	char *vars_dir;
	char *pid_path;
	char *cmd_socket_path;
	char *unix_domain_socket_mode;
	int nmdm_offset;
	int foreground;
};

struct hda_conf {
	STAILQ_ENTRY(hda_conf) next;
	char *play_dev;
	char *rec_dev;
};

struct passthru_conf {
	STAILQ_ENTRY(passthru_conf) next;
	char *devid;
};

struct disk_conf {
	STAILQ_ENTRY(disk_conf) next;
	char *type;
	char *path;
	bool nocache;
	bool direct;
	bool readonly;
	bool nodelete;
	bool noexist;
};

struct iso_conf {
	STAILQ_ENTRY(iso_conf) next;
	char *type;
	char *path;
	bool noexist;
};

struct net_conf {
	STAILQ_ENTRY(net_conf) next;
	char *type;
	char *bridge;
	char *tap;
	char *vale;
	char *vale_port;
	char *mac;
	bool wol;
};

struct sharefs_conf {
	STAILQ_ENTRY(sharefs_conf) next;
	char *name;
	char *path;
	bool readonly;
};

struct fbuf {
	int enable;
	int port;
	char *ipaddr;
	char *vgaconf;
	char *password;
	int width;
	int height;
	int wait;
	char *unixpath;
};

struct bhyveload_env {
	STAILQ_ENTRY(bhyveload_env) next;
	char env[0];
};

struct bhyve_env {
	STAILQ_ENTRY(bhyve_env) next;
	char env[0];
};

struct cpu_pin {
	STAILQ_ENTRY(cpu_pin) next;
	int vcpu;
	int hostcpu;
};

struct conf_var {
	RB_ENTRY(conf_var) entry;
	char *key, *val;
};

RB_HEAD(vartree, conf_var);
extern struct vartree *global_vars;

struct variables {
	struct vartree *global;
	struct vartree *local;
	struct vartree *args;
};

/* owner and group can be negative to represent nobody. */
_Static_assert(sizeof(int64_t) > sizeof(uid_t),
    "uid_t must be shorter than int64_t");
_Static_assert(sizeof(int64_t) > sizeof(gid_t),
    "gid_t must be shorter than int64_t");
struct vm_conf {
	struct variables vars;
	struct fbuf *fbuf;
	STAILQ_HEAD(, disk_conf) disks;
	STAILQ_HEAD(, iso_conf) isoes;
	STAILQ_HEAD(, net_conf) nets;
	STAILQ_HEAD(, passthru_conf) passthrues;
	char *keymap;
	char *backend;
	char *debug_port;
	int ncpu;
	char *memory;
	char *name;
	char *com[NCOM];
	char *loader;
	char *loadcmd;
	char *installcmd;
	char *err_logfile;
	char *grub_run_partition;
	int64_t owner;
	int64_t group;
	enum BOOT boot;
	enum HOSTBRIDGE_TYPE hostbridge;
	int ndisks;
	int nisoes;
	int nnets;
	int npassthrues;
	int boot_delay;
	int loader_timeout;
	int stop_timeout;
	bool mouse;
	bool wired_memory;
	bool utctime;
	bool reboot_on_change;
	bool single_user;
	bool install;
	char *bhyveload_loader;
	int nbhyveload_envs;
	STAILQ_HEAD(, bhyveload_env) bhyveload_envs;
	int nbhyve_envs;
	STAILQ_HEAD(, bhyve_env) bhyve_envs;
	int ncpu_pins;
	STAILQ_HEAD(, cpu_pin) cpu_pins;
	int ncpu_sockets;
	int ncpu_cores;
	int ncpu_threads;
	unsigned int id;
	char *tpm_dev;
	char *tpm_type;
	char *tpm_version;
	STAILQ_HEAD(, sharefs_conf) sharefss;
	int nsharefss;
	bool virt_random;
	bool x2apic;
	int nhdas;
	STAILQ_HEAD(, hda_conf) hdas;
};

struct vm {
	struct vm_conf *conf;
	enum STATE state;
	pid_t pid;
	STAILQ_HEAD(, net_conf) taps;
	char *mapfile;
	char *bootrom;
	char *varsfile;
	char *assigned_com[NCOM];
	int infd;
	int outfd;
	int errfd;
	int logfd;
	int ntaps;
};

#define ARRAY_FOREACH(p, a)	for (p = &a[0]; p < &a[nitems(a)]; p++)

#define CONF_COM_NUM(com, base) ((com) - (base) + 1)

void free_vartree(struct vartree *);
void free_passthru_conf(struct passthru_conf *);
void free_disk_conf(struct disk_conf *);
void free_iso_conf(struct iso_conf *);
void free_net_conf(struct net_conf *);
void free_sharefs_conf(struct sharefs_conf *);
void free_hda_conf(struct hda_conf *);
void free_vm_conf(struct vm_conf *);
#define free_bhyveload_env(p) free(p)
#define free_bhyve_env(p)     free(p)
#define free_cpu_pin(p)	      free(p)
void free_fbuf(struct fbuf *);
void clear_passthru_conf(struct vm_conf *);
void clear_disk_conf(struct vm_conf *);
void clear_iso_conf(struct vm_conf *);
void clear_net_conf(struct vm_conf *);
void clear_sharefs_conf(struct vm_conf *);
void clear_hda_conf(struct vm_conf *);
void clear_bhyveload_env(struct vm_conf *);
void clear_bhyve_env(struct vm_conf *);
void clear_cpu_pin(struct vm_conf *);

int add_passthru_conf(struct vm_conf *, const char *);
int add_disk_conf(struct vm_conf *, const char *, const char *, bool, bool,
    bool, bool, bool);
int add_iso_conf(struct vm_conf *, const char *, const char *, bool);
int add_net_conf(struct vm_conf *, const char *, const char *, const char *,
		 bool);
int add_sharefs_conf(struct vm_conf *, const char *, const char *, bool);
int add_hda_conf(struct vm_conf *, const char *, const char *);
int add_bhyveload_env(struct vm_conf *, const char *);
int add_bhyve_env(struct vm_conf *, const char *);
int add_cpu_pin(struct vm_conf *, int, int);
struct net_conf *copy_net_conf(const struct net_conf *);
int set_name(struct vm_conf *, const char *);
int set_memory(struct vm_conf *, const char *);
int set_ncpu(struct vm_conf *, int);
int set_cpu_topology(struct vm_conf *, int[3]);
int set_loadcmd(struct vm_conf *, const char *);
int set_installcmd(struct vm_conf *, const char *);
int set_err_logfile(struct vm_conf *, const char *);
int set_loader(struct vm_conf *, const char *);
int set_bhyveload_loader(struct vm_conf *, const char *);
int set_loader_timeout(struct vm_conf *, int);
int set_stop_timeout(struct vm_conf *, int);
int set_grub_run_partition(struct vm_conf *, const char *);
int set_debug_port(struct vm_conf *, const char *);
int set_owner(struct vm_conf *, uid_t);
int set_group(struct vm_conf *, gid_t);
int set_boot(struct vm_conf *, enum BOOT);
int set_hostbridge(struct vm_conf *, enum HOSTBRIDGE_TYPE);
int set_backend(struct vm_conf *, const char *);
int set_boot_delay(struct vm_conf *, int);
int set_com(struct vm_conf *, unsigned int, const char *);
int set_reboot_on_change(struct vm_conf *, bool);
int set_single_user(struct vm_conf *, bool);
int set_install(struct vm_conf *, bool);
int set_fbuf_enable(struct fbuf *, bool);
int set_fbuf_ipaddr(struct fbuf *, const char *);
int set_fbuf_port(struct fbuf *, int);
int set_fbuf_res(struct fbuf *, int, int);
int set_fbuf_vgaconf(struct fbuf *, const char *);
int set_fbuf_wait(struct fbuf *, bool);
int set_fbuf_password(struct fbuf *, const char *);
int set_fbuf_unixpath(struct fbuf *, const char *);
int set_mouse(struct vm_conf *, bool);
int set_wired_memory(struct vm_conf *, bool);
int set_utctime(struct vm_conf *, bool);
int set_virt_random(struct vm_conf *, bool);
int set_x2apic(struct vm_conf *, bool);
int set_keymap(struct vm_conf *, const char *);
int set_tpm_dev(struct vm_conf *, const char *);
int set_tpm_type(struct vm_conf *, const char *);
int set_tpm_version(struct vm_conf *, const char *);

struct fbuf *create_fbuf(void);
struct vm_conf *create_vm_conf(const char *);
int finalize_vm_conf(struct vm_conf *);
int dump_vm_conf(struct vm_conf *, FILE *);

int compare_vm_conf(const struct vm_conf *, const struct vm_conf *);
int compare_nvlist(const nvlist_t *, const nvlist_t *);

int set_var0(struct vartree *, const char *, const char *);
int set_var(struct variables *, const char *, const char *);
char *get_var0(struct vartree *, char *);
char *get_var(struct variables *, char *);
int init_global_vars(void);
void set_global_vars(struct vartree *);
void free_global_vars(void);

void free_id_list(void);

int set_string(char **, const char *);
int vm_conf_export_env(struct vm_conf *);

#endif
