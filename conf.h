#ifndef _CONF_H_
#define _CONF_H_

#include <stdbool.h>
#include <stdio.h>

#include "bmd_plugin.h"

#ifndef LOCALBASE
#define LOCALBASE "/usr/local"
#endif

struct global_conf {
	char *config_file;
	char *plugin_dir;
	char *vars_dir;
	char *pid_path;
	char *cmd_sock_path;
	char *unix_domain_socket_mode;
	int nmdm_offset;
	int foreground;
};

struct passthru_conf {
	STAILQ_ENTRY(passthru_conf) next;
	char *devid;
};

struct disk_conf {
	STAILQ_ENTRY(disk_conf) next;
	char *type;
	char *path;
};

struct iso_conf {
	STAILQ_ENTRY(iso_conf) next;
	char *type;
	char *path;
};

struct net_conf {
	STAILQ_ENTRY(net_conf) next;
	char *type;
	char *bridge;
	char *tap;
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
};

struct conf_var {
	RB_ENTRY(conf_var) entry;
	char *key, *val;
};

RB_HEAD(vartree, conf_var);

struct variables {
	struct vartree *global;
	struct vartree *local;
	struct vartree *args;
};

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
	char *ncpu;
	char *memory;
	char *name;
	char *comport;
	char *loader;
	char *loadcmd;
	char *installcmd;
	char *err_logfile;
	char *grub_run_partition;
	uid_t owner;
	gid_t group;
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
};

struct vm {
	struct vm_conf *conf;
	enum STATE state;
	pid_t pid;
	STAILQ_HEAD(, net_conf) taps;
	char *mapfile;
	char *varsfile;
	char *assigned_comport;
	int infd;
	int outfd;
	int errfd;
	int logfd;
	int ntaps;
};

#define ARRAY_FOREACH(p, a) \
	for (p = &a[0]; p < &a[sizeof(a) / sizeof(a[0])]; p++)

void free_vartree(struct vartree *vt);
void free_passthru_conf(struct passthru_conf *c);
void free_disk_conf(struct disk_conf *c);
void free_iso_conf(struct iso_conf *c);
void free_net_conf(struct net_conf *c);
void free_vm_conf(struct vm_conf *vc);
void free_fbuf(struct fbuf *f);
void clear_passthru_conf(struct vm_conf *vc);
void clear_disk_conf(struct vm_conf *vc);
void clear_iso_conf(struct vm_conf *vc);
void clear_net_conf(struct vm_conf *vc);

int add_passthru_conf(struct vm_conf *conf, const char *devid);
int add_disk_conf(struct vm_conf *conf, const char *type, const char *path);
int add_iso_conf(struct vm_conf *conf, const char *type, const char *path);
int add_net_conf(struct vm_conf *conf, const char *type, const char *bridge);
struct net_conf *copy_net_conf(const struct net_conf *nc);
int set_name(struct vm_conf *conf, const char *name);
int set_memory_size(struct vm_conf *conf, const char *memory);
int set_ncpu(struct vm_conf *conf, int ncpu);
int set_loadcmd(struct vm_conf *conf, const char *cmd);
int set_installcmd(struct vm_conf *conf, const char *cmd);
int set_err_logfile(struct vm_conf *conf, const char *name);
int set_loader(struct vm_conf *conf, const char *loader);
int set_loader_timeout(struct vm_conf *conf, int timeout);
int set_stop_timeout(struct vm_conf *conf, int timeout);
int set_grub_run_partition(struct vm_conf *conf, const char *partition);
int set_debug_port(struct vm_conf *conf, const char *port);
int set_owner(struct vm_conf *conf, uid_t owner);
int set_group(struct vm_conf *conf, gid_t group);
int set_boot(struct vm_conf *conf, enum BOOT boot);
int set_hostbridge(struct vm_conf *conf, enum HOSTBRIDGE_TYPE type);
int set_backend(struct vm_conf *conf, char *backend);
int set_boot_delay(struct vm_conf *conf, int delay);
int set_comport(struct vm_conf *conf, const char *cmd);
int set_reboot_on_change(struct vm_conf *conf, bool enable);
int set_single_user(struct vm_conf *conf, bool single);
int set_install(struct vm_conf *conf, bool install);
int set_fbuf_enable(struct fbuf *fb, bool enable);
int set_fbuf_ipaddr(struct fbuf *fb, const char *ipaddr);
int set_fbuf_port(struct fbuf *fb, int port);
int set_fbuf_res(struct fbuf *fb, int width, int height);
int set_fbuf_vgaconf(struct fbuf *fb, const char *vga);
int set_fbuf_wait(struct fbuf *fb, int wait);
int set_fbuf_password(struct fbuf *fb, const char *pass);
int set_mouse(struct vm_conf *conf, bool use);
int set_wired_memory(struct vm_conf *conf, bool val);
int set_utctime(struct vm_conf *conf, bool val);
int set_keymap(struct vm_conf *conf, const char *keymap);

struct fbuf *create_fbuf();
struct vm_conf *create_vm_conf(const char *vm_name);
int finalize_vm_conf(struct vm_conf *conf);
int dump_vm_conf(struct vm_conf *conf, FILE *fp);

int compare_fbuf(const struct fbuf *a, const struct fbuf *b);
int compare_passthru_conf(const struct passthru_conf *a, const struct passthru_conf *b);
int compare_disk_conf(const struct disk_conf *a, const struct disk_conf *b);
int compare_iso_conf(const struct iso_conf *a, const struct iso_conf *b);
int compare_net_conf(const struct net_conf *a, const struct net_conf *b);
int compare_vm_conf(const struct vm_conf *a, const struct vm_conf *b);
int compare_nvlist(const nvlist_t *a, const nvlist_t *b);

int set_var0(struct vartree *vars, char *k, const char *v);
int set_var(struct variables *vars, char *k, const char *v);
char *get_var0(struct vartree *vars, char *k);
char *get_var(struct variables *vars, char *k);
int init_global_vars();
void set_global_vars(struct vartree *gv);
void free_global_vars();

void free_id_list();

#endif
