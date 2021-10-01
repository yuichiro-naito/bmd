#ifndef _CONF_H_
#define _CONF_H_

#include <stdbool.h>
#include <stdio.h>

#include "vars.h"

#define ARRAY_FOREACH(p, a) \
	for (p = &a[0]; p < &a[sizeof(a)/sizeof(a[0])]; p++)

void free_disk_conf(struct disk_conf *c);
void free_iso_conf(struct iso_conf *c);
void free_net_conf(struct net_conf *c);
void free_vm_conf(struct vm_conf *vc);
void free_fbuf(struct fbuf *f);

int add_disk_conf(struct vm_conf *conf, const char *type, const char *path);
int add_iso_conf(struct vm_conf *conf, const char *type, const char *path);
int add_net_conf(struct vm_conf *conf, const char *type, const char *bridge);
struct net_conf *copy_net_conf(const struct net_conf *nc);
int set_name(struct vm_conf *conf, const char *name);
int set_memory_size(struct vm_conf *conf, const char *memory);
int set_ncpu(struct vm_conf *conf, int ncpu);
int assign_nmdm(struct vm_conf *conf);
int set_loadcmd(struct vm_conf *conf, const char *cmd);
int set_installcmd(struct vm_conf *conf, const char *cmd);
int set_hookcmd(struct vm_conf *conf, const char *cmd);
int set_err_logfile(struct vm_conf *conf, const char *name);
int set_loader(struct vm_conf *conf, const char *loader);
int set_loader_timeout(struct vm_conf *conf, int timeout);
int set_stop_timeout(struct vm_conf *conf, int timeout);
int set_grub_run_partition(struct vm_conf *conf, const char *partition);
int set_debug_port(struct vm_conf *conf, const char *port);
int set_boot(struct vm_conf *conf, enum BOOT boot);
int set_hostbridge(struct vm_conf *conf, enum HOSTBRIDGE_TYPE type);
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

struct fbuf *create_fbuf();
struct vm_conf *create_vm_conf(char *filename);
int finalize_vm_conf(struct vm_conf *conf);
int dump_vm_conf(struct vm_conf *conf, FILE *fp);

int compare_fbuf(const struct fbuf *a, const struct fbuf *b);
int compare_disk_conf(const struct disk_conf *a, const struct disk_conf *b);
int compare_iso_conf(const struct iso_conf *a, const struct iso_conf *b);
int compare_net_conf(const struct net_conf *a, const struct net_conf *b);
int compare_vm_conf(const struct vm_conf *a, const struct vm_conf *b);
#endif
