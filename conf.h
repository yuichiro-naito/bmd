#ifndef _CONF_H_
#define _CONF_H_

#include <stdbool.h>
#include <stdio.h>
#include "vars.h"

void free_disk_conf(struct disk_conf *c);
void free_iso_conf(struct iso_conf *c);
void free_net_conf(struct net_conf *c);
void free_vm_conf(struct vm_conf *vc);
void free_fbuf(struct fbuf *f);

int add_disk_conf(struct vm_conf *conf, char *type, char *path);
int add_iso_conf(struct vm_conf *conf, char *type, char *path);
int add_net_conf(struct vm_conf *conf, char *type, char *bridge);
struct net_conf *copy_net_conf(struct net_conf *nc);
int set_name(struct vm_conf *conf, char *name);
int set_memory_size(struct vm_conf *conf, char *memory);
int set_ncpu(struct vm_conf *conf, int ncpu);
int assign_nmdm(struct vm_conf *conf);
int set_loadcmd(struct vm_conf *conf, char *cmd);
int set_installcmd(struct vm_conf *conf, char *cmd);
int set_hookcmd(struct vm_conf *conf, char *cmd);
int set_err_logfile(struct vm_conf *conf, char *name);
int set_loader(struct vm_conf *conf, char *loader);
int set_boot(struct vm_conf *conf, enum BOOT boot);
int set_boot_delay(struct vm_conf *conf, int delay);
int set_comport(struct vm_conf *conf, char *cmd);
int set_fbuf_enable(struct fbuf *fb, bool enable);
int set_fbuf_ipaddr(struct fbuf *fb, char *ipaddr);
int set_fbuf_port(struct fbuf *fb, int port);
int set_fbuf_res(struct fbuf *fb, int width, int height);
int set_fbuf_vgaconf(struct fbuf *fb, char *vga);
int set_fbuf_wait(struct fbuf *fb, int wait);
int set_fbuf_password(struct fbuf *fb, char *pass);
int set_mouse(struct vm_conf *conf, bool use);

struct fbuf *create_fbuf();
struct vm_conf *create_vm_conf(char *name);
int dump_vm_conf(struct vm_conf *conf, FILE *fp);

int compare_fbuf(struct fbuf *a, struct fbuf *b);
int compare_disk_conf(struct disk_conf *a, struct disk_conf *b);
int compare_iso_conf(struct iso_conf *a, struct iso_conf *b);
int compare_net_conf(struct net_conf *a, struct net_conf *b);
int compare_vm_conf(struct vm_conf *a, struct vm_conf *b);
#endif
