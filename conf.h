#ifndef _CONF_H_
#define _CONF_H_

#include "vars.h"

void free_disk_conf(struct disk_conf *c);
void free_iso_conf(struct iso_conf *c);
void free_net_conf(struct net_conf *c);
void free_vm_conf(struct vm_conf *vc);
int add_disk_conf(struct vm_conf *conf, char *type, char *path);
int add_iso_conf(struct vm_conf *conf, char *type, char *path);
int add_net_conf(struct vm_conf *conf, char *type, char *bridge);
int set_name(struct vm_conf *conf, char *name);
int set_memory_size(struct vm_conf *conf, char *memory);
int set_ncpu(struct vm_conf *conf, int ncpu);
int assign_nmdm(struct vm_conf *conf);
int set_loadcmd(struct vm_conf *conf, char *cmd);
int set_loader(struct vm_conf *conf, char *loader);
int set_boot(struct vm_conf *conf, enum BOOT boot);
int set_comport(struct vm_conf *conf, char *cmd);

struct vm_conf *create_vm_conf(char *name);
int dump_vm_conf(struct vm_conf *conf);
#endif
