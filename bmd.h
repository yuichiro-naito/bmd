#ifndef _BMD_H_
#define _BMD_H_

#include <sys/queue.h>
#include "vars.h"

#define MAX(x, y) ((x) > (y) ? (x) : (y))

/*
  Entry of plugins.
  The individual entries refer to the installed plugin.
 */
struct plugin_entry {
	struct plugin_desc desc;
	void *handle;
	SLIST_ENTRY(plugin_entry) next;
};

/*
  Plugin data is for each plugin and virtual machine.
 */
struct plugin_data {
	struct plugin_entry *ent;
	void *data;
	SLIST_ENTRY(plugin_data) next;
};

/*
  Entry of vm_conf list.
  The individual entories hold the VM configuration.
  Make sure 'conf' is the first element of the structure.
 */
struct vm_conf_entry {
	struct vm_conf conf;
	SLIST_ENTRY(vm_conf_entry) next;
};

/*
  Entry of vm list.
  The individual entries indicate the virtual machine process.
  Make sure 'vm' is the first element of the structure.
 */
struct vm_entry {
	struct vm vm;
	struct vm_conf *new_conf;
	SLIST_HEAD(, plugin_data) pl_data;
	SLIST_ENTRY(vm_entry) next;
};

struct vm_conf_head;

int remove_plugins();
void call_plugins(struct vm_entry *vm_ent);
int load_plugins();
void free_vm_entry(struct vm_entry *vm_ent);

struct vm_entry *create_vm_entry(struct vm_conf_entry *conf_ent);
int load_config_files(struct vm_conf_head *list);
struct vm_entry *lookup_vm_by_name(const char *name);
int set_timer(struct vm_entry *vm_ent, int second);
int start_virtual_machine(struct vm_entry *vm_ent);

#endif
