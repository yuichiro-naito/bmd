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
  Make sure that 'conf' is the first member of this structure.
 */
struct vm_conf_entry {
	struct vm_conf conf;
	SLIST_ENTRY(vm_conf_entry) next;
};

enum STRUCT_TYPE { VMENTRY, SOCKBUF };

#define VM_START(v)         (v)->method->vm_start(&(v)->vm)
#define VM_RESET(v)         (v)->method->vm_reset(&(v)->vm)
#define VM_POWEROFF(v)      (v)->method->vm_poweroff(&(v)->vm)
#define VM_ACPI_POWEROFF(v) (v)->method->vm_acpi_poweroff(&(v)->vm)
#define VM_CLEANUP(v)       (v)->method->vm_cleanup(&(v)->vm)
#define VM_PTR(v)           (&(v)->vm)
#define VM_CONF(v)          ((v)->vm.conf)
#define VM_NEWCONF(v)       ((v)->new_conf)
#define VM_METHOD(v)        ((v)->method)
#define VM_TYPE(v)          ((v)->type)
#define VM_PLUGIN_DATA(v)   ((v)->pl_data)
#define VM_PID(v)           ((v)->vm.pid)
#define VM_TAPS(v)          ((v)->vm.taps)
#define VM_STATE(v)         ((v)->vm.state)
#define VM_MAPFILE(v)       ((v)->vm.mapfile)
#define VM_INFD(v)          ((v)->vm.infd)
#define VM_OUTFD(v)         ((v)->vm.outfd)
#define VM_ERRFD(v)         ((v)->vm.errfd)
#define VM_LOGFD(v)         ((v)->vm.logfd)
#define VM_CLOSE(v, fd)                    \
	do {                               \
		if (VM_##fd(v) != -1) {    \
			close(VM_##fd(v)); \
			VM_##fd(v) = -1;   \
		}                          \
	} while (0)

/*
  Entry of vm list.
  The individual entries indicate the virtual machine process.
  Make sure that 'type' is the first member of this structure.
 */
struct vm_entry {
	enum STRUCT_TYPE type;
	struct vm vm;
	struct vm_conf *new_conf;
	SLIST_HEAD(, plugin_data) pl_data;
	SLIST_ENTRY(vm_entry) next;
	struct vm_methods *method;
};

/*
  Socker buffer.
  Make sure that 'type' is the first member of this structure.
 */
struct sock_buf {
	enum STRUCT_TYPE type;
	SLIST_ENTRY(sock_buf) next;
	int fd;
	int state;
	size_t buf_size;
	char size[4];
	size_t read_size;
	size_t read_bytes;
	char *buf;
	size_t res_size;
	size_t res_bytes;
	char *res_buf;
};

struct vm_conf_head;

int remove_plugins();
void call_plugins(struct vm_entry *vm_ent);
int load_plugins();
void free_vm_entry(struct vm_entry *vm_ent);

struct vm_entry *create_vm_entry(struct vm_conf_entry *conf_ent);
int load_config_files(struct vm_conf_head *list);
void free_config_files();
struct vm_entry *lookup_vm_by_name(const char *name);
int set_timer(struct vm_entry *vm_ent, int second);
int start_virtual_machine(struct vm_entry *vm_ent);

#endif
