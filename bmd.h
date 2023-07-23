#ifndef _BMD_H_
#define _BMD_H_

#include <sys/queue.h>
#include <sys/nv.h>
#include <sys/event.h>

#include "conf.h"
#include "bmd_plugin.h"

#define UID_NOBODY   65534

/*
  Command timeout in second.
 */
#define COMMAND_TIMEOUT_SEC 30

struct global_conf;

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
	nvlist_t *pl_conf;
	SLIST_ENTRY(plugin_data) next;
};

/*
  Entry of vm_conf list.
  The individual entories hold the VM configuration.
  Make sure that 'conf' is the first member of this structure.
 */
struct vm_conf_entry {
	struct vm_conf conf;
	SLIST_HEAD(plugin_data_head, plugin_data) pl_data;
	LIST_ENTRY(vm_conf_entry) next;
};

enum STRUCT_TYPE { EVENT, PLUGIN };

#define VM_START(v)         (v)->method->vm_start(&(v)->vm, (v)->pl_conf)
#define VM_RESET(v)         (v)->method->vm_reset(&(v)->vm, (v)->pl_conf)
#define VM_POWEROFF(v)      (v)->method->vm_poweroff(&(v)->vm, (v)->pl_conf)
#define VM_ACPI_POWEROFF(v) (v)->method->vm_acpi_poweroff(&(v)->vm, (v)->pl_conf)
#define VM_CLEANUP(v)       (v)->method->vm_cleanup(&(v)->vm, (v)->pl_conf)
#define VM_PTR(v)           (&(v)->vm)
#define VM_CONF(v)          ((v)->vm.conf)
#define VM_CONF_ENT(v)      ((struct vm_conf_entry *)((v)->vm.conf))
#define VM_NEWCONF(v)       ((v)->new_conf)
#define VM_METHOD(v)        ((v)->method)
#define VM_PLCONF(v)        ((v)->pl_conf)
#define VM_TYPE(v)          ((v)->type)
#define VM_PLUGIN_DATA(v)   (VM_CONF_ENT(v)->pl_data)
#define VM_PID(v)           ((v)->vm.pid)
#define VM_TAPS(v)          (&(v)->vm.taps)
#define VM_STATE(v)         ((v)->vm.state)
#define VM_MAPFILE(v)       ((v)->vm.mapfile)
#define VM_VARSFILE(v)      ((v)->vm.varsfile)
#define VM_ASCOMPORT(v)     ((v)->vm.assigned_comport)
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
	struct vm vm;
	struct vm_conf *new_conf;
	SLIST_ENTRY(vm_entry) next;
	struct vm_method *method;
	nvlist_t *pl_conf;
};

/*
   Event Structure.
 */
LIST_HEAD(events, event);
struct event {
	enum STRUCT_TYPE type;
	struct kevent kev;
	void *data;
	int (*cb)(int ident, void *data);
	LIST_ENTRY(event) next;
};

/*
  Socker buffer.
  Make sure that 'type' is the first member of this structure.
 */
struct sock_buf {
	LIST_ENTRY(sock_buf) next;
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
	time_t event_time;
};

LIST_HEAD(vm_conf_head, vm_conf_entry);

int init_gl_conf();
void free_gl_conf();
int merge_global_conf(struct global_conf *gc);
void free_global_conf(struct global_conf *gc);

int remove_plugins();
void call_plugins(struct vm_entry *vm_ent);
int call_plugin_parser(struct plugin_data_head *head,
		       const char *key, const char *val);
int load_plugins(const char *plugin_dir);
int vm_method_exists(char *name);

int create_plugin_data(struct plugin_data_head *head);
void free_plugin_data(struct plugin_data_head *head);
void free_vm_conf_entry(struct vm_conf_entry *conf_ent);
struct vm_entry *lookup_vm_by_name(const char *name);
int set_timer(struct vm_entry *vm_ent, int second);
int start_virtual_machine(struct vm_entry *vm_ent);

int direct_run(const char *name, bool install, bool single);

int load_config_file(struct vm_conf_head *list, bool update_gl_conf);

extern struct global_conf *gl_conf;
#endif
