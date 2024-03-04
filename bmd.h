#ifndef _BMD_H_
#define _BMD_H_

#include <sys/queue.h>
#include <sys/nv.h>
#include <sys/event.h>
#include <sys/ucred.h>

#include "conf.h"
#include "bmd_plugin.h"

#define BMD_VERSION "2.3"

#define UID_NOBODY   65534
#define GID_NOBODY   65534

#define FD_KEY       "_file_descriptor_"

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

enum EVENT_TYPE { EVENT, PLUGIN };

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
typedef int (*event_call_back)(int ident, void *data);
struct event {
	enum EVENT_TYPE type;
	struct kevent kev;
	void *data;
	event_call_back cb;
	LIST_ENTRY(event) next;
};

/*
  Socker buffer.
 */
struct sock_buf {
	LIST_ENTRY(sock_buf) next;
	int fd;
	int read_state;
	size_t buf_size;
	char size[4];
	size_t read_size;
	size_t read_bytes;
	char *buf;
	size_t sent_size;
	int res_fd;
	size_t res_size;
	size_t res_bytes;
	char *res_buf;
	time_t event_time;
	struct xucred peer;
};

LIST_HEAD(vm_conf_head, vm_conf_entry);

int init_gl_conf(void);
void free_gl_conf(void);
int merge_global_conf(struct global_conf *);
void free_global_conf(struct global_conf *);

int remove_plugins(void);
void call_plugins(struct vm_entry *);
int call_plugin_parser(struct plugin_data_head *,
		       const char *, const char *);
int load_plugins(const char *);
int vm_method_exists(char *);

int create_plugin_data(struct plugin_data_head *);
void free_plugin_data(struct plugin_data_head *);
void free_vm_conf_entry(struct vm_conf_entry *);
struct vm_entry *lookup_vm_by_name(const char *);
int set_timer(struct vm_entry *, int);
int start_virtual_machine(struct vm_entry *);

int direct_run(const char *, bool, bool);

int load_config_file(struct vm_conf_head *, bool);
int compare_vm_conf_entry(struct vm_conf_entry *, struct vm_conf_entry *);

extern struct global_conf *gl_conf;
#endif
