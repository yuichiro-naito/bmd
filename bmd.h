#ifndef _BMD_H_
#define _BMD_H_

#include <sys/queue.h>
#include <sys/nv.h>
#include <sys/event.h>
#include <sys/ucred.h>

#include "conf.h"
#include "bmd_plugin.h"

#define BMD_VERSION "2.5"

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
SLIST_HEAD(plugin_list, plugin_entry);
struct plugin_entry {
	struct plugin_desc desc;
	void *handle;
	SLIST_ENTRY(plugin_entry) next;
	/* Remember pointers need to be freed. */
	char *desc_name;
	char *vm_name;
	char *lm_name;
};

/*
  Plugin data is for each plugin and virtual machine.
 */
SLIST_HEAD(plugin_data_list, plugin_data);
struct callback_result {
	bool called;
	int state;
};
struct plugin_data {
	struct plugin_entry *ent;
	nvlist_t *pl_conf;
#define prestart_result results[0]
#define poststop_result results[1]
	struct callback_result results[2];
	SLIST_ENTRY(plugin_data) next;
};

/*
  Entry of vm_conf list.
  The individual entories hold the VM configuration.
  Make sure that 'conf' is the first member of this structure.
 */
LIST_HEAD(vm_conf_list, vm_conf_entry);
struct vm_conf_entry {
	struct vm_conf conf;
	struct plugin_data_list pl_data;
	LIST_ENTRY(vm_conf_entry) next;
};

enum EVENT_TYPE { EVENT, PLUGIN };

#define VM_START(v)         (v)->vm_method->vm_start(&(v)->vm, (v)->pl_conf)
#define VM_RESET(v)         (v)->vm_method->vm_reset(&(v)->vm, (v)->pl_conf)
#define VM_POWEROFF(v)      (v)->vm_method->vm_poweroff(&(v)->vm, (v)->pl_conf)
#define VM_ACPI_POWEROFF(v) (v)->vm_method->vm_acpi_poweroff(&(v)->vm, (v)->pl_conf)
#define VM_CLEANUP(v)       (v)->vm_method->vm_cleanup(&(v)->vm, (v)->pl_conf)
#define VM_LD_LOAD(v)       (v)->loader_method->ld_load(&(v)->vm, (v)->pl_conf)
#define VM_LD_CLEANUP(v)    (v)->loader_method->ld_cleanup(&(v)->vm, (v)->pl_conf)
#define VM_PTR(v)           (&(v)->vm)
#define VM_CONF(v)          ((v)->vm.conf)
#define VM_CONF_ENT(v)      ((struct vm_conf_entry *)((v)->vm.conf))
#define VM_NEWCONF(v)       ((v)->new_conf)
#define VM_TMPCONF(v)       ((v)->tmp_conf)
#define VM_METHOD(v)        ((v)->vm_method)
#define VM_LD_METHOD(v)     ((v)->loader_method)
#define VM_PLCONF(v)        ((v)->pl_conf)
#define VM_TYPE(v)          ((v)->type)
#define VM_PLUGIN_DATA(v)   (VM_CONF_ENT(v)->pl_data)
#define VM_PID(v)           ((v)->vm.pid)
#define VM_TAPS(v)          (&(v)->vm.taps)
#define VM_STATE(v)         ((v)->vm.state)
#define VM_MAPFILE(v)       ((v)->vm.mapfile)
#define VM_BOOTROM(v)       ((v)->vm.bootrom)
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
SLIST_HEAD(vm_list, vm_entry);
struct vm_entry {
	struct vm vm;
	struct vm_conf *tmp_conf, *new_conf;
	SLIST_ENTRY(vm_entry) next;
	struct vm_method *vm_method;
	struct loader_method *loader_method;
	nvlist_t *pl_conf;
};

/*
   Event Structure.
 */
typedef int (*event_call_back)(int ident, void *data);
LIST_HEAD(event_list, event);
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
typedef unsigned int  sock_buf_id;
LIST_HEAD(sock_list, sock_buf);
struct sock_buf {
	LIST_ENTRY(sock_buf) next;
	sock_buf_id id;
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
	long cid;         /* com_opener_id. set -1 if no opener is assigned. */
};

extern struct global_conf *gl_conf;
extern struct vm_conf_list vm_conf_list;
extern struct vm_list vm_list;

int init_gl_conf(void);
void free_gl_conf(void);
int merge_global_conf(struct global_conf *);
void free_global_conf(struct global_conf *);

int remove_plugins(void);
void call_plugins(struct vm_entry *);
int call_plugin_parser(struct plugin_data_list *,
		       const char *, const char *);
int load_plugins(const char *);
bool vm_method_exists(char *);
bool loader_method_exists(char *);
void copy_plugin_data(struct vm_conf_entry *, struct vm_conf_entry *);

int create_plugin_data(struct plugin_data_list *);
void free_plugin_data(struct plugin_data_list *);
void free_vm_conf_entry(struct vm_conf_entry *);
struct vm_entry *lookup_vm_by_name(const char *);
int set_timer(struct vm_entry *, int);
int start_virtual_machine(struct vm_entry *);

int direct_run(const char *, bool, bool);

int load_config_file(struct vm_conf_list *, bool);
int compare_vm_conf_entry(struct vm_conf_entry *, struct vm_conf_entry *);

int send_fd(int, int);
int recv_fd(int);
int send_ack(int);
int recv_ack(int);
int register_events(struct kevent *, event_call_back *, void **, int);
int set_sock_buf_wait_flags(struct sock_buf *, short, short);

/* implemented in control.c */
int control(int, char *[]);
struct vm_conf_entry *lookup_vm_conf(const char *);
#endif
