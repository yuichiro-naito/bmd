#ifndef _VARS_H_
#define _VARS_H_

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/nv.h>

#include <stdbool.h>

#ifndef LOCALBASE
#define LOCALBASE "/usr/local"
#endif

/*
 * Nmdm number offset for auto assignment.
 */
#define DEFAULT_NMDM_OFFSET 200


int plugin_wait_for_process(pid_t pid, int (*cb)(int ident, void *data), void *data);
int plugin_set_timer(int second, int (*cb)(int ident, void *data), void *data);

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

enum BOOT { NO, YES, ONESHOT, ALWAYS };

struct fbuf {
	int enable;
	char *ipaddr;
	int port;
	int width;
	int height;
	char *vgaconf;
	int wait;
	char *password;
};

enum VM_BACKENDS { BHYVE, QEMU };

enum HOSTBRIDGE_TYPE { NONE, INTEL, AMD };

struct conf_var {
	RB_ENTRY(conf_var) entry;
	char *key, *val;
};

RB_HEAD(vartree, conf_var);

struct variables {
	struct vartree *global;
	struct vartree *local;
};

struct vm_conf {
	struct variables vars;
	uid_t owner;
	int boot_delay;
	int loader_timeout;
	int stop_timeout;
	enum HOSTBRIDGE_TYPE hostbridge;
	enum VM_BACKENDS backend;
	char *debug_port;
	char *ncpu;
	char *memory;
	char *name;
	char *comport;
	enum BOOT boot;
	char *loader;
	char *loadcmd;
	char *installcmd;
	char *err_logfile;
	char *grub_run_partition;
	struct fbuf *fbuf;
	bool mouse;
	bool wired_memory;
	bool utctime;
	bool reboot_on_change;
	bool single_user;
	bool install;
	int ndisks;
	int nisoes;
	int nnets;
	int npassthrues;
	STAILQ_HEAD(, disk_conf) disks;
	STAILQ_HEAD(, iso_conf) isoes;
	STAILQ_HEAD(, net_conf) nets;
	STAILQ_HEAD(, passthru_conf) passthrues;
	char *qemu_arch;
	char *qemu_machine;
	char *keymap;
};

enum STATE {
	TERMINATE, // bhyve is terminated
	LOAD,	   // bhyveload or grub-bhyve
	RUN,	   // bhyve is running
	STOP,	   // send SIGTERM to stop bhyve
	REMOVE,	   // send SIGTERM to stop bhyve and remove vm_entry
	RESTART	   // send SIGTERM and need rebooting
};

struct vm {
	struct vm_conf *conf;
	pid_t pid;
	enum STATE state;
	int infd;
	int outfd;
	int errfd;
	int logfd;
	int ntaps;
	STAILQ_HEAD(, net_conf) taps;
	char *mapfile;
	char *varsfile;
	char *assigned_comport;
};

struct vm_methods {
	int (*vm_start)(struct vm *);
	int (*vm_reset)(struct vm *);
	int (*vm_poweroff)(struct vm *);
	int (*vm_acpi_poweroff)(struct vm *);
	void (*vm_cleanup)(struct vm *);
};

#define PLUGIN_VERSION 8

/*
  Plugin call back function
 */
typedef int (*plugin_call_back)(int ident, void *data);

/*
  Plugin Environment

  Utility functions for plugins.

         set_timer: wait in 'sec' seconds and call back 'cb' function.
  wait_for_process: wait for process 'pid' exits and call back 'cb' function.

  'data' pointer is passed to 'data' argument in the call back function.
  'ident' argument is the same value of 'pid' in 'wait_for_process' function.
  For 'set_timer' function, 'ident' is an unique number to the timers.
 */
typedef struct plugin_env {
	int (*set_timer)(int sec, plugin_call_back cb, void *data);
	int (*wait_for_process)(pid_t pid, plugin_call_back cb, void *data);
} PLUGIN_ENV;

/*
  Plugin Description

           version: must be set PLUGIN_VERSION
              name: plugin name
        initialize: a function called after plugin is loaded. (*1)
          finalize: a function called before plugin is removed.
  on_status_change: a function called when VM state changed. (*2)
      parse_config: a function called while parsing VM configuratin (*2)

  *1: PLUGIN_ENV pointer is available while plugin is loaded.
  *2: nvlist_t pointer is available while VM is existing, unless removed from
      config file and reloaded.

  All other pointers in arguments are local scope to the function.
 */
typedef struct plugin_desc {
	int version;
	char *name;
	int (*initialize)(PLUGIN_ENV *);
	void (*finalize)();
	void (*on_status_change)(struct vm *, nvlist_t *);
	int (*parse_config)(nvlist_t *, const char *, const char *);
} PLUGIN_DESC;

#endif
