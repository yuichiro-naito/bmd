#ifndef _BMD_PLUGIN_H_
#define _BMD_PLUGIN_H_

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/nv.h>

#include <stdbool.h>

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
	int port;
	char *ipaddr;
	char *vgaconf;
	char *password;
	int width;
	int height;
	int wait;
};

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

struct vm_method {
	char *name;
	int (*vm_start)(struct vm *, nvlist_t *);
	int (*vm_reset)(struct vm *, nvlist_t *);
	int (*vm_poweroff)(struct vm *, nvlist_t *);
	int (*vm_acpi_poweroff)(struct vm *, nvlist_t *);
	void (*vm_cleanup)(struct vm *, nvlist_t *);
};

#define PLUGIN_VERSION 10

/*
  Plugin call back function
 */
typedef int (*plugin_call_back)(int ident, void *data);

/*
  Plugin Environment

  Utility functions for plugins.

         set_timer: wait in 'sec' seconds and call back 'cb' function.
  wait_for_process: wait for process 'pid' exits and call back 'cb' function.
       assign_taps: assigns tap interfaces for all networks.
     activate_taps: bring up all tap interfaces and set description.
       remove_taps: destroy all tap interfaces.

  'data' pointer is passed to 'data' argument in the call back function.
  'ident' argument is the same value of 'pid' in 'wait_for_process' function.
  For 'set_timer' function, 'ident' is an unique number to the timers.
 */
typedef struct plugin_env {
	int (*set_timer)(int sec, plugin_call_back cb, void *data);
	int (*wait_for_process)(pid_t pid, plugin_call_back cb, void *data);
	int (*assign_taps)(struct vm *vm);
	int (*activate_taps)(struct vm *vm);
	int (*remove_taps)(struct vm *vm);
} PLUGIN_ENV;

/*
  Plugin Description

           version: must set PLUGIN_VERSION
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
	struct vm_method *method;
} PLUGIN_DESC;

#endif