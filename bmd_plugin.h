#ifndef _BMD_PLUGIN_H_
#define _BMD_PLUGIN_H_

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/nv.h>

#include <stdbool.h>

struct passthru_conf;
struct disk_conf;
struct iso_conf;
struct net_conf;
struct vm_conf;
struct vm;

enum BOOT {
	NO,       // Do not boot VM
	YES,      // Boot when daemon starts
	ONESHOT,  // Boot when daemon starts, do not reboot on VM exit
	ALWAYS    // Keep on running VM although VM terminates
};

enum HOSTBRIDGE_TYPE {
	NONE,
	INTEL,
	AMD
};

enum STATE {
	TERMINATE, // bhyve is terminated
	LOAD,	   // bhyveload or grub-bhyve
	RUN,	   // bhyve is running
	STOP,	   // send SIGTERM to stop bhyve
	REMOVE,	   // send SIGTERM to stop bhyve and remove vm_entry
	RESTART	   // send SIGTERM and need rebooting
};

#define DISK_CONF_FOREACH(dc, conf)	   \
	for ((dc) = get_disk_conf((conf)); \
	     (dc) != NULL;		   \
	     (dc) = next_disk_conf((dc)))

#define ISO_CONF_FOREACH(ic, conf)	  \
	for ((ic) = get_iso_conf((conf)); \
	     (ic) != NULL;		  \
	     (ic) = next_net_conf((ic)))

#define NET_CONF_FOREACH(nc, conf)	  \
	for ((nc) = get_net_conf((conf)); \
	     (nc) != NULL;		  \
	     (nc) = next_net_conf((nc)))

#define TAPS_FOREACH(nc, vm)		  \
	for ((nc) = get_taps((vm));	  \
	     (nc) != NULL;		  \
	     (nc) = next_net_conf((nc)))

int get_infd(struct vm *);
int get_outfd(struct vm *);
int get_errfd(struct vm *);
int get_logfd(struct vm *);
void set_infd(struct vm *, int);
void set_outfd(struct vm *, int);
void set_errfd(struct vm *, int);
void set_logfd(struct vm *, int);
char *get_assigned_comport(struct vm *);
enum STATE get_state(struct vm *);
void set_state(struct vm *, enum STATE);
void set_pid(struct vm *, pid_t);
struct vm_conf *vm_get_conf(struct vm *);
struct passthru_conf *get_passthru_conf(struct vm_conf *);
struct passthru_conf *next_passthru_conf(struct passthru_conf *);
char *get_passthru_conf_devid(struct passthru_conf *);
struct disk_conf *get_disk_conf(struct vm_conf *);
struct disk_conf *next_disk_conf(struct disk_conf *);
char *get_disk_conf_type(struct disk_conf *);
char *get_disk_conf_path(struct disk_conf *);
struct iso_conf *get_iso_conf(struct vm_conf *);
struct iso_conf *next_iso_conf(struct iso_conf *);
char *get_iso_conf_type(struct iso_conf *);
char *get_iso_conf_path(struct iso_conf *);
struct net_conf *get_taps(struct vm *);
struct net_conf *get_net_conf(struct vm_conf *);
struct net_conf *next_net_conf(struct net_conf *);
char *get_net_conf_type(struct net_conf *);
char *get_net_conf_bridge(struct net_conf *);
char *get_net_conf_tap(struct net_conf *);
struct bhyveload_env *get_bhyveload_env(struct vm_conf *);
struct bhyveload_env *next_bhyveload_env(struct bhyveload_env *);
char *get_bhyveload_env_env(struct bhyveload_env *);
char *get_name(struct vm_conf *);
char *get_memory(struct vm_conf *);
int get_ncpu(struct vm_conf *);
char *get_loadcmd(struct vm_conf *);
char *get_installcmd(struct vm_conf *);
char *get_err_logfile(struct vm_conf *);
char *get_loader(struct vm_conf *);
char *get_bhyveload_loader(struct vm_conf *);
struct bhyve_env *get_bhyve_env(struct vm_conf *);
struct bhyve_env *next_bhyve_env(struct bhyve_env *);
char *get_bhyve_env_env(struct bhyve_env *);
struct cpu_pin *get_cpu_pin(struct vm_conf *);
struct cpu_pin *next_cpu_pin(struct cpu_pin *);
int get_cpu_pin_vcpu(struct cpu_pin *);
int get_cpu_pin_hostcpu(struct cpu_pin *);
int get_loader_timeout(struct vm_conf *);
int get_stop_timeout(struct vm_conf *);
char *get_grub_run_partition(struct vm_conf *);
char *get_debug_port(struct vm_conf *);
uid_t get_owner(struct vm_conf *);
gid_t get_group(struct vm_conf *);
enum BOOT get_boot(struct vm_conf *);
enum HOSTBRIDGE_TYPE get_hostbridge(struct vm_conf *);
char *get_backend(struct vm_conf *);
int get_boot_delay(struct vm_conf *);
char *get_comport(struct vm_conf *);
bool is_reboot_on_change(struct vm_conf *);
bool is_single_user(struct vm_conf *);
bool is_install(struct vm_conf *);
bool is_fbuf_enable(struct vm_conf *);
char *get_fbuf_ipaddr(struct vm_conf *);
int get_fbuf_port(struct vm_conf *);
void get_fbuf_res(struct vm_conf *, int *, int *);
char *get_fbuf_vgaconf(struct vm_conf *);
int get_fbuf_wait(struct vm_conf *);
char *get_fbuf_password(struct vm_conf *);
bool is_mouse(struct vm_conf *);
bool is_wired_memory(struct vm_conf *);
bool is_utctime(struct vm_conf *);
char *get_keymap(struct vm_conf *);
char **split_args(char *);

/*
  Plugin call back function
 */
typedef int (*plugin_call_back)(int, void *);

int plugin_wait_for_process(pid_t, plugin_call_back, void *);
int plugin_set_timer(int, plugin_call_back, void *);

struct vm_method {
	const char *name;
	int (*vm_start)(struct vm *, nvlist_t *);
	int (*vm_reset)(struct vm *, nvlist_t *);
	int (*vm_poweroff)(struct vm *, nvlist_t *);
	int (*vm_acpi_poweroff)(struct vm *, nvlist_t *);
	void (*vm_cleanup)(struct vm *, nvlist_t *);
};

#define PLUGIN_VERSION 12

/*
  Plugin Description

           version: must set PLUGIN_VERSION
              name: plugin name
        initialize: a function called after plugin is loaded.
          finalize: a function called before plugin is removed.
  on_status_change: a function called when VM state changed. (*1)
      parse_config: a function called while parsing VM configuratin (*1)
  on_reload_config: copy plugin data while reloading VM configuration (*1)

  *1: The nvlist_t pointer is available while VM is existing, unless VM is
      removed from the config file nor VM configuration is reloaded.

  When VM configuration is reloaded, 'parse_config' is called and then
  on_reload_confg is called. Plugins have a chance to copy its data from
  old config to new one.

  All other pointers in arguments are local scope to the function.
 */
typedef struct plugin_desc {
	int version;
	const char *name;
	int (*initialize)(void);
	void (*finalize)(void);
	void (*on_status_change)(struct vm *, nvlist_t *);
	int (*parse_config)(nvlist_t *, const char *, const char *);
	struct vm_method *method;
	void (*on_reload_config)(nvlist_t *, nvlist_t *);
} PLUGIN_DESC;

extern PLUGIN_DESC plugin_desc;

#endif
