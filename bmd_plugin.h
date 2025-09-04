/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Yuichiro Naito
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _BMD_PLUGIN_H_
#define _BMD_PLUGIN_H_

#include <sys/types.h>
#include <sys/nv.h>
#include <sys/queue.h>
#include <sys/tree.h>

#include <stdbool.h>
#include <syslog.h>

struct passthru_conf;
struct disk_conf;
struct iso_conf;
struct net_conf;
struct bhyveload_env;
struct bhyve_env;
struct cpu_pin;
struct sharefs_conf;
struct hda_conf;
struct vm_conf;
struct vm;

enum BOOT {
	NO,	 // Do not boot VM
	YES,	 // Boot when daemon starts
	ONESHOT, // Boot when daemon starts, do not reboot on VM exit
	ALWAYS	 // Keep on running VM although VM terminates
};

enum HOSTBRIDGE_TYPE { NONE, INTEL, AMD };

enum STATE {
	TERMINATE, // bhyve is terminated
	LOAD,	   // bhyveload or grub-bhyve
	RUN,	   // bhyve is running
	STOP,	   // send SIGTERM to stop bhyve
	REMOVE,	   // send SIGTERM to stop bhyve and remove vm_entry
	RESTART,   // send SIGTERM and need rebooting
	PRESTART,  // before starting VM
	POSTSTOP   // after stopping VM
};

#define DISK_CONF_FOREACH(dc, conf)                      \
	for ((dc) = get_disk_conf((conf)); (dc) != NULL; \
	     (dc) = next_disk_conf((dc)))

#define ISO_CONF_FOREACH(ic, conf)                      \
	for ((ic) = get_iso_conf((conf)); (ic) != NULL; \
	     (ic) = next_iso_conf((ic)))

#define NET_CONF_FOREACH(nc, conf)                      \
	for ((nc) = get_net_conf((conf)); (nc) != NULL; \
	     (nc) = next_net_conf((nc)))

#define SHAREFS_CONF_FOREACH(sc, conf)                      \
	for ((sc) = get_sharefs_conf((conf)); (sc) != NULL; \
	     (sc) = next_sharefs_conf((sc)))

#define CPU_PINS_FOREACH(sc, conf)                      \
	for ((sc) = get_cpu_pin((conf)); (sc) != NULL; \
	     (sc) = next_cpu_pin((sc)))

#define HDA_CONF_FOREACH(hc, conf)                      \
	for ((hc) = get_hda_conf((conf)); (hc) != NULL; \
	     (hc) = next_hda_conf((hc)))

#define TAPS_FOREACH(nc, vm) \
	for ((nc) = get_taps((vm)); (nc) != NULL; (nc) = next_net_conf((nc)))

#define BHYVELOAD_ENV_FOREACH(be, conf)                      \
	for ((be) = get_bhyveload_env((conf)); (be) != NULL; \
	     (be) = next_bhyveload_env((be)))

#define BHYVE_ENV_FOREACH(be, conf)                      \
	for ((be) = get_bhyve_env((conf)); (be) != NULL; \
	     (be) = next_bhyve_env((be)))

int get_infd(struct vm *);
int get_outfd(struct vm *);
int get_errfd(struct vm *);
int get_logfd(struct vm *);
void set_infd(struct vm *, int);
void set_outfd(struct vm *, int);
void set_errfd(struct vm *, int);
void set_logfd(struct vm *, int);
char *get_assigned_comport(struct vm *);
char *get_assigned_com(struct vm *, unsigned int);
enum STATE get_state(struct vm *);
void set_state(struct vm *, enum STATE);
void set_pid(struct vm *, pid_t);
int set_bootrom(struct vm *, const char *);
void clear_bootrom(struct vm *);
const char *get_mapfile(struct vm *);
int set_mapfile(struct vm *, const char *);
const char *get_varsdir(void);
const char *get_varsfile(struct vm *);
int set_varsfile(struct vm *, const char *);
void free_mapfile(struct vm *);
struct vm_conf *vm_get_conf(struct vm *);
struct passthru_conf *get_passthru_conf(struct vm_conf *);
struct passthru_conf *next_passthru_conf(struct passthru_conf *);
char *get_passthru_conf_devid(struct passthru_conf *);
struct disk_conf *get_disk_conf(struct vm_conf *);
struct disk_conf *next_disk_conf(struct disk_conf *);
char *get_disk_conf_type(struct disk_conf *);
char *get_disk_conf_path(struct disk_conf *);
bool is_disk_conf_nocache(struct disk_conf *);
bool is_disk_conf_direct(struct disk_conf *);
bool is_disk_conf_readonly(struct disk_conf *);
bool is_disk_conf_nodelete(struct disk_conf *);
bool is_disk_conf_noexist(struct disk_conf *);
struct iso_conf *get_iso_conf(struct vm_conf *);
struct iso_conf *next_iso_conf(struct iso_conf *);
char *get_iso_conf_type(struct iso_conf *);
char *get_iso_conf_path(struct iso_conf *);
bool is_iso_conf_noexist(struct iso_conf *);
struct net_conf *get_taps(struct vm *);
struct net_conf *get_net_conf(struct vm_conf *);
struct net_conf *next_net_conf(struct net_conf *);
char *get_net_conf_type(struct net_conf *);
char *get_net_conf_bridge(struct net_conf *);
char *get_net_conf_mac(struct net_conf *);
char *get_net_conf_tap(struct net_conf *);
char *get_net_conf_vale(struct net_conf *);
char *get_net_conf_vale_port(struct net_conf *);
bool get_net_conf_wol(struct net_conf *); /* deprecated, violates naming rule. */
bool is_net_conf_wol(struct net_conf *);
struct sharefs_conf *get_sharefs_conf(struct vm_conf *);
struct sharefs_conf *next_sharefs_conf(struct sharefs_conf *);
char *get_sharefs_conf_name(struct sharefs_conf *);
char *get_sharefs_conf_path(struct sharefs_conf *);
bool is_sharefs_conf_readonly(struct sharefs_conf *);
struct hda_conf *get_hda_conf(struct vm_conf *);
struct hda_conf *next_hda_conf(struct hda_conf *);
char *get_hda_conf_play_dev(struct hda_conf *);
char *get_hda_conf_rec_dev(struct hda_conf *);
struct bhyveload_env *get_bhyveload_env(struct vm_conf *);
struct bhyveload_env *next_bhyveload_env(struct bhyveload_env *);
char *get_bhyveload_env_env(struct bhyveload_env *);
unsigned int get_id(struct vm_conf *);
char *get_name(struct vm_conf *);
char *get_memory(struct vm_conf *);
int get_ncpu(struct vm_conf *);
int get_ncpu_sockets(struct vm_conf *);
int get_ncpu_cores(struct vm_conf *);
int get_ncpu_threads(struct vm_conf *);
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
char *get_com(struct vm_conf *, unsigned int);
bool is_reboot_on_change(struct vm_conf *);
bool is_single_user(struct vm_conf *);
bool is_install(struct vm_conf *);
bool is_fbuf_enable(struct vm_conf *);
char *get_fbuf_ipaddr(struct vm_conf *);
int get_fbuf_port(struct vm_conf *);
void get_fbuf_res(struct vm_conf *, int *, int *);
char *get_fbuf_vgaconf(struct vm_conf *);
int get_fbuf_wait(struct vm_conf *); /* deprecated, violates naming rule. */
bool is_fbuf_wait(struct vm_conf *);
char *get_fbuf_password(struct vm_conf *);
bool is_mouse(struct vm_conf *);
bool is_wired_memory(struct vm_conf *);
bool is_utctime(struct vm_conf *);
bool is_virt_random(struct vm_conf *);
bool is_x2apic(struct vm_conf *);
char *get_keymap(struct vm_conf *);
char *get_tpm_dev(struct vm_conf *);
char *get_tpm_type(struct vm_conf *);
char *get_tpm_version(struct vm_conf *);
int vm_conf_export_env(struct vm_conf *);

char **split_args(char *);

/*
  Plugin call back function.
 */
typedef int (*plugin_call_back)(int, void *);

/*
  Plugin structures.
 */
struct loader_method {
	const char *name;
	int (*ld_load)(struct vm *, nvlist_t *);
	void (*ld_cleanup)(struct vm *, nvlist_t *);
};

struct vm_method {
	const char *name;
	int (*vm_start)(struct vm *, nvlist_t *);
	int (*vm_reset)(struct vm *, nvlist_t *);
	int (*vm_poweroff)(struct vm *, nvlist_t *);
	int (*vm_acpi_poweroff)(struct vm *, nvlist_t *);
	void (*vm_cleanup)(struct vm *, nvlist_t *);
};

#define PLUGIN_VERSION 13

/*
  Plugin Description

	   version: must set PLUGIN_VERSION
	      name: plugin name
	initialize: a function called after plugin is loaded.
	  finalize: a function called before plugin is removed.
  on_status_change: a function called when VM state changed. (*1)
      parse_config: a function called while parsing VM configuratin (*1)
  on_reload_config: copy plugin data while reloading VM configuration (*1)
	   prehook: a function called before executing loader and bhyve (*1)
	  prestart: a function called before starting VM.
	  poststop: a function called after stopping VM.

  *1: The nvlist_t pointer and struct vm pointer are available while VM is
      existing, unless VM is removed from the config file nor VM configuration
      is reloaded.

  All other pointers in arguments are local scope to the function.

  When VM configuration is reloaded, 'parse_config' is called and then
  'on_reload_confg' is called. Plugins have a chance to copy its data from
  old config to new one. The first argument of 'on_reload_config' is the
  new config and the second is the old one.

  `prestart` is used for external configurations such as firewall, routing, etc.
  `prestart` will be called before starting the VM.

  `prestart` has to run in the short term, because the bmd is implemented
  as an event machine. If 'prestart' runs for a long time, the bmd will
  be blocked all the operations from the client during that time. To get avoid
  blocking, `prestart` should fork a child process and wait for it.

  Returning a positive number from the 'prestart' function will delay
  invoking the loader and bhyve until the `plugin_start_virtual_machine`
  function is called. The `plugin_wait_for_process` function will wait for the
  child process termination and the callback function has to wait(2) and call
  the `plugin_start_virtual_machine` function if it succeeded, or call the
  `plugin_stop_virtual_machine` function if it failed.
  Returning zero from the 'prestart' function will invoke the loader and bhyve
  soon. Returning a negative number means an error occured in the function.
  The VM will not start by the error.

  `poststop` is used for clean up the external configurations for the VM.
  `poststop` has to run in the short term as same as 'prestart'. During
  the child process is running, the VM state keeps 'POSTSTOP' state.

  Returning a positive number from the 'poststop' function will delay
  cleanup the VM resources until the `plugin_cleanup_virtual_machine`
  function is called. Returning zero or a negative number will cleanup
  the VM resources soon.

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
	struct loader_method *loader_method;
	int (*prestart)(struct vm *, nvlist_t *);
	int (*poststop)(struct vm *, nvlist_t *);
} PLUGIN_DESC;

extern PLUGIN_DESC plugin_desc;

/*
  Plugin utilities.
 */
int plugin_wait_for_read_fd(int, plugin_call_back, void *);
int plugin_wait_for_write_fd(int, plugin_call_back, void *);
void plugin_stop_waiting_read_fd(int, void *);
void plugin_stop_waiting_write_fd(int, void *);
int plugin_wait_for_process(pid_t, plugin_call_back, void *);
int plugin_set_timer(int, plugin_call_back, void *);
int plugin_start_virtualmachine(PLUGIN_DESC *, struct vm *);
int plugin_stop_virtualmachine(PLUGIN_DESC *, struct vm *);
int plugin_cleanup_virtualmachine(PLUGIN_DESC *, struct vm *);
int register_vm_method(struct vm_method *);
int register_loader_method(struct loader_method *);
int plugin_logger(int, PLUGIN_DESC *, const char *, ...);
#define plugin_infolog(desc, fmt, ...) \
	plugin_logger(LOG_INFO, desc, fmt, __VA_ARGS__)
#define plugin_warnlog(desc, fmt, ...) \
	plugin_logger(LOG_WARN, desc, fmt, __VA_ARGS__)
#define plugin_errlog(desc, fmt, ...) \
	plugin_logger(LOG_ERR, desc, fmt, __VA_ARGS__)

#endif
