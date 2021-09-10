#ifndef _VARS_H_
#define _VARS_H_

#include <sys/types.h>
#include <sys/queue.h>

#include <stdbool.h>

#ifndef LOCALBASE
#define LOCALBASE "/usr/local"
#endif

struct global_conf {
	char *config_dir;
	char *plugin_dir;
	char *pid_path;
	char *cmd_sock_path;
	char *unix_domain_socket_mode;
	char *vm_name;
	int install;
	int config_fd;
	int plugin_fd;
	int cmd_sock;
	int foreground;
	int kq;
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

enum BOOT { NO, YES, ONESHOT, INSTALL, ALWAYS, REBOOT };

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

struct vm_conf {
	unsigned int nmdm;
	int boot_delay;
	int loader_timeout;
	int stop_timeout;
	char *debug_port;
	char *filename;
	char *ncpu;
	char *memory;
	char *name;
	char *comport;
	enum BOOT boot;
	char *loader;
	char *loadcmd;
	char *installcmd;
	char *hookcmd;
	char *err_logfile;
	struct fbuf *fbuf;
	bool mouse;
	bool wired_memory;
	bool utctime;
	int ndisks;
	int nisoes;
	int nnets;
	STAILQ_HEAD(, disk_conf) disks;
	STAILQ_HEAD(, iso_conf) isoes;
	STAILQ_HEAD(, net_conf) nets;
};

enum STATE {
	INIT,	   // initial state
	LOAD,	   // bhyveload or grub-bhyve
	RUN,	   // bhyve is running
	TERMINATE, // bhyve is terminated
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
};

#define PLUGIN_VERSION 1

typedef struct plugin_desc {
	int version;
	char *name;
	int (*initialize)(struct global_conf *);
	void (*finalize)(struct global_conf *);
	void (*on_status_change)(struct vm *, void **);
} PLUGIN_DESC;

#endif
