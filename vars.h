#ifndef _VARS_H_
#define _VARS_H_

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/event.h>
#include <stdbool.h>

struct global_conf {
	char *config_dir;
	char *plugin_dir;
	int config_fd;
	int plugin_fd;
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

enum BOOT {
	NO,
	YES,
	ONESHOT,
	INSTALL,
	ALWAYS
};

struct fbuf {
	bool enable;
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
	char *ncpu;
	char *memory;
	char *name;
	char *comport;
	enum BOOT boot;
	char *loader;
	char *loadcmd;
	struct fbuf *fbuf;
	bool mouse;
	int ndisks;
	int nisoes;
	int nnets;
	STAILQ_HEAD(, disk_conf) disks;
	STAILQ_HEAD(, iso_conf) isoes;
	STAILQ_HEAD(, net_conf) nets;
};

enum STATE {
	INIT,
	LOAD,
	RUN,
	TERMINATE
};

struct vm {
	struct vm_conf *conf;
	pid_t pid;
	enum STATE state;
	char *mapfile;
	int infd;
	int outfd;
	int errfd;
};

#define PLUGIN_VERSION 1

typedef struct plugin_desc {
	int version;
	char *name;
	int (*initialize)(struct global_conf*);
	void (*finalize)(struct global_conf*);
	void (*on_status_change)(struct vm*, void**);
} PLUGIN_DESC;

#endif
