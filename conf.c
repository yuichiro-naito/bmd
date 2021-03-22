#include <sys/wait.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "vars.h"

void
free_disk_conf(struct disk_conf *c)
{
	if (c == NULL) return;
	free(c->type);
	free(c->path);
	free(c);
}

void
free_iso_conf(struct iso_conf *c)
{
	if (c == NULL) return;
	free(c->type);
	free(c->path);
	free(c);
}

void
free_net_conf(struct net_conf *c)
{
	if (c == NULL) return;
	free(c->type);
	free(c->bridge);
	free(c->tap);
	free(c);
}

void
free_fbuf(struct fbuf *f)
{
	if (f == NULL) return;
	free(f->ipaddr);
	free(f->vgaconf);
	free(f);
}

void
free_vm_conf(struct vm_conf *vc)
{
	struct disk_conf *dc, *dn;
	struct iso_conf *ic, *in;
	struct net_conf *nc, *nn;

	if (vc == NULL) return;
	free(vc->name);
	free(vc->ncpu);
	free(vc->memory);
	free(vc->comport);
	free(vc->loader);
	free(vc->loadcmd);
	free_fbuf(vc->fbuf);
	STAILQ_FOREACH_SAFE(dc, &vc->disks, next, dn)
		free_disk_conf(dc);
	STAILQ_FOREACH_SAFE(ic, &vc->isoes, next, in)
		free_iso_conf(ic);
	STAILQ_FOREACH_SAFE(nc, &vc->nets, next, nn)
		free_net_conf(nc);
	free(vc);
}

int
add_disk_conf(struct vm_conf *conf, char *type, char *path)
{
	struct disk_conf *t;
	if (conf == NULL) return 0;

	t = malloc(sizeof(struct disk_conf));
	if (t == NULL)
		return -1;
	t->type = strdup(type);
	t->path = strdup(path);

	STAILQ_INSERT_TAIL(&conf->disks, t, next);
	conf->ndisks++;
	return 0;
}

int
add_iso_conf(struct vm_conf *conf, char *type, char *path)
{
	struct iso_conf *t;
	if (conf == NULL) return 0;

	t = malloc(sizeof(struct iso_conf));
	if (t == NULL)
		return -1;
	t->type = strdup(type);
	t->path = strdup(path);

	STAILQ_INSERT_TAIL(&conf->isoes, t, next);
	conf->nisoes++;
	return 0;
}

int
add_net_conf(struct vm_conf *conf, char *type, char *bridge)
{
	struct net_conf *t;
	if (conf == NULL) return 0;

	t = malloc(sizeof(struct net_conf));
	if (t == NULL)
		return -1;
	t->type = strdup(type);
	t->bridge = strdup(bridge);
	t->tap = NULL;

	STAILQ_INSERT_TAIL(&conf->nets, t, next);
	conf->nnets++;
	return 0;
}

static int
set_string(char **var, char *value)
{
	char *new;

	if ((new = strdup(value)) == NULL)
		return -1;

	free(*var);
	*var = new;
	return 0;
}

int
set_name(struct vm_conf *conf, char *name)
{
	if (conf == NULL) return 0;
	return set_string(&conf->name, name);
}

int
set_loadcmd(struct vm_conf *conf, char *cmd)
{
	if (conf == NULL) return 0;
	return set_string(&conf->loadcmd, cmd);
}

int
set_loader(struct vm_conf *conf, char *loader)
{
	if (conf == NULL) return 0;
	return set_string(&conf->loader, loader);
}

int
set_memory_size(struct vm_conf *conf, char *memory)
{
	if (conf == NULL) return 0;
	return set_string(&conf->memory, memory);
}

int
set_comport(struct vm_conf *conf, char *com)
{
	if (conf == NULL) return 0;
	return set_string(&conf->comport, com);
}

int
set_ncpu(struct vm_conf *conf, int ncpu)
{
	char *new;

	if (conf == NULL) return 0;

	if ((asprintf(&new, "%d", ncpu)) < 0)
		return -1;

	free(conf->ncpu);
	conf->ncpu = new;
	return 0;
}

int
assign_nmdm(struct vm_conf *conf)
{
	static unsigned int max=0;

	if (conf == NULL) return 0;
	conf->nmdm = max++;

	free(conf->comport);
	asprintf(&conf->comport, "/dev/nmdm%uB", conf->nmdm);
	if (conf->comport == NULL)
		return -1;

	return 0;
}

int
set_boot(struct vm_conf *conf, enum BOOT boot)
{
	if (conf == NULL) return 0;

	conf->boot = boot;
	return 0;
}

int
set_fbuf_enable(struct fbuf *fb, bool enable)
{
	if (fb == NULL) return 0;
	fb->enable = enable;
	return 0;
}

int
set_fbuf_ipaddr(struct fbuf *fb, char *ipaddr)
{
	int ret;
	if (fb == NULL) return 0;

	ret = set_string(&fb->ipaddr, ipaddr);
	if (ret == 0)
		fb->enable = 1;
	return ret;
}

int
set_fbuf_port(struct fbuf *fb, int port)
{
	if (fb == NULL) return 0;

	fb->port = port;
	fb->enable = 1;
	return 0;
}

int
set_fbuf_res(struct fbuf *fb, int width, int height)
{
	if (fb == NULL) return 0;

	fb->width = width;
	fb->height = height;
	fb->enable = 1;
	return 0;
}

int
set_fbuf_vgaconf(struct fbuf *fb, char *vga)
{
	int ret;
	if (fb == NULL) return 0;

	ret = set_string(&fb->vgaconf,vga);
	if (ret == 0)
		fb->enable = 1;
	return ret;
}

int
set_fbuf_wait(struct fbuf *fb, int wait)
{
	fb->wait = wait;
	return 0;
}

struct fbuf *
create_fbuf()
{
	struct fbuf *ret;
	char *addr, *vga;
	ret = calloc(1, sizeof(typeof(*ret)));
	addr = strdup("0.0.0.0");
	vga = strdup("io");
	if (ret == NULL || addr == NULL || vga == NULL)
		goto err;

	ret->ipaddr = addr;
	ret->vgaconf = vga;
	ret->port = 5900;
	ret->width = 1024;
	ret->height = 768;
	return ret;
err:
	free(ret);
	free(addr);
	free(vga);
	return NULL;
}

struct vm_conf *
create_vm_conf(char *name)
{
	struct vm_conf *ret;
	struct fbuf *fbuf;
	char *com;

	ret = calloc(1, sizeof(typeof(*ret)));
	fbuf = create_fbuf();
	name = strdup(name);
	com = strdup("stdio");
	if (ret == NULL || fbuf == NULL || name == NULL || com == NULL)
		goto err;

	ret->fbuf = fbuf;
	ret->name = name;
	ret->comport = com;
	ret->nmdm = -1;

	STAILQ_INIT(&ret->disks);
	STAILQ_INIT(&ret->isoes);
	STAILQ_INIT(&ret->nets);

	return ret;
err:
	free(ret);
	free(fbuf);
	free(name);
	free(com);
	return NULL;
}

int
dump_vm_conf(struct vm_conf *conf)
{
	int i;
	struct disk_conf *dc;
	struct iso_conf *ic;
	struct net_conf *nc;
	struct fbuf *fb;
	static char *btype[] = {
		"no", "yes", "delayed", "oneshot", "install"
	};

	printf("name: %s\n", conf->name);
	printf("ncpu: %s\n", conf->ncpu);
	printf("memory: %s\n", conf->memory);
	printf("comport: %s\n", conf->comport);
	printf("boot: %s\n", btype[conf->boot]);
	printf("loader: %s\n", conf->loader);
	printf("loadcmd: %s\n", conf->loadcmd);
	i = 0;
	STAILQ_FOREACH(dc, &conf->disks, next)
		printf("disk%d: %s,%s\n", i++, dc->type, dc->path);
	i = 0;
	STAILQ_FOREACH(ic, &conf->isoes, next)
		printf("iso%d: %s,%s\n", i++, ic->type, ic->path);
	i = 0;
	STAILQ_FOREACH(nc, &conf->nets, next)
		printf("net%d: %s,%s\n", i++, nc->type, nc->bridge);

	fb = conf->fbuf;
	if (fb->enable) {
		printf("graphics: %s:%d, %dx%d, %s, %s\n",
		       fb->ipaddr,fb->port, fb->width, fb->height,
		       fb->vgaconf, fb->wait ? "wait" : "nowait");
	}
	return 0;
}
