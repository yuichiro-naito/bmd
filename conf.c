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
}

void
free_iso_conf(struct iso_conf *c)
{
	if (c == NULL) return;
	free(c->type);
	free(c->path);
}

void
free_net_conf(struct net_conf *c)
{
	if (c == NULL) return;
	free(c->type);
	free(c->bridge);
	free(c->tap);
}

void
free_vm_conf(struct vm_conf *vc)
{
	struct disk_conf *dc;
	struct iso_conf *ic;
	struct net_conf *nc;

	if (vc == NULL) return;
	free(vc->name);
	free(vc->console);
	STAILQ_FOREACH(dc, &vc->disks, next)
		free_disk_conf(dc);
	STAILQ_FOREACH(ic, &vc->isoes, next)
		free_iso_conf(ic);
	STAILQ_FOREACH(nc, &vc->nets, next)
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

int
set_name(struct vm_conf *conf, char *name)
{
	char *new;

	if (conf == NULL)
		return 0;

	if ((new = strdup(name)) == NULL)
		return -1;

	free(conf->name);
	conf->name = new;
	return 0;
}

int
set_loadcmd(struct vm_conf *conf, char *cmd)
{
	char *new;

	if (conf == NULL)
		return 0;

	if ((new = strdup(cmd)) == NULL)
		return -1;

	free(conf->loadcmd);
	conf->loadcmd = new;
	return 0;
}

int
set_memory_size(struct vm_conf *conf, char *memory)
{
	char *new;

	if (conf == NULL) return 0;
	if ((new = strdup(memory)) == NULL)
		return -1;

	free(conf->memory);
	conf->memory = new;
	return 0;
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

	free(conf->console);
	asprintf(&conf->console, "/dev/nmdm%uB", conf->nmdm);
	if (conf->console == NULL)
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

struct vm_conf *
create_vm_conf(char *name)
{
	struct vm_conf *ret;

	ret = malloc(sizeof(struct vm_conf));
	if (ret == NULL) return NULL;
	ret->name = strdup(name);
	ret->console = strdup("stdio");
	ret->nmdm = -1;
	ret->ncpu = 0;
	ret->memory = 0;
	ret->pid = 0;
	ret->ndisks = 0;
	ret->nisoes = 0;
	ret->nnets = 0;
	STAILQ_INIT(&ret->disks);
	STAILQ_INIT(&ret->isoes);
	STAILQ_INIT(&ret->nets);

	return ret;
}

int
dump_vm_conf(struct vm_conf *conf)
{
	struct disk_conf *dc;
	struct iso_conf *ic;
	struct net_conf *nc;
	static char *btype[] = {
		"no", "yes", "delayed", "oneshot", "install"
	};

	printf("name: %s\n", conf->name);
	printf("ncpu: %s\n", conf->ncpu);
	printf("memory: %s\n", conf->memory);
	printf("console: %s\n", conf->console);
	printf("boot: %s\n", btype[conf->boot]);
	printf("loadcmd: %s\n", conf->loadcmd);
	printf("disk:");
	STAILQ_FOREACH(dc, &conf->disks, next)
		printf(" %s,%s", dc->type, dc->path);
	printf("\niso:");
	STAILQ_FOREACH(ic, &conf->isoes, next)
		printf(" %s,%s", ic->type, ic->path);
	printf("\nnet:");
	STAILQ_FOREACH(nc, &conf->nets, next)
		printf(" %s,%s", nc->type, nc->bridge);
	printf("\n");

	return 0;
}
