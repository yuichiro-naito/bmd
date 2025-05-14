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
#include <sys/param.h>

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "bmd.h"
#include "bmd_plugin.h"
#include "conf.h"
#include "log.h"

#define CMP(a, b) ((a) < (b) ? -1 : ((a) == (b) ? 0 : 1))
#define CMP_RETURN(a, b) \
	if ((a) != (b))  \
	return (a) < (b) ? -1 : 1

struct id_entry {
	SLIST_ENTRY(id_entry) next;
	unsigned int id;
	char name[0];
};

/*
  List of identfiers.
 */
static SLIST_HEAD(, id_entry) id_list = SLIST_HEAD_INITIALIZER();

static int compare_variable_key(struct conf_var *, struct conf_var *);
RB_GENERATE_STATIC(vartree, conf_var, entry, compare_variable_key);
struct vartree *global_vars = NULL;

#define generate_list_getter(type, member)            \
	struct type *get_##type(struct vm_conf *conf) \
	{                                             \
		return STAILQ_FIRST(&conf->member);   \
	}                                             \
	struct type *next_##type(struct type *p)      \
	{                                             \
		return STAILQ_NEXT(p, next);          \
	}

#define generate_member_getter(rtype, type, member) \
	rtype get_##type##_##member(struct type *p) \
	{                                           \
		return p->member;                   \
	}

#define generate_member_bool(type, member)        \
	bool is_##type##_##member(struct type *p) \
	{                                         \
		return p->member;                 \
	}

#define generate_clear_list(type, member)                     \
	void clear_##type(struct vm_conf *vc)                 \
	{                                                     \
		struct type *p, *pn;                          \
		STAILQ_FOREACH_SAFE(p, &vc->member, next, pn) \
			free_##type(p);                       \
		STAILQ_INIT(&vc->member);                     \
	}

#define generate_getter(rtype, member)        \
	rtype get_##member(struct vm_conf *c) \
	{                                     \
		return c->member;             \
	}

#define generate_string_accessor(member)                   \
	char *get_##member(struct vm_conf *c)              \
	{                                                  \
		return c->member;                          \
	}                                                  \
	int set_##member(struct vm_conf *c, const char *v) \
	{                                                  \
		if (c == NULL)                             \
			return -1;                         \
		return set_string(&c->member, v);          \
	}

#define generate_number_accessor(type, member)      \
	type get_##member(struct vm_conf *c)        \
	{                                           \
		return c->member;                   \
	}                                           \
	int set_##member(struct vm_conf *c, type v) \
	{                                           \
		if (c == NULL)                      \
			return -1;                  \
		c->member = v;                      \
		return 0;                           \
	}

#define generate_bool_accessor(member)              \
	bool is_##member(struct vm_conf *c)         \
	{                                           \
		return c->member;                   \
	}                                           \
	int set_##member(struct vm_conf *c, bool v) \
	{                                           \
		if (c == NULL)                      \
			return -1;                  \
		c->member = v;                      \
		return 0;                           \
	}

#define generate_vm_accessor(type, member)       \
	type get_##member(struct vm *vm)         \
	{                                        \
		return vm->member;               \
	}                                        \
	void set_##member(struct vm *vm, type v) \
	{                                        \
		vm->member = v;                  \
	}

void
free_id_list(void)
{
	struct id_entry *e, *t;

	SLIST_FOREACH_SAFE(e, &id_list, next, t)
		free(e);
	SLIST_INIT(&id_list);
}

static int
assign_id(const char *name, unsigned int *id)
{
	static unsigned int lastid = 0;
	struct id_entry *e;

	SLIST_FOREACH(e, &id_list, next)
		if (strcmp(e->name, name) == 0) {
			*id = e->id;
			return 0;
		}
	if ((e = malloc(sizeof(*e) + strlen(name) + 1)) == NULL)
		return -1;
	strcpy(e->name, name);
	*id = e->id = lastid++;
	SLIST_INSERT_HEAD(&id_list, e, next);
	return 0;
}

void
free_passthru_conf(struct passthru_conf *c)
{
	if (c == NULL)
		return;
	free(c->devid);
	free(c);
}

void
free_disk_conf(struct disk_conf *c)
{
	if (c == NULL)
		return;
	free(c->type);
	free(c->path);
	free(c);
}

void
free_iso_conf(struct iso_conf *c)
{
	if (c == NULL)
		return;
	free(c->type);
	free(c->path);
	free(c);
}

void
free_net_conf(struct net_conf *c)
{
	if (c == NULL)
		return;
	free(c->type);
	free(c->bridge);
	free(c->tap);
	free(c->vale);
	free(c->vale_port);
	free(c->mac);
	free(c);
}

void
free_sharefs_conf(struct sharefs_conf *c)
{
	if (c == NULL)
		return;
	free(c->name);
	free(c->path);
	free(c);
}

void
free_fbuf(struct fbuf *f)
{
	if (f == NULL)
		return;
	free(f->ipaddr);
	free(f->vgaconf);
	free(f->password);
	free(f);
}

void
free_hda_conf(struct hda_conf *c)
{
	if (c == NULL)
		return;
	free(c->play_dev);
	free(c->rec_dev);
	free(c);
}

generate_clear_list(passthru_conf, passthrues);
generate_clear_list(disk_conf, disks);
generate_clear_list(iso_conf, isoes);
generate_clear_list(net_conf, nets);
generate_clear_list(sharefs_conf, sharefss);
generate_clear_list(bhyveload_env, bhyveload_envs);
generate_clear_list(bhyve_env, bhyve_envs);
generate_clear_list(cpu_pin, cpu_pins);
generate_clear_list(hda_conf, hdas);

static void
free_var(struct conf_var *c)
{
	if (c == NULL)
		return;
	free(c->key);
	free(c->val);
	free(c);
}

void
free_vartree(struct vartree *vt)
{
	struct conf_var *v, *vn;

	RB_FOREACH_SAFE(v, vartree, vt, vn) {
		RB_REMOVE(vartree, vt, v);
		free_var(v);
	}
	free(vt);
}

void
free_vm_conf(struct vm_conf *vc)
{
	char **com;

	if (vc == NULL)
		return;

	free_vartree(vc->vars.local);

	free(vc->name);
	free(vc->memory);
	ARRAY_FOREACH(com, vc->com)
		free(*com);
	free(vc->loader);
	free(vc->loadcmd);
	free(vc->installcmd);
	free(vc->backend);
	free(vc->debug_port);
	free(vc->err_logfile);
	free(vc->grub_run_partition);
	free_fbuf(vc->fbuf);
	clear_passthru_conf(vc);
	clear_disk_conf(vc);
	clear_iso_conf(vc);
	clear_net_conf(vc);
	clear_sharefs_conf(vc);
	free(vc->keymap);
	free(vc->bhyveload_loader);
	clear_bhyveload_env(vc);
	clear_bhyve_env(vc);
	clear_cpu_pin(vc);
	free(vc->tpm_dev);
	free(vc->tpm_type);
	free(vc->tpm_version);
	clear_hda_conf(vc);
	free(vc);
}

int
add_passthru_conf(struct vm_conf *conf, const char *devid)
{
	struct passthru_conf *p;
	char *d;
	if (conf == NULL)
		return 0;

	p = malloc(sizeof(struct passthru_conf));
	d = strdup(devid);
	if (p == NULL || d == NULL)
		goto err;
	p->devid = d;

	STAILQ_INSERT_TAIL(&conf->passthrues, p, next);
	conf->npassthrues++;
	set_wired_memory(conf, true);
	return 0;
err:
	free(d);
	free(p);
	return -1;
}

generate_list_getter(passthru_conf, passthrues);
generate_member_getter(char *, passthru_conf, devid);

int
add_disk_conf(struct vm_conf *conf, const char *type, const char *path,
    bool nocache, bool direct, bool readonly, bool nodelete, bool noexist)
{
	struct disk_conf *t;
	char *y, *p;
	if (conf == NULL)
		return 0;

	t = malloc(sizeof(struct disk_conf));
	y = strdup(type);
	p = strdup(path);
	if (t == NULL || y == NULL || p == NULL)
		goto err;
	t->type = y;
	t->path = p;
	t->nocache = nocache;
	t->direct = direct;
	t->readonly = readonly;
	t->nodelete = nodelete;
	t->noexist = noexist;

	STAILQ_INSERT_TAIL(&conf->disks, t, next);
	conf->ndisks++;
	return 0;
err:
	free(p);
	free(y);
	free(t);
	return -1;
}

generate_list_getter(disk_conf, disks);
generate_member_getter(char *, disk_conf, type);
generate_member_getter(char *, disk_conf, path);
generate_member_bool(disk_conf, nocache);
generate_member_bool(disk_conf, direct);
generate_member_bool(disk_conf, readonly);
generate_member_bool(disk_conf, nodelete);
generate_member_bool(disk_conf, noexist);

int
add_hda_conf(struct vm_conf *conf, const char *play, const char *rec)
{
	struct hda_conf *h;
	char *p, *r;
	if (conf == NULL)
		return 0;

	h = malloc(sizeof(struct hda_conf));
	p = strdup(play);
	r = strdup(rec);
	if (h == NULL || p == NULL || r == NULL)
		goto err;
	h->play_dev = p;
	h->rec_dev = r;

	STAILQ_INSERT_TAIL(&conf->hdas, h, next);
	conf->nhdas++;
	return 0;
err:
	free(h);
	free(p);
	free(r);
	return -1;
}

generate_list_getter(hda_conf, hdas);
generate_member_getter(char *, hda_conf, play_dev);
generate_member_getter(char *, hda_conf, rec_dev);

int
add_iso_conf(struct vm_conf *conf, const char *type, const char *path)
{
	struct iso_conf *t;
	char *y, *p;
	if (conf == NULL)
		return 0;

	t = malloc(sizeof(struct iso_conf));
	y = strdup(type);
	p = strdup(path);
	if (t == NULL)
		goto err;
	t->type = y;
	t->path = p;

	STAILQ_INSERT_TAIL(&conf->isoes, t, next);
	conf->nisoes++;
	return 0;
err:
	free(p);
	free(y);
	free(t);
	return -1;
}

generate_list_getter(iso_conf, isoes);
generate_member_getter(char *, iso_conf, type);
generate_member_getter(char *, iso_conf, path);

int
add_net_conf(struct vm_conf *conf, const char *type, const char *eaddr,
    const char *bridge, bool wol)
{
	bool is_vale;
	struct net_conf *t;
	char *y, *b, *e = NULL;
	if (conf == NULL)
		return 0;

	is_vale = (strncmp(bridge, "vale", 4) == 0);

	t = calloc(1, sizeof(struct net_conf));
	y = strdup(type);
	b = strdup(bridge);
	if (t == NULL || y == NULL || b == NULL)
		goto err;

	if (eaddr && strlen(eaddr) > 10) {
		if ((e = strdup(eaddr)) == NULL)
			goto err;
		t->mac = e;
	}

	if (is_vale) {
		if (asprintf(&t->vale_port, "vm%dp%d", conf->id, conf->nnets) <
		    0)
			goto err;
		t->vale = b;
	} else
		t->bridge = b;
	t->type = y;
	t->tap = NULL;
	t->wol = wol;

	STAILQ_INSERT_TAIL(&conf->nets, t, next);
	conf->nnets++;
	return 0;
err:
	free(b);
	free(y);
	free(e);
	free(t);
	return -1;
}

generate_list_getter(net_conf, nets);
generate_member_getter(char *, net_conf, type);
generate_member_getter(char *, net_conf, bridge);
generate_member_getter(char *, net_conf, mac);
generate_member_getter(char *, net_conf, tap);
generate_member_getter(char *, net_conf, vale);
generate_member_getter(char *, net_conf, vale_port);
generate_member_getter(bool, net_conf, wol);

int
add_sharefs_conf(struct vm_conf *conf, const char *name, const char *path,
    bool ro)
{
	struct sharefs_conf *t;
	char *n, *p;

	t = calloc(1, sizeof(struct sharefs_conf));
	n = strdup(name);
	p = strdup(path);
	if (t == NULL || n == NULL || p == NULL)
		goto err;
	t->name = n;
	t->path = p;
	t->readonly = ro;
	STAILQ_INSERT_TAIL(&conf->sharefss, t, next);
	conf->nsharefs++;
	return 0;
err:
	free(t);
	free(n);
	free(p);
	return -1;
}

generate_list_getter(sharefs_conf, sharefss);
generate_member_getter(char *, sharefs_conf, name);
generate_member_getter(char *, sharefs_conf, path);
generate_member_bool(sharefs_conf, readonly);

int
add_bhyveload_env(struct vm_conf *conf, const char *env)
{
	struct bhyveload_env *be;

	if (conf == NULL)
		return 0;

	if (env == NULL || (be = malloc(sizeof(*be) + strlen(env) + 1)) == NULL)
		return -1;
	strcpy(be->env, env);

	STAILQ_INSERT_TAIL(&conf->bhyveload_envs, be, next);
	conf->nbhyveload_envs++;
	return 0;
}

generate_list_getter(bhyveload_env, bhyveload_envs);
generate_member_getter(char *, bhyveload_env, env);

int
add_bhyve_env(struct vm_conf *conf, const char *env)
{
	struct bhyve_env *be;

	if (conf == NULL)
		return 0;

	if (env == NULL || (be = malloc(sizeof(*be) + strlen(env) + 1)) == NULL)
		return -1;
	strcpy(be->env, env);

	STAILQ_INSERT_TAIL(&conf->bhyve_envs, be, next);
	conf->nbhyve_envs++;
	return 0;
}

generate_list_getter(bhyve_env, bhyve_envs);
generate_member_getter(char *, bhyve_env, env);

int
add_cpu_pin(struct vm_conf *conf, int vcpu, int hostcpu)
{
	struct cpu_pin *pin;

	if (conf == NULL)
		return 0;

	if ((pin = malloc(sizeof(struct cpu_pin))) == NULL)
		return -1;
	pin->vcpu = vcpu;
	pin->hostcpu = hostcpu;

	STAILQ_INSERT_TAIL(&conf->cpu_pins, pin, next);
	conf->ncpu_pins++;
	return 0;
}

generate_list_getter(cpu_pin, cpu_pins);
generate_member_getter(int, cpu_pin, vcpu);
generate_member_getter(int, cpu_pin, hostcpu);

struct net_conf *
copy_net_conf(const struct net_conf *nc)
{
	struct net_conf *ret;
	char *y, *b, *t, *v, *m, *vp;

#define DUPLICATE_STRING(str)	(str) ? strdup(str) : NULL
#define CHECK_DUP_ERR(src, dst) (src != NULL && dst == NULL)
	ret = malloc(sizeof(struct net_conf));
	y = strdup(nc->type);
	b = DUPLICATE_STRING(nc->bridge);
	t = DUPLICATE_STRING(nc->tap);
	m = DUPLICATE_STRING(nc->mac);
	v = DUPLICATE_STRING(nc->vale);
	vp = DUPLICATE_STRING(nc->vale_port);
	if (ret == NULL || y == NULL || CHECK_DUP_ERR(nc->bridge, b) ||
	    CHECK_DUP_ERR(nc->tap, t) || CHECK_DUP_ERR(nc->mac, m) ||
	    CHECK_DUP_ERR(nc->vale, v) || CHECK_DUP_ERR(nc->vale_port, vp))
		goto err;
#undef CHECK_DUP_ERR
#undef DUPLICATE_STRING

	ret->type = y;
	ret->bridge = b;
	ret->tap = t;
	ret->mac = m;
	ret->vale = v;
	ret->vale_port = vp;
	STAILQ_NEXT(ret, next) = NULL;
	return ret;
err:
	free(t);
	free(b);
	free(y);
	free(m);
	free(v);
	free(vp);
	free(ret);
	return NULL;
}

int
set_string(char **var, const char *value)
{
	char *new;

	if ((new = strdup(value)) == NULL)
		return -1;

	free(*var);
	*var = new;
	return 0;
}

generate_getter(unsigned int, id);
generate_string_accessor(name);
generate_string_accessor(loadcmd);
generate_string_accessor(installcmd);
generate_string_accessor(err_logfile);
generate_string_accessor(loader);
generate_string_accessor(bhyveload_loader);
generate_number_accessor(int, loader_timeout);
generate_number_accessor(int, stop_timeout);
generate_string_accessor(grub_run_partition);
generate_string_accessor(debug_port);
generate_string_accessor(memory);

int
set_ncpu(struct vm_conf *conf, int ncpu)
{
	if (conf == NULL)
		return 0;

	conf->ncpu = ncpu;
	conf->ncpu_sockets = ncpu;
	conf->ncpu_cores = 1;
	conf->ncpu_threads = 1;
	return 0;
}

int
set_cpu_topology(struct vm_conf *conf, int ncpu[3])
{
	if (conf == NULL)
		return 0;

	conf->ncpu = ncpu[0] * ncpu[1] * ncpu[2];
	conf->ncpu_sockets = ncpu[0];
	conf->ncpu_cores = ncpu[1];
	conf->ncpu_threads = ncpu[2];

	return 0;
}

generate_getter(int, ncpu);
generate_getter(int, ncpu_sockets);
generate_getter(int, ncpu_cores);
generate_getter(int, ncpu_threads);
generate_number_accessor(uid_t, owner);
generate_number_accessor(gid_t, group);
generate_number_accessor(enum BOOT, boot);
generate_number_accessor(enum HOSTBRIDGE_TYPE, hostbridge);
generate_string_accessor(backend);
generate_string_accessor(keymap);
generate_number_accessor(int, boot_delay);
generate_bool_accessor(reboot_on_change);
generate_bool_accessor(single_user);
generate_bool_accessor(install);
generate_bool_accessor(virt_random);
generate_bool_accessor(x2apic);

int
set_fbuf_enable(struct fbuf *fb, bool enable)
{
	if (fb == NULL)
		return 0;
	fb->enable = enable;
	return 0;
}

bool
is_fbuf_enable(struct vm_conf *conf)
{
	return conf->fbuf->enable;
}

int
set_fbuf_ipaddr(struct fbuf *fb, const char *ipaddr)
{
	int ret;
	if (fb == NULL)
		return 0;

	ret = set_string(&fb->ipaddr, ipaddr);
	if (ret == 0 && fb->enable < 0)
		fb->enable = true;
	return ret;
}

char *
get_fbuf_ipaddr(struct vm_conf *conf)
{
	return conf->fbuf->ipaddr;
}

int
set_fbuf_port(struct fbuf *fb, int port)
{
	if (fb == NULL)
		return 0;

	fb->port = port;
	if (fb->enable < 0)
		fb->enable = true;
	return 0;
}

int
get_fbuf_port(struct vm_conf *conf)
{
	return conf->fbuf->port;
}

int
set_fbuf_res(struct fbuf *fb, int width, int height)
{
	if (fb == NULL)
		return 0;

	fb->width = width;
	fb->height = height;
	if (fb->enable < 0)
		fb->enable = true;
	return 0;
}

void
get_fbuf_res(struct vm_conf *conf, int *width, int *height)
{
	if (width)
		*width = conf->fbuf->width;
	if (height)
		*height = conf->fbuf->height;
}

int
set_fbuf_vgaconf(struct fbuf *fb, const char *vga)
{
	int ret;
	if (fb == NULL)
		return 0;

	ret = set_string(&fb->vgaconf, vga);
	if (ret == 0 && fb->enable < 0)
		fb->enable = 1;
	return ret;
}

char *
get_fbuf_vgaconf(struct vm_conf *conf)
{
	return conf->fbuf->vgaconf;
}

int
set_fbuf_wait(struct fbuf *fb, int wait)
{
	fb->wait = wait;
	return 0;
}

int
get_fbuf_wait(struct vm_conf *conf)
{
	return conf->fbuf->wait;
}

int
set_fbuf_password(struct fbuf *fb, const char *pass)
{
	int ret;
	if (fb == NULL)
		return 0;

	ret = set_string(&fb->password, pass);
	if (ret == 0 && fb->enable < 0)
		fb->enable = true;
	return ret;
}

char *
get_fbuf_password(struct vm_conf *conf)
{
	return conf->fbuf->password;
}

generate_bool_accessor(mouse);
generate_bool_accessor(wired_memory);
generate_bool_accessor(utctime);
generate_string_accessor(tpm_dev);
generate_string_accessor(tpm_type);
generate_string_accessor(tpm_version);

generate_vm_accessor(int, infd);
generate_vm_accessor(int, outfd);
generate_vm_accessor(int, errfd);
generate_vm_accessor(int, logfd);
generate_vm_accessor(id_t, load_cmd_supplier);
generate_vm_accessor(enum STATE, state);

char *
get_assigned_comport(struct vm *vm)
{
	return vm->assigned_com[0];
}

int
set_com(struct vm_conf *c, unsigned int i, const char *v)
{
	if (c == NULL)
		return -1;
	return set_string(&c->com[i], v);
}

char *
get_comport(struct vm_conf *conf)
{
	return conf->com[0];
}

char *
get_com(struct vm_conf *conf, unsigned int i)
{
	if (i >= nitems(conf->com))
		return NULL;

	return conf->com[i];
}

char *
get_assigned_com(struct vm *vm, unsigned int i)
{
	if (i >= nitems(vm->assigned_com))
		return NULL;

	return vm->assigned_com[i];
}

void
set_pid(struct vm *vm, pid_t pid)
{
	vm->pid = pid;
}

int
set_bootrom(struct vm *vm, const char *rom)
{
	return set_string(&vm->bootrom, rom);
}

const char *
get_mapfile(struct vm *vm)
{
	return vm->mapfile;
}

int
set_mapfile(struct vm *vm, const char *mapfile)
{
	return set_string(&vm->mapfile, mapfile);
}

const char *
get_varsdir(void)
{
	return gl_conf->vars_dir;
}

const char *
get_varsfile(struct vm *vm)
{
	return vm->varsfile;
}

int
set_varsfile(struct vm *vm, const char *varsfile)
{
	return set_string(&vm->varsfile, varsfile);
}

void
free_mapfile(struct vm *vm)
{
	free(vm->mapfile);
	vm->mapfile = NULL;
}

struct vm_conf *
vm_get_conf(struct vm *vm)
{
	return vm->conf;
}

struct net_conf *
get_taps(struct vm *vm)
{
	return STAILQ_FIRST(&vm->taps);
}

struct fbuf *
create_fbuf(void)
{
	struct fbuf *ret;
	char *addr, *vga;
	ret = calloc(1, sizeof(typeof(*ret)));
	addr = strdup("0.0.0.0");
	vga = strdup("io");
	if (ret == NULL || addr == NULL || vga == NULL)
		goto err;

	ret->enable = -1;
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
create_vm_conf(const char *vm_name)
{
	char *name, *backend, idnum[12];
	struct vm_conf *ret;
	struct fbuf *fbuf;
	unsigned int id;
	struct vartree *local;

	ret = calloc(1, sizeof(typeof(*ret)));
	fbuf = create_fbuf();
	name = strdup(vm_name);
	backend = strdup("bhyve");
	local = malloc(sizeof(*local));
	if (ret == NULL || fbuf == NULL || name == NULL || backend == NULL ||
	    local == NULL)
		goto err;

	RB_INIT(local);
	ret->vars.local = local;
	ret->vars.args = NULL;
	if (set_var0(local, "NAME", name) < 0)
		ERR("failed to set \"NAME\" variable! (%s)\n", strerror(errno));
	if (assign_id(name, &id) == 0) {
		snprintf(idnum, sizeof(idnum), "%u", id);
		if (set_var0(local, "ID", idnum) < 0)
			ERR("failed to set \"ID\" variable! (%s)\n",
			    strerror(errno));
		ret->id = id;
	} else {
		ERR("failed to allocate \"ID\" number! (%s)\n",
		    strerror(errno));
		free_vartree(local);
		local = NULL;
		goto err;
	}
	ret->ncpu = 1;
	ret->ncpu_sockets = 1;
	ret->ncpu_cores = 1;
	ret->ncpu_threads = 1;
	ret->hostbridge = INTEL;
	ret->fbuf = fbuf;
	ret->name = name;
	ret->loader_timeout = 15;
	ret->stop_timeout = 300;
	ret->utctime = true;
	ret->backend = backend;
	ret->group = -1;

	STAILQ_INIT(&ret->disks);
	STAILQ_INIT(&ret->isoes);
	STAILQ_INIT(&ret->nets);
	STAILQ_INIT(&ret->sharefss);
	STAILQ_INIT(&ret->bhyveload_envs);
	STAILQ_INIT(&ret->bhyve_envs);
	STAILQ_INIT(&ret->cpu_pins);
	STAILQ_INIT(&ret->hdas);

	return ret;
err:
	ERR("failed to create VM config! (%s)\n", strerror(errno));
	free(local);
	free(ret);
	free(backend);
	free(fbuf);
	free(name);
	return NULL;
}

int
finalize_vm_conf(struct vm_conf *conf)
{
	if (conf == NULL || conf->fbuf == NULL)
		return -1;

	if (conf->fbuf->enable < 0)
		conf->fbuf->enable = false;

	return 0;
}

static int
vputenv(const char *fmt, ...)
{
	int rc;
	char *s;
	va_list ap;

	va_start(ap, fmt);
	rc = vasprintf(&s, fmt, ap);
	va_end(ap);
	if (rc < 0)
		return -1;

	if (putenv(s) < 0) {
		free(s);
		return -1;
	}

	return 0;
}

static char *
capitalize(char *buf, size_t bufsize, const char *str)
{
	unsigned int i;
	size_t len = strlen(str) + 1;

	for (i = 0; i < MIN(bufsize, len) - 1; i++)
		buf[i] = toupper(str[i]);
	buf[i] = '\0';
	return buf;
}

int
vm_conf_export_env(struct vm_conf *conf)
{
	int i;
	struct disk_conf *dc;
	struct iso_conf *ic;
	struct net_conf *nc;
	struct sharefs_conf *sc;
	struct passthru_conf *pc;
	struct bhyveload_env *be;
	struct bhyve_env *ev;
	struct cpu_pin *cp;
	struct hda_conf *hc;
	struct fbuf *fb;
	const static char *btype[] = { "no", "yes", "oneshot", "install",
		"always", "reboot" };
	const static char *hostbridge_str[] = { "none", "intel", "amd" };
	const static char *bool_str[] = { "false", "true" };
	char **com, buf[32];
	struct vm_entry *vm_ent;
	struct vm *vm;

	if ((vm_ent = lookup_vm_by_name(conf->name)) == NULL)
		return -1;
	vm = VM_PTR(vm_ent);

#define ENV_PREFIX "VM_"
#define VPUTSTR(v) \
	vputenv(ENV_PREFIX "%s=%s", capitalize(buf, sizeof(buf), #v), conf->v)
#define VPUTINT(v) \
	vputenv(ENV_PREFIX "%s=%d", capitalize(buf, sizeof(buf), #v), conf->v)
#define VPUTBOOL(v)                                                   \
	vputenv(ENV_PREFIX "%s=%s", capitalize(buf, sizeof(buf), #v), \
	    bool_str[conf->v])

	VPUTINT(id);
	VPUTSTR(name);
	VPUTINT(owner);
	VPUTINT(group);
	VPUTINT(ncpu);
	VPUTINT(ncpu_pins);
	i = 1;
	STAILQ_FOREACH(cp, &conf->cpu_pins, next)
		vputenv(ENV_PREFIX "CPU_PIN%d=%d:%d", i++, cp->vcpu,
		    cp->hostcpu);
	VPUTSTR(memory);
	VPUTBOOL(wired_memory);
	VPUTBOOL(utctime);
	VPUTBOOL(reboot_on_change);
	VPUTBOOL(single_user);
	VPUTBOOL(install);
	VPUTBOOL(virt_random);
	VPUTBOOL(x2apic);
	ARRAY_FOREACH(com, vm->assigned_com)
		if (*com != NULL)
			vputenv(ENV_PREFIX "COM%ld=%s",
			    CONF_COM_NUM(com, vm->assigned_com), *com);
	VPUTSTR(debug_port);
	vputenv(ENV_PREFIX "BOOT=%s", btype[conf->boot]);
	VPUTINT(boot_delay);
	VPUTINT(loader_timeout);
	VPUTINT(stop_timeout);
	VPUTSTR(loader);
	VPUTSTR(bhyveload_loader);
	VPUTINT(nbhyveload_envs);
	i = 1;
	STAILQ_FOREACH(be, &conf->bhyveload_envs, next)
		vputenv(ENV_PREFIX "BHYVE_LOADENV%d=%s", i++, be->env);
	VPUTINT(nbhyve_envs);
	i = 1;
	STAILQ_FOREACH(ev, &conf->bhyve_envs, next)
		vputenv(ENV_PREFIX "BHYVE_ENV%d=%s", i++, ev->env);
	VPUTSTR(loadcmd);
	VPUTSTR(installcmd);
	VPUTSTR(err_logfile);
	vputenv(ENV_PREFIX "HOSTBRIDGE=%s", hostbridge_str[conf->hostbridge]);

	VPUTINT(npassthrues);
	i = 1;
	STAILQ_FOREACH(pc, &conf->passthrues, next)
		vputenv(ENV_PREFIX "PASSTHRUES%d=%s", i++, pc->devid);

	if (conf->tpm_dev) {
		VPUTSTR(tpm_dev);
		VPUTSTR(tpm_version);
	}

	VPUTINT(ndisks);
	i = 1;
	STAILQ_FOREACH(dc, &conf->disks, next) {
		vputenv(ENV_PREFIX "DISK%d_TYPE=%s", i, dc->type);
		vputenv(ENV_PREFIX "DISK%d_PATH=%s", i, dc->path);
		vputenv(ENV_PREFIX "DISK%d_NOCACHE=%s", i,
		    bool_str[dc->nocache]);
		vputenv(ENV_PREFIX "DISK%d_DIRECT=%s", i, bool_str[dc->direct]);
		vputenv(ENV_PREFIX "DISK%d_READONLY=%s", i,
		    bool_str[dc->readonly]);
		vputenv(ENV_PREFIX "DISK%d_NODELETE=%s", i,
		    bool_str[dc->nodelete]);
		vputenv(ENV_PREFIX "DISK%d_NOEXIST=%s", i,
		    bool_str[dc->noexist]);
	}
	VPUTINT(nsharefs);
	i = 1;
	STAILQ_FOREACH(sc, &conf->sharefss, next) {
		vputenv(ENV_PREFIX "SHAREFS%d_NAME=%s", i, sc->name);
		vputenv(ENV_PREFIX "SHAREFS%d_PATH=%s", i, sc->path);
		vputenv(ENV_PREFIX "DISK%d_READONLY=%s", i,
		    bool_str[sc->readonly]);
	}
	VPUTINT(nisoes);
	i = 1;
	STAILQ_FOREACH(ic, &conf->isoes, next) {
		vputenv(ENV_PREFIX "ISO%d_TYPE=%s", i, ic->type);
		vputenv(ENV_PREFIX "ISO%d_PATH=%s", i++, ic->path);
	}
	vputenv(ENV_PREFIX "NNETWORKS=%d", conf->nnets);
	i = 1;
	STAILQ_FOREACH(nc, &vm->taps, next) {
		vputenv(ENV_PREFIX "NETWORK%d_TYPE=%s", i, nc->type);
		vputenv(ENV_PREFIX "NETWORK%d_WOL=%s", i, bool_str[nc->wol]);
		if (nc->mac)
			vputenv(ENV_PREFIX "NETWORK%d_MAC=%s", i, nc->mac);
		if (nc->tap)
			vputenv(ENV_PREFIX "NETWORK%d_TAP=%s", i, nc->tap);
		else if (nc->vale_port)
			vputenv(ENV_PREFIX "NETWORK%d_TAP=%s", i,
			    nc->vale_port);
		if (nc->bridge)
			vputenv(ENV_PREFIX "NETWORK%d_BRIDGE=%s", i,
			    nc->bridge);
		else if (nc->vale)
			vputenv(ENV_PREFIX "NETWORK%d_BRIDGE=%s", i, nc->vale);
		i++;
	}
	VPUTINT(nhdas);
	i = 1;
	STAILQ_FOREACH(hc, &conf->hdas, next) {
		if (*hc->play_dev != '\0')
			vputenv(ENV_PREFIX "HDA%d_PLAY_DEV=%s", i,
			    hc->play_dev);
		if (*hc->rec_dev != '\0')
			vputenv(ENV_PREFIX "HDA%d_REC_DEV=%s", i++,
			    hc->rec_dev);
	}
	fb = conf->fbuf;
	vputenv(ENV_PREFIX "GRAPHICS=%s", bool_str[fb->enable]);
	if (fb->enable) {
		vputenv(ENV_PREFIX "GRAPHICS_LISTEN=%s", fb->ipaddr);
		vputenv(ENV_PREFIX "GRAPHICS_PASSWORD=%s", fb->password);
		vputenv(ENV_PREFIX "GRAPHICS_RES=%dx%d", fb->width, fb->height);
		vputenv(ENV_PREFIX "GRAPHICS_VGA=%s", fb->vgaconf);
		vputenv(ENV_PREFIX "GRAPHICS_WAIT=%s", bool_str[fb->wait]);
		vputenv(ENV_PREFIX "XHCI_MOUSE=%s", conf->mouse);
		VPUTSTR(keymap);
	}

	return 0;
}

int
dump_vm_conf(struct vm_conf *conf, FILE *fp)
{
	int i;
	struct disk_conf *dc;
	struct sharefs_conf *sc;
	struct iso_conf *ic;
	struct net_conf *nc;
	struct passthru_conf *pc;
	struct bhyveload_env *be;
	struct bhyve_env *ev;
	struct cpu_pin *cp;
	struct hda_conf *hc;
	struct fbuf *fb;
	const static char *btype[] = { "no", "yes", "oneshot", "install",
		"always", "reboot" };
	const static char *hostbridge_str[] = { "none", "intel", "amd" };
	const static char *bool_str[] = { "false", "true" };
	const static char *hdr = "%18s = ";
	const static char *fmt = "%18s = %s\n";
	const static char *dfmt = "%18s = %d\n";
	const static char *lfmt = "%18s = %s,%s\n";
	const static char *nfmt = "%18s = %s%s%s%s,%s\n";
	char *p, **com, buf[32];

	fprintf(fp, fmt, "name", conf->name);
	fprintf(fp, dfmt, "owner", conf->owner);
	fprintf(fp, dfmt, "group", conf->group);
	fprintf(fp, dfmt, "ncpu", conf->ncpu);
	if ((cp = STAILQ_FIRST(&conf->cpu_pins))) {
		fprintf(fp, "%18s = %d:%d", "cpu_pin", cp->vcpu, cp->hostcpu);
		while ((cp = STAILQ_NEXT(cp, next)))
			fprintf(fp, ", %d:%d", cp->vcpu, cp->hostcpu);
		fprintf(fp, "\n");
	}
	fprintf(fp, fmt, "x2apic", bool_str[conf->x2apic]);
	fprintf(fp, fmt, "memory", conf->memory);
	fprintf(fp, fmt, "wired_memory", bool_str[conf->wired_memory]);
	fprintf(fp, fmt, "utctime", bool_str[conf->utctime]);
	fprintf(fp, fmt, "reboot_on_change", bool_str[conf->reboot_on_change]);
	fprintf(fp, fmt, "single_user", bool_str[conf->single_user]);
	fprintf(fp, fmt, "install", bool_str[conf->install]);
	ARRAY_FOREACH(com, conf->com)
		if (*com != NULL) {
			snprintf(buf, sizeof(buf), "com%ld",
			    CONF_COM_NUM(com, conf->com));
			fprintf(fp, fmt, buf, *com);
		}
	fprintf(fp, fmt, "debug_port", conf->debug_port);
	fprintf(fp, fmt, "boot", btype[conf->boot]);
	fprintf(fp, dfmt, "boot_delay", conf->boot_delay);
	fprintf(fp, dfmt, "loader_timeout", conf->loader_timeout);
	fprintf(fp, dfmt, "stop_timeout", conf->stop_timeout);
	fprintf(fp, fmt, "loader", conf->loader);
	fprintf(fp, fmt, "bhyveload_loader", conf->bhyveload_loader);
	i = 0;
	STAILQ_FOREACH(be, &conf->bhyveload_envs, next) {
		snprintf(buf, sizeof(buf), "bhyveload_env%d", i++);
		fprintf(fp, fmt, buf, be->env);
	}
	i = 0;
	STAILQ_FOREACH(ev, &conf->bhyve_envs, next) {
		snprintf(buf, sizeof(buf), "bhyve_env%d", i++);
		fprintf(fp, fmt, buf, ev->env);
	}
	fprintf(fp, fmt, "loadcmd", conf->loadcmd);
	fprintf(fp, fmt, "installcmd", conf->installcmd);
	fprintf(fp, fmt, "err_logfile", conf->err_logfile);
	fprintf(fp, fmt, "hostbrigde", hostbridge_str[conf->hostbridge]);
	fprintf(fp, fmt, "virt_random", bool_str[conf->virt_random]);

	if (!STAILQ_EMPTY(&conf->passthrues)) {
		fprintf(fp, "%18s =", "passthru");
		STAILQ_FOREACH(pc, &conf->passthrues, next)
			fprintf(fp, " %s", pc->devid);
		fprintf(fp, "\n");
	}

	if (conf->tpm_dev) {
		if (conf->tpm_version)
			fprintf(fp, "%18s = %s:%s:%s\n", "tpm", conf->tpm_type,
			    conf->tpm_dev, conf->tpm_version);
		else
			fprintf(fp, "%18s = %s:%s\n", "tpm", conf->tpm_type,
			    conf->tpm_dev);
	}

	i = 0;
	STAILQ_FOREACH(dc, &conf->disks, next) {
		snprintf(buf, sizeof(buf), "disk%d", i++);
		fprintf(fp, "%18s = %s", buf, dc->type);
		if (dc->nocache)
			fprintf(fp, ":nocache");
		if (dc->direct)
			fprintf(fp, ":direct");
		if (dc->readonly)
			fprintf(fp, ":readonly");
		if (dc->nodelete)
			fprintf(fp, ":nodelete");
		if (dc->noexist)
			fprintf(fp, ":noexist");
		fprintf(fp, ":%s\n", dc->path);
	}
	i = 0;
	STAILQ_FOREACH(sc, &conf->sharefss, next) {
		snprintf(buf, sizeof(buf), "sharefs%d", i++);
		fprintf(fp, "%18s = %s%s=%s\n", buf,
		    (sc->readonly) ? "readonly:" : "", sc->name, sc->path);
	}
	i = 0;
	STAILQ_FOREACH(ic, &conf->isoes, next) {
		snprintf(buf, sizeof(buf), "iso%d", i++);
		fprintf(fp, lfmt, buf, ic->type, ic->path);
	}
	i = 0;
	STAILQ_FOREACH(nc, &conf->nets, next) {
		p = nc->bridge ? nc->bridge : nc->vale;
		snprintf(buf, sizeof(buf), "net%d", i++);
		fprintf(fp, nfmt, buf, nc->wol ? "wol," : "",
		    nc->mac ? nc->mac : "", nc->mac ? "," : "", nc->type, p);
	}
	i = 0;
	STAILQ_FOREACH(hc, &conf->hdas, next) {
		snprintf(buf, sizeof(buf), "hda%d", i++);
		if (*hc->play_dev == '\0' && *hc->rec_dev == '\0')
			continue;
		fprintf(fp, hdr, buf);
		if (*hc->play_dev != '\0')
			fprintf(fp, "%s", hc->play_dev);
		if (*hc->rec_dev != '\0')
			fprintf(fp, ":%s", hc->rec_dev);
		fprintf(fp, "\n");
	}
	fb = conf->fbuf;
	if (fb->enable) {
		fprintf(fp, "%18s = %s:%d, %dx%d, %s, %s\n", "graphics",
		    fb->ipaddr, fb->port, fb->width, fb->height, fb->vgaconf,
		    fb->wait ? "wait" : "nowait");
		fprintf(fp, fmt, "xhci_mouse", bool_str[conf->mouse]);
		fprintf(fp, fmt, "keymap", conf->keymap);
	}
	return 0;
}

static int
compare_string(const char *a, const char *b)
{
	if (a == NULL && b == NULL)
		return 0;
	if (a == NULL)
		return -1;
	if (b == NULL)
		return 1;
	return strcmp(a, b);
}

#define CMP_NUM(t)                       \
	if ((rc = (a)->t - (b)->t) != 0) \
	return rc
#define CMP_STR(t)                                      \
	if ((rc = compare_string((a)->t, (b)->t)) != 0) \
	return rc

static int
compare_fbuf(const struct fbuf *a, const struct fbuf *b)
{
	int rc;

	CMP_NUM(enable);
	CMP_STR(ipaddr);
	CMP_NUM(port);
	CMP_NUM(width);
	CMP_NUM(height);
	CMP_STR(vgaconf);
	CMP_NUM(wait);
	CMP_STR(password);

	return 0;
}

static int
compare_passthru_conf(const struct passthru_conf *a,
    const struct passthru_conf *b)
{
	int rc;

	CMP_STR(devid);

	return 0;
}

static int
compare_disk_conf(const struct disk_conf *a, const struct disk_conf *b)
{
	int rc;

	CMP_STR(type);
	CMP_STR(path);
	CMP_NUM(nocache);
	CMP_NUM(direct);
	CMP_NUM(readonly);
	CMP_NUM(nodelete);
	CMP_NUM(noexist);

	return 0;
}

static int
compare_sharefs_conf(const struct sharefs_conf *a, const struct sharefs_conf *b)
{
	int rc;

	CMP_STR(name);
	CMP_STR(path);
	CMP_NUM(readonly);

	return 0;
}

static int
compare_iso_conf(const struct iso_conf *a, const struct iso_conf *b)
{
	int rc;

	CMP_STR(type);
	CMP_STR(path);

	return 0;
}

static int
compare_net_conf(const struct net_conf *a, const struct net_conf *b)
{
	int rc;

	CMP_STR(type);
	CMP_STR(bridge);
	CMP_STR(mac);
	CMP_STR(vale);
	CMP_NUM(wol);
	/*
	 * We don't need to compare tap.
	 * Because it is not written in the vm config file.
	 * 'tap' holds assigned tap interface name while vm is running.
	 *
	 * CMP_STR(tap);
	 */

	return 0;
}

static int
compare_hda_conf(const struct hda_conf *a, const struct hda_conf *b)
{
	int rc;

	CMP_STR(play_dev);
	CMP_STR(rec_dev);

	return 0;
}

static int
compare_bhyveload_env(const struct bhyveload_env *a,
    const struct bhyveload_env *b)
{
	int rc;

	CMP_STR(env);
	return 0;
}

static int
compare_bhyve_env(const struct bhyve_env *a, const struct bhyve_env *b)
{
	int rc;

	CMP_STR(env);
	return 0;
}

static int
compare_cpu_pin(const struct cpu_pin *a, const struct cpu_pin *b)
{
	int rc;
	CMP_NUM(vcpu);
	CMP_NUM(hostcpu);
	return 0;
}

#define CMP_LIST(type, member)                                               \
	do {                                                                 \
		struct type *ea, *eb;                                        \
		for (ea = STAILQ_FIRST(&a->member),                          \
		    eb = STAILQ_FIRST(&b->member);                           \
		     ea != NULL && eb != NULL;                               \
		     ea = STAILQ_NEXT(ea, next), eb = STAILQ_NEXT(eb, next)) \
			if ((rc = compare_##type(ea, eb)) != 0)              \
				return rc;                                   \
		if (ea != NULL)                                              \
			return 1;                                            \
		if (eb != NULL)                                              \
			return -1;                                           \
	} while (0)

int
compare_vm_conf(const struct vm_conf *a, const struct vm_conf *b)
{
	unsigned int i;
	int rc;

	CMP_NUM(boot_delay);
	CMP_NUM(loader_timeout);
	CMP_NUM(stop_timeout);
	CMP_NUM(hostbridge);
	CMP_NUM(owner);
	CMP_NUM(group);
	CMP_STR(debug_port);
	CMP_NUM(ncpu);
	CMP_NUM(ncpu_sockets);
	CMP_NUM(ncpu_cores);
	CMP_NUM(ncpu_threads);
	CMP_STR(memory);
	CMP_STR(name);
	for (i = 0; i < nitems(a->com); i++)
		CMP_STR(com[i]);
	CMP_NUM(boot);
	CMP_STR(loader);
	CMP_STR(loadcmd);
	CMP_STR(installcmd);
	CMP_STR(err_logfile);
	CMP_STR(grub_run_partition);
	CMP_STR(bhyveload_loader);

	CMP_STR(keymap);

	if ((rc = compare_fbuf(a->fbuf, b->fbuf)) != 0)
		return rc;

	CMP_NUM(mouse);
	CMP_NUM(wired_memory);
	CMP_NUM(utctime);
	CMP_NUM(reboot_on_change);
	CMP_NUM(single_user);
	CMP_NUM(install);
	CMP_NUM(ndisks);
	CMP_NUM(nisoes);
	CMP_NUM(nnets);
	CMP_NUM(virt_random);
	CMP_NUM(x2apic);

	CMP_LIST(passthru_conf, passthrues);
	CMP_LIST(disk_conf, disks);
	CMP_LIST(sharefs_conf, sharefss);
	CMP_LIST(iso_conf, isoes);
	CMP_LIST(net_conf, nets);
	CMP_LIST(bhyveload_env, bhyveload_envs);
	CMP_LIST(bhyve_env, bhyve_envs);
	CMP_LIST(cpu_pin, cpu_pins);
	CMP_LIST(hda_conf, hdas);
	CMP_STR(tpm_dev);
	CMP_STR(tpm_type);
	CMP_STR(tpm_version);

	return 0;
}

static int
compare_variable_key(struct conf_var *a, struct conf_var *b)
{
	if (a == NULL && b == NULL)
		return 0;
	if (a == NULL)
		return -1;
	if (b == NULL)
		return 1;
	return compare_string(a->key, b->key);
}

static int
del_var(struct vartree *vars, const char *k)
{
	struct conf_var key, *n;

	if (k == NULL)
		return -1;
	key = (struct conf_var) { .key = strdup(k), .val = NULL };
	if (key.key == NULL)
		return -1;

	if ((n = RB_FIND(vartree, vars, &key))) {
		RB_REMOVE(vartree, vars, n);
		free_var(n);
	}
	free(key.key);
	return 0;
}

int
set_var0(struct vartree *vars, const char *k, const char *v)
{
	struct conf_var *n, key;
	char *nv;

	if (k == NULL || v == NULL)
		return -1;

	key = (struct conf_var) { .key = strdup(k), .val = NULL };
	if (key.key == NULL)
		return -1;

	if ((n = RB_FIND(vartree, vars, &key))) {
		if ((nv = strdup(v)) == NULL)
			return -1;
		free(key.key);
		free(n->val);
		n->val = nv;
	} else {
		n = malloc(sizeof(*n));
		key.val = strdup(v);
		if (n == NULL || key.val == NULL) {
			free(key.key);
			free(key.val);
			free(n);
			return -1;
		}
		memcpy(n, &key, sizeof(*n));
		RB_INSERT(vartree, vars, n);
	}
	return 0;
}

int
set_var(struct variables *vars, const char *k, const char *v)
{
	if (vars->args)
		del_var(vars->args, k);
	if (vars->local)
		return set_var0(vars->local, k, v);
	if (vars->global)
		return set_var0(vars->global, k, v);
	return -1;
}

int
init_global_vars(void)
{
	struct vartree *gv;

	if ((gv = malloc(sizeof(*gv))) == NULL)
		return -1;
	RB_INIT(gv);
	if (set_var0(gv, "LOCALBASE", LOCALBASE) < 0)
		ERR("%s\n", "failed to set \"LOCALBASE\" variable!");
	global_vars = gv;
	return 0;
}

void
set_global_vars(struct vartree *gv)
{
	if (global_vars != NULL)
		free_global_vars();
	global_vars = gv;
}

void
free_global_vars(void)
{
	if (global_vars == NULL)
		return;

	free_vartree(global_vars);

	global_vars = NULL;
}

char *
get_var0(struct vartree *vars, char *k)
{
	struct conf_var *r, key = { .key = k, .val = NULL };

	if (vars == NULL)
		return NULL;

	if ((r = RB_FIND(vartree, vars, &key)) != NULL)
		return r->val;
	return NULL;
}

char *
get_var(struct variables *vars, char *k)
{
	char *ret;

	/*
	 * Lookup local variables first. This pretends for users
	 * that global variables are re-writable in vm and
	 * template section.
	 */
	if ((ret = get_var0(vars->args, k)) == NULL &&
	    (ret = get_var0(vars->local, k)) == NULL &&
	    (ret = get_var0(vars->global, k)) == NULL)
		return NULL;

	return ret;
}

static int
compare_nvlist_null(const nvlist_t *a __unused, const char *k __unused,
    const nvlist_t *b __unused)
{
	return 0;
}

static int
compare_nvlist_bool(const nvlist_t *a, const char *k, const nvlist_t *b)
{
	bool da, db;

	da = nvlist_get_bool(a, k);
	db = nvlist_get_bool(b, k);

	return da - db;
}

static int
compare_nvlist_number(const nvlist_t *a, const char *k, const nvlist_t *b)
{
	uint64_t da, db;

	da = nvlist_get_number(a, k);
	db = nvlist_get_number(b, k);

	return CMP(da, db);
}

static int
compare_nvlist_nvlist(const nvlist_t *a, const char *k, const nvlist_t *b)
{
	const nvlist_t *da, *db;

	da = nvlist_get_nvlist(a, k);
	db = nvlist_get_nvlist(b, k);

	return compare_nvlist(da, db);
}

static int
compare_nvlist_string(const nvlist_t *a, const char *k, const nvlist_t *b)
{
	const char *da, *db;

	da = nvlist_get_string(a, k);
	db = nvlist_get_string(b, k);

	return strcmp(da, db);
}

static int
compare_nvlist_descriptor(const nvlist_t *a, const char *k, const nvlist_t *b)
{
	int da, db;

	da = nvlist_get_descriptor(a, k);
	db = nvlist_get_descriptor(b, k);

	return CMP(da, db);
}

static int
compare_nvlist_binary(const nvlist_t *a, const char *k, const nvlist_t *b)
{
	const void *da, *db;
	size_t sa, sb;
	int rc;

	da = nvlist_get_binary(a, k, &sa);
	db = nvlist_get_binary(b, k, &sb);
	if ((rc = memcmp(da, db, MIN(sa, sb))) != 0)
		return rc;

	return CMP(sa, sb);
}

static int
compare_nvlist_bool_array(const nvlist_t *a, const char *k, const nvlist_t *b)
{
	const bool *da, *db;
	size_t i, sa, sb;

	da = nvlist_get_bool_array(a, k, &sa);
	db = nvlist_get_bool_array(b, k, &sb);
	for (i = 0; i < MIN(sa, sb); i++)
		CMP_RETURN(da[i], db[i]);

	return CMP(sa, sb);
}

static int
compare_nvlist_number_array(const nvlist_t *a, const char *k, const nvlist_t *b)
{
	const uint64_t *da, *db;
	size_t i, sa, sb;

	da = nvlist_get_number_array(a, k, &sa);
	db = nvlist_get_number_array(b, k, &sb);
	for (i = 0; i < MIN(sa, sb); i++)
		CMP_RETURN(da[i], db[i]);

	return CMP(sa, sb);
}

static int
compare_nvlist_string_array(const nvlist_t *a, const char *k, const nvlist_t *b)
{
	const char *const *da, *const *db;
	size_t i, sa, sb;
	int rc;

	da = nvlist_get_string_array(a, k, &sa);
	db = nvlist_get_string_array(b, k, &sb);
	for (i = 0; i < MIN(sa, sb); i++)
		if ((rc = strcmp(da[i], db[i])) != 0)
			return rc;

	return CMP(sa, sb);
}

static int
compare_nvlist_nvlist_array(const nvlist_t *a, const char *k, const nvlist_t *b)
{
	const nvlist_t *const *da, *const *db;
	size_t i, sa, sb;
	int rc;

	da = nvlist_get_nvlist_array(a, k, &sa);
	db = nvlist_get_nvlist_array(b, k, &sb);
	for (i = 0; i < MIN(sa, sb); i++)
		if ((rc = compare_nvlist(da[i], db[i])) != 0)
			return rc;

	return CMP(sa, sb);
}

static int
compare_nvlist_descriptor_array(const nvlist_t *a, const char *k,
    const nvlist_t *b)
{
	const int *da, *db;
	size_t i, sa, sb;

	da = nvlist_get_descriptor_array(a, k, &sa);
	db = nvlist_get_descriptor_array(b, k, &sb);
	for (i = 0; i < MIN(sa, sb); i++)
		CMP_RETURN(da[i], db[i]);

	return CMP(sa, sb);
}

typedef int (*nvcomp)(const nvlist_t *a, const char *k, const nvlist_t *b);

int
compare_nvlist(const nvlist_t *a, const nvlist_t *b)
{
	const char *k;
	int t, rc;
	void *cookie = NULL;
	static nvcomp cfuncs[] = {
		compare_nvlist_null,
		compare_nvlist_null,
		compare_nvlist_bool,
		compare_nvlist_number,
		compare_nvlist_string,
		compare_nvlist_nvlist,
		compare_nvlist_descriptor,
		compare_nvlist_binary,
		compare_nvlist_bool_array,
		compare_nvlist_number_array,
		compare_nvlist_string_array,
		compare_nvlist_nvlist_array,
		compare_nvlist_descriptor_array,
	};

	if (a == NULL && b == NULL)
		return 0;
	if (a == NULL || nvlist_error(a))
		return -1;
	if (b == NULL || nvlist_error(b))
		return 1;
	while ((k = nvlist_next(a, &t, &cookie)) != NULL) {
		if (!nvlist_exists_type(b, k, t))
			return 1;
		if (t < 0 || t > (int)nitems(cfuncs))
			continue;
		if ((rc = (*cfuncs[t])(a, k, b)) != 0)
			return rc;
	}

	cookie = NULL;
	while ((k = nvlist_next(b, &t, &cookie)) != NULL)
		if (!nvlist_exists_type(a, k, t))
			return -1;

	return 0;
}
