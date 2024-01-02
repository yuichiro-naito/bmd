#include <sys/param.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "log.h"
#include "conf.h"
#include "bmd_plugin.h"

#define CMP(a,b)    ((a) < (b) ? -1 : ((a) == (b) ? 0 : 1))
#define CMP_RETURN(a,b)  if ((a) != (b)) return (a) < (b) ? -1 : 1

struct id_entry {
	SLIST_ENTRY(id_entry) next;
	unsigned int id;
	char name[0];
};

/*
  List of identfiers.
 */
SLIST_HEAD(, id_entry) id_list = SLIST_HEAD_INITIALIZER();

static int compare_variable_key(struct conf_var *, struct conf_var *);
RB_GENERATE(vartree, conf_var, entry, compare_variable_key);
struct vartree *global_vars = NULL;

void
free_id_list()
{
	struct id_entry *e, *t;

	SLIST_FOREACH_SAFE (e, &id_list, next, t)
		free(e);
	SLIST_INIT(&id_list);
}

static int
get_id(const char *name, unsigned int *id)
{
	static unsigned int lastid = 0;
	struct id_entry *e;

	SLIST_FOREACH (e, &id_list, next)
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
	free(c);
}

void
free_bhyveload_env(struct bhyveload_env *e)
{
	if (e == NULL)
		return;
	free(e);
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
clear_passthru_conf(struct vm_conf *vc)
{
	struct passthru_conf *pc, *pn;
	STAILQ_FOREACH_SAFE (pc, &vc->passthrues, next, pn)
		free_passthru_conf(pc);
	STAILQ_INIT(&vc->passthrues);
}

void
clear_disk_conf(struct vm_conf *vc)
{
	struct disk_conf *dc, *dn;
	STAILQ_FOREACH_SAFE (dc, &vc->disks, next, dn)
		free_disk_conf(dc);
	STAILQ_INIT(&vc->disks);
}

void
clear_iso_conf(struct vm_conf *vc)
{
	struct iso_conf *ic, *in;
	STAILQ_FOREACH_SAFE (ic, &vc->isoes, next, in)
		free_iso_conf(ic);
	STAILQ_INIT(&vc->isoes);
}

void
clear_net_conf(struct vm_conf *vc)
{
	struct net_conf *nc, *nn;
	STAILQ_FOREACH_SAFE (nc, &vc->nets, next, nn)
		free_net_conf(nc);
	STAILQ_INIT(&vc->nets);
}

void
clear_bhyveload_env(struct vm_conf *vc)
{
	struct bhyveload_env *be, *bn;
	STAILQ_FOREACH_SAFE(be, &vc->bhyveload_envs, next, bn)
		free_bhyveload_env(be);
	STAILQ_INIT(&vc->bhyveload_envs);
}

void
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

	RB_FOREACH_SAFE (v, vartree, vt, vn) {
		RB_REMOVE(vartree, vt, v);
		free_var(v);
	}
	free(vt);
}

void
free_vm_conf(struct vm_conf *vc)
{

	if (vc == NULL)
		return;

	free_vartree(vc->vars.local);

	free(vc->name);
	free(vc->ncpu);
	free(vc->memory);
	free(vc->comport);
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
	free(vc->keymap);
	free(vc->bhyveload_loader);
	clear_bhyveload_env(vc);
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
	return 0;
err:
	free(d);
	free(p);
	return -1;
}

struct passthru_conf *
get_passthru_conf(struct vm_conf *conf)
{
	return STAILQ_FIRST(&conf->passthrues);
}

struct passthru_conf *
next_passthru_conf(struct passthru_conf *p_conf)
{
	return STAILQ_NEXT(p_conf, next);
}

char *
get_passthru_conf_devid(struct passthru_conf *p_conf)
{
	return p_conf->devid;
}

int
add_disk_conf(struct vm_conf *conf, const char *type, const char *path)
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

	STAILQ_INSERT_TAIL(&conf->disks, t, next);
	conf->ndisks++;
	return 0;
err:
	free(p);
	free(y);
	free(t);
	return -1;
}

struct disk_conf *
get_disk_conf(struct vm_conf *conf)
{
	return STAILQ_FIRST(&conf->disks);
}

struct disk_conf *
next_disk_conf(struct disk_conf *d_conf)
{
	return STAILQ_NEXT(d_conf, next);
}

char *
get_disk_conf_type(struct disk_conf *d_conf)
{
	return d_conf->type;
}

char *
get_disk_conf_path(struct disk_conf *d_conf)
{
	return d_conf->path;
}

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

struct iso_conf *
get_iso_conf(struct vm_conf *conf)
{
	return STAILQ_FIRST(&conf->isoes);
}

struct iso_conf *
next_iso_conf(struct iso_conf *i_conf)
{
	return STAILQ_NEXT(i_conf, next);
}

char *
get_iso_conf_type(struct iso_conf *i_conf)
{
	return i_conf->type;
}

char *
get_iso_conf_path(struct iso_conf *i_conf)
{
	return i_conf->path;
}

int
add_net_conf(struct vm_conf *conf, const char *type, const char *bridge)
{
	struct net_conf *t;
	char *y, *b;
	if (conf == NULL)
		return 0;

	t = malloc(sizeof(struct net_conf));
	y = strdup(type);
	b = strdup(bridge);
	if (t == NULL || y == NULL || b == NULL)
		goto err;
	t->type = y;
	t->bridge = b;
	t->tap = NULL;

	STAILQ_INSERT_TAIL(&conf->nets, t, next);
	conf->nnets++;
	return 0;
err:
	free(b);
	free(y);
	free(t);
	return -1;
}

struct net_conf *
get_net_conf(struct vm_conf *conf)
{
	return STAILQ_FIRST(&conf->nets);
}

struct net_conf *
next_net_conf(struct net_conf *n_conf)
{
	return STAILQ_NEXT(n_conf, next);
}

char *
get_net_conf_type(struct net_conf *n_conf)
{
	return n_conf->type;
}

char *
get_net_conf_bridge(struct net_conf *n_conf)
{
	return n_conf->bridge;
}

char *
get_net_conf_tap(struct net_conf *n_conf)
{
	return n_conf->tap;
}

int
add_bhyveload_env(struct vm_conf *conf, const char *env)
{
	struct bhyveload_env *be;

	if (conf == NULL)
		return 0;

	if (env == NULL ||
	    (be = malloc(sizeof(struct bhyveload_env) + strlen(env) + 1)) == NULL)
		return -1;
	strcpy(be->env, env);

	STAILQ_INSERT_TAIL(&conf->bhyveload_envs, be, next);
	conf->nbhyveload_envs++;
	return 0;
}

struct bhyveload_env *
get_bhyveload_env(struct vm_conf *conf)
{
	return STAILQ_FIRST(&conf->bhyveload_envs);
}

struct bhyveload_env *
next_bhyveload_env(struct bhyveload_env *be)
{
	return STAILQ_NEXT(be, next);
}

char *
get_bhyveload_env_env(struct bhyveload_env *be)
{
	return be->env;
}

struct net_conf *
copy_net_conf(const struct net_conf *nc)
{
	struct net_conf *ret;
	char *y, *b, *t;

	ret = malloc(sizeof(struct net_conf));
	y = strdup(nc->type);
	b = strdup(nc->bridge);
	t = (nc->tap) ? strdup(nc->tap) : NULL;
	if (ret == NULL || y == NULL || b == NULL ||
	    (nc->tap != NULL && t == NULL))
		goto err;

	ret->type = y;
	ret->bridge = b;
	ret->tap = t;
	STAILQ_NEXT(ret, next) = NULL;
	return ret;
err:
	free(t);
	free(b);
	free(y);
	free(ret);
	return NULL;
}

static int
set_string(char **var, const char *value)
{
	char *new;

	if ((new = strdup(value)) == NULL)
		return -1;

	free(*var);
	*var = new;
	return 0;
}

int
set_name(struct vm_conf *conf, const char *name)
{
	if (conf == NULL)
		return 0;
	return set_string(&conf->name, name);
}

char *
get_name(struct vm_conf *c)
{
	return c->name;
}

int
set_loadcmd(struct vm_conf *conf, const char *cmd)
{
	if (conf == NULL)
		return 0;
	return set_string(&conf->loadcmd, cmd);
}

char *
get_loadcmd(struct vm_conf *conf)
{
	return conf->loadcmd;
}

int
set_installcmd(struct vm_conf *conf, const char *cmd)
{
	if (conf == NULL)
		return 0;
	return set_string(&conf->installcmd, cmd);
}

char *
get_installcmd(struct vm_conf *conf)
{
	return conf->installcmd;
}

int
set_err_logfile(struct vm_conf *conf, const char *name)
{
	if (conf == NULL)
		return 0;
	return set_string(&conf->err_logfile, name);
}

char *
get_err_logfile(struct vm_conf *conf)
{
	return conf->err_logfile;
}

int
set_loader(struct vm_conf *conf, const char *loader)
{
	if (conf == NULL)
		return 0;
	return set_string(&conf->loader, loader);
}

char *
get_loader(struct vm_conf *conf)
{
	return conf->loader;
}

int
set_bhyveload_loader(struct vm_conf *conf, const char *loader)
{
	if (conf == NULL)
		return 0;
	return set_string(&conf->bhyveload_loader, loader);
}

char *
get_bhyveload_loader(struct vm_conf *conf)
{
	return conf->bhyveload_loader;
}

int
set_loader_timeout(struct vm_conf *conf, int timeout)
{
	if (conf == NULL)
		return 0;

	conf->loader_timeout = timeout;
	return 0;
}

int
get_loader_timeout(struct vm_conf *conf)
{
	return conf->loader_timeout;
}

int
set_stop_timeout(struct vm_conf *conf, int timeout)
{
	if (conf == NULL)
		return 0;

	conf->stop_timeout = timeout;
	return 0;
}

int
get_stop_timeout(struct vm_conf *conf)
{
	return conf->stop_timeout;
}

int
set_grub_run_partition(struct vm_conf *conf, const char *partition)
{
	if (conf == NULL)
		return 0;

	return set_string(&conf->grub_run_partition, partition);
}

char *
get_grub_run_partition(struct vm_conf *conf)
{
	return conf->grub_run_partition;
}

int
set_debug_port(struct vm_conf *conf, const char *port)
{
	if (conf == NULL)
		return 0;

	return set_string(&conf->debug_port, port);
}

char *
get_debug_port(struct vm_conf *conf)
{
	return conf->debug_port;
}

int
set_memory_size(struct vm_conf *conf, const char *memory)
{
	if (conf == NULL)
		return 0;
	return set_string(&conf->memory, memory);
}

char *
get_memory(struct vm_conf *conf)
{
	return conf->memory;
}

int
set_comport(struct vm_conf *conf, const char *com)
{
	if (conf == NULL)
		return 0;
	return set_string(&conf->comport, com);
}

char *
get_comport(struct vm_conf *conf)
{
	return conf->comport;
}

int
set_ncpu(struct vm_conf *conf, int ncpu)
{
	char *new;

	if (conf == NULL)
		return 0;

	if ((asprintf(&new, "%d", ncpu)) < 0)
		return -1;

	free(conf->ncpu);
	conf->ncpu = new;
	return 0;
}

char *
get_ncpu(struct vm_conf *conf)
{
	return conf->ncpu;
}

int
set_owner(struct vm_conf *conf, uid_t owner)
{
	if (conf == NULL)
		return 0;

	conf->owner = owner;
	return 0;
}

uid_t
get_owner(struct vm_conf *conf)
{
	return conf->owner;
}

int
set_group(struct vm_conf *conf, gid_t group)
{
	if (conf == NULL)
		return 0;

	conf->group = group;
	return 0;
}

gid_t
get_group(struct vm_conf *conf)
{
	return conf->group;
}

int
set_boot(struct vm_conf *conf, enum BOOT boot)
{
	if (conf == NULL)
		return 0;

	conf->boot = boot;
	return 0;
}

enum BOOT
get_boot(struct vm_conf *conf)
{
	return conf->boot;
}

int
set_hostbridge(struct vm_conf *conf, enum HOSTBRIDGE_TYPE type)
{
	if (conf == NULL)
		return 0;

	conf->hostbridge = type;
	return 0;
}

enum HOSTBRIDGE_TYPE
get_hostbridge(struct vm_conf *conf)
{
	return conf->hostbridge;
}

int
set_backend(struct vm_conf *conf, char *backend)
{
	if (conf == NULL)
		return 0;

	return set_string(&conf->backend, backend);
}

char *
get_backend(struct vm_conf *conf)
{
	return conf->backend;
}

int
set_keymap(struct vm_conf *conf, const char *keymap)
{
	if (conf == NULL)
		return 0;
	return set_string(&conf->keymap, keymap);
}

char *
get_keymap(struct vm_conf *conf)
{
	return conf->keymap;
}

int
set_boot_delay(struct vm_conf *conf, int delay)
{
	if (conf == NULL)
		return 0;

	conf->boot_delay = delay;
	return 0;
}

int
get_boot_delay(struct vm_conf *conf)
{
	return conf->boot_delay;
}

int
set_reboot_on_change(struct vm_conf *conf, bool enable)
{
	if (conf == NULL)
		return 0;
	conf->reboot_on_change = enable;
	return 0;
}

bool
is_reboot_on_change(struct vm_conf *conf)
{
	return conf->reboot_on_change;
}

int
set_single_user(struct vm_conf *conf, bool single)
{
	if (conf == NULL)
		return 0;
	conf->single_user = single;
	return 0;
}

bool
is_single_user(struct vm_conf *conf)
{
	return conf->single_user;
}

int
set_install(struct vm_conf *conf, bool install)
{
	if (conf == NULL)
		return 0;
	conf->install = install;
	return 0;
}

bool
is_install(struct vm_conf *conf)
{
	return conf->install;
}

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

char
*get_fbuf_ipaddr(struct vm_conf *conf)
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

int
set_mouse(struct vm_conf *conf, bool use)
{
	conf->mouse = use;
	return 0;
}

bool
is_mouse(struct vm_conf *conf)
{
	return conf->mouse;
}

int
set_wired_memory(struct vm_conf *conf, bool val)
{
	if (conf == NULL)
		return 0;
	conf->wired_memory = val;
	return 0;
}

bool
is_wired_memory(struct vm_conf *conf)
{
	return conf->wired_memory;
}

int
set_utctime(struct vm_conf *conf, bool val)
{
	if (conf == NULL)
		return 0;
	conf->utctime = val;
	return 0;
}

bool
is_utctime(struct vm_conf *conf)
{
	return conf->utctime;
}

int
get_infd(struct vm *vm)
{
	return vm->infd;
}

int
get_outfd(struct vm *vm)
{
	return vm->outfd;
}

int
get_errfd(struct vm *vm)
{
	return vm->errfd;
}

int
get_logfd(struct vm *vm)
{
	return vm->logfd;
}

void
set_infd(struct vm *vm, int fd)
{
	vm->infd = fd;
}

void
set_outfd(struct vm *vm, int fd)
{
	vm->outfd = fd;
}
void
set_errfd(struct vm *vm, int fd)
{
	vm->errfd = fd;
}

void
set_logfd(struct vm *vm, int fd)
{
	vm->logfd = fd;
}

char *
get_assigned_comport(struct vm *vm)
{
	return vm->assigned_comport;
}

void
set_pid(struct vm *vm, pid_t pid)
{
	vm->pid = pid;
}

void
set_state(struct vm *vm, enum STATE st)
{
	vm->state = st;
}

enum STATE
get_state(struct vm *vm)
{
	return vm->state;
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
create_fbuf()
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
		ERR("failed to set \"NAME\" variable! (%s)\n",
		    strerror(errno));
	if (get_id(name, &id) == 0) {
		snprintf(idnum, sizeof(idnum), "%u", id);
		if (set_var0(local, "ID", idnum) < 0)
			ERR("failed to set \"ID\" variable! (%s)\n",
			    strerror(errno));
	} else
		ERR("failed to allocate \"ID\" number! (%s)\n",
		    strerror(errno));
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
	STAILQ_INIT(&ret->bhyveload_envs);

	return ret;
err:
	ERR("failed to create VM config! (%s)\n", strerror(errno));
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

int
dump_vm_conf(struct vm_conf *conf, FILE *fp)
{
	int i;
	struct disk_conf *dc;
	struct iso_conf *ic;
	struct net_conf *nc;
	struct passthru_conf *pc;
	struct bhyveload_env *be;
	struct fbuf *fb;
	const static char *btype[] = { "no", "yes", "oneshot", "install",
				       "always", "reboot" };
	const static char *hostbridge_str[] = {"none", "intel", "amd"};
	const static char *bool_str[] ={"false", "true"};
	const static char *fmt = "%18s = %s\n";
	const static char *dfmt = "%18s = %d\n";
	const static char *lfmt = "%18s = %s,%s\n";
	char buf[32];

	fprintf(fp, fmt, "name", conf->name);
	fprintf(fp, dfmt, "owner", conf->owner);
	fprintf(fp, dfmt, "group", conf->group);
	fprintf(fp, fmt, "ncpu", conf->ncpu);
	fprintf(fp, fmt, "memory", conf->memory);
	fprintf(fp, fmt, "wired_memory", bool_str[conf->wired_memory]);
	fprintf(fp, fmt, "utctime", bool_str[conf->utctime]);
	fprintf(fp, fmt, "reboot_on_change", bool_str[conf->reboot_on_change]);
	fprintf(fp, fmt, "single_user", bool_str[conf->single_user]);
	fprintf(fp, fmt, "install", bool_str[conf->install]);
	fprintf(fp, fmt, "comport", conf->comport);
	fprintf(fp, fmt, "debug_port", conf->debug_port);
	fprintf(fp, fmt, "boot", btype[conf->boot]);
	fprintf(fp, dfmt, "boot_delay", conf->boot_delay);
	fprintf(fp, dfmt, "loader_timeout", conf->loader_timeout);
	fprintf(fp, dfmt, "stop_timeout", conf->stop_timeout);
	fprintf(fp, fmt, "loader", conf->loader);
	fprintf(fp, fmt, "bhyveload_loader", conf->bhyveload_loader);
	i = 0;
	STAILQ_FOREACH (be, &conf->bhyveload_envs, next) {
		snprintf(buf, sizeof(buf), "bhyveload_env%d", i++);
		fprintf(fp, fmt, buf, be->env);
	}
	fprintf(fp, fmt, "loadcmd", conf->loadcmd);
	fprintf(fp, fmt, "installcmd", conf->installcmd);
	fprintf(fp, fmt, "err_logfile", conf->err_logfile);
	fprintf(fp, fmt, "hostbrigde", hostbridge_str[conf->hostbridge]);

	if (!STAILQ_EMPTY(&conf->passthrues)) {
		fprintf(fp, "%18s =" , "passthru");
		STAILQ_FOREACH (pc, &conf->passthrues, next)
			fprintf(fp, " %s", pc->devid);
		fprintf(fp, "\n");
	}

	i = 0;
	STAILQ_FOREACH (dc, &conf->disks, next) {
		snprintf(buf, sizeof(buf), "disk%d", i++);
		fprintf(fp, lfmt, buf, dc->type, dc->path);
	}
	i = 0;
	STAILQ_FOREACH (ic, &conf->isoes, next) {
		snprintf(buf, sizeof(buf), "iso%d", i++);
		fprintf(fp, lfmt, buf, ic->type, ic->path);
	}
	i = 0;
	STAILQ_FOREACH (nc, &conf->nets, next) {
		snprintf(buf, sizeof(buf), "net%d", i++);
		fprintf(fp, lfmt, buf, nc->type, nc->bridge);
	}
	fb = conf->fbuf;
	if (fb->enable) {
		fprintf(fp, "%18s = %s:%d, %dx%d, %s, %s\n", "graphics",
		    fb->ipaddr,
		    fb->port, fb->width, fb->height, fb->vgaconf,
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

int
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

int
compare_passthru_conf(const struct passthru_conf *a, const struct passthru_conf *b)
{
	int rc;

	CMP_STR(devid);

	return 0;
}

int
compare_disk_conf(const struct disk_conf *a, const struct disk_conf *b)
{
	int rc;

	CMP_STR(type);
	CMP_STR(path);

	return 0;
}

int
compare_iso_conf(const struct iso_conf *a, const struct iso_conf *b)
{
	int rc;

	CMP_STR(type);
	CMP_STR(path);

	return 0;
}

int
compare_net_conf(const struct net_conf *a, const struct net_conf *b)
{
	int rc;

	CMP_STR(type);
	CMP_STR(bridge);
	/*
	 * We don't need to compare tap.
	 * Because it is not written in the vm config file.
	 * 'tap' holds assigned tap interface name while vm is running.
	 *
	 * CMP_STR(tap);
	 */

	return 0;
}

int
compare_vm_conf(const struct vm_conf *a, const struct vm_conf *b)
{
	int rc;
	struct passthru_conf *pa, *pb;
	struct disk_conf *da, *db;
	struct iso_conf *ia, *ib;
	struct net_conf *na, *nb;
	struct bhyveload_env *ba, *bb;

	CMP_NUM(boot_delay);
	CMP_NUM(loader_timeout);
	CMP_NUM(stop_timeout);
	CMP_NUM(hostbridge);
	CMP_NUM(owner);
	CMP_NUM(group);
	CMP_STR(debug_port);
	CMP_STR(ncpu);
	CMP_STR(memory);
	CMP_STR(name);
	CMP_STR(comport);
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

	for (pa = STAILQ_FIRST(&a->passthrues), pb = STAILQ_FIRST(&b->passthrues);
	     pa != NULL && pb != NULL;
	     pa = STAILQ_NEXT(pa, next), pb = STAILQ_NEXT(pb, next))
		if ((rc = compare_passthru_conf(pa, pb)) != 0)
			return rc;
	if (pa != NULL)
		return 1;
	if (pb != NULL)
		return -1;

	for (da = STAILQ_FIRST(&a->disks), db = STAILQ_FIRST(&b->disks);
	     da != NULL && db != NULL;
	     da = STAILQ_NEXT(da, next), db = STAILQ_NEXT(db, next))
		if ((rc = compare_disk_conf(da, db)) != 0)
			return rc;
	if (da != NULL)
		return 1;
	if (db != NULL)
		return -1;

	for (ia = STAILQ_FIRST(&a->isoes), ib = STAILQ_FIRST(&b->isoes);
	     ia != NULL && ib != NULL;
	     ia = STAILQ_NEXT(ia, next), ib = STAILQ_NEXT(ib, next))
		if ((rc = compare_iso_conf(ia, ib)) != 0)
			return rc;
	if (ia != NULL)
		return 1;
	if (ib != NULL)
		return -1;

	for (na = STAILQ_FIRST(&a->nets), nb = STAILQ_FIRST(&b->nets);
	     na != NULL && nb != NULL;
	     na = STAILQ_NEXT(na, next), nb = STAILQ_NEXT(nb, next))
		if ((rc = compare_net_conf(na, nb)) != 0)
			return rc;
	if (na != NULL)
		return 1;
	if (nb != NULL)
		return -1;

	for (ba = STAILQ_FIRST(&a->bhyveload_envs),
		     bb = STAILQ_FIRST(&b->bhyveload_envs);
	     ba != NULL && bb != NULL;
	     ba = STAILQ_NEXT(ba, next), bb = STAILQ_NEXT(bb, next))
		if ((rc = compare_string(ba->env, bb->env)) != 0)
			return rc;
	if (ba != NULL)
		return 1;
	if (bb != NULL)
		return -1;

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

int
del_var(struct vartree *vars, char *k)
{
	struct conf_var key = {.key = k, .val = NULL};

	if (k == NULL)
		return -1;

	RB_REMOVE(vartree, vars, &key);
	return 0;
}

int
set_var0(struct vartree *vars, char *k, const char *v)
{
	struct conf_var *n, key = {.key = k, .val = NULL};
	char *nk, *nv;

	if (k == NULL || v == NULL)
		return -1;

	if ((n = RB_FIND(vartree, vars, &key))) {
		if ((nv = strdup(v)) == NULL)
			return -1;
		free(n->val);
		n->val = nv;
	} else {
		n = malloc(sizeof(*n));
		nk = strdup(k);
		nv = strdup(v);
		if (n == NULL || nk == NULL || nv == NULL) {
			free(nv);
			free(nk);
			free(n);
			return -1;
		}
		n->key = nk;
		n->val = nv;
		RB_INSERT(vartree, vars, n);
	}
	return 0;
}

int
set_var(struct variables *vars, char *k, const char *v)
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
init_global_vars()
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
free_global_vars()
{
	if (global_vars == NULL)
		return;

	free_vartree(global_vars);

	global_vars = NULL;
}

char *
get_var0(struct vartree *vars, char *k)
{
	struct conf_var *r, key = {.key = k, .val = NULL};

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
compare_nvlist_null(const nvlist_t *a, const char *k, const nvlist_t *b)
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
	const char * const *da, * const *db;
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
	const nvlist_t * const *da, * const *db;
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
compare_nvlist_descriptor_array(const nvlist_t *a, const char *k, const nvlist_t *b)
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
		if (! nvlist_exists_type(b, k, t))
			return 1;
		if (t < 0 || t > sizeof(cfuncs)/sizeof(cfuncs[0]))
			continue;
		if ((rc = (*cfuncs[t])(a, k, b)) != 0)
			return rc;
	}

	cookie = NULL;
	while ((k = nvlist_next(b, &t, &cookie)) != NULL)
		if (! nvlist_exists_type(a, k, t))
			return -1;

	return 0;
}
