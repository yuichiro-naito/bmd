#include <sys/fcntl.h>
#include <sys/queue.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../bmd.h"

#define assert_str(a, b)  assert(strcmp((a), (b)) == 0)

void
free_vm_conf_list(struct vm_conf_list *l)
{
	struct vm_conf_entry *c = NULL, *n;
	LIST_FOREACH_FROM_SAFE(c, l, next, n)
		free_vm_conf_entry(c);
}

void
test0()
{
	struct vm_conf_list list = LIST_HEAD_INITIALIZER();
	init_gl_conf();
	free(gl_conf->config_file);
	gl_conf->config_file = strdup("./test0.conf");
	assert(load_config_file(&list, true) == 0);
	printf("parser %s: ok\n", __func__);
	free_vm_conf_list(&list);
}

void
check_test(struct vm_conf *c)
{
	assert(c->ncpu == 4);
	assert_str(c->memory, "2G");;
	assert_str(c->err_logfile, "/var/log/test.log");;
}

void
check_test0(struct vm_conf *c)
{
	assert_str(c->err_logfile, "aaa");;
	assert(c->ncpu == 4);
}

void
check_test1_0(struct vm_conf *c)
{
	assert_str(c->err_logfile, "/var/log/test1_0.log");;
	assert(c->ncpu == 1);
	assert(c->ncpu_sockets == 1);
	assert(c->ncpu_cores == 1);
	assert(c->ncpu_threads == 1);
}

void
check_test1_1(struct vm_conf *c)
{
	assert_str(c->err_logfile, "");;
	assert(c->ncpu == 8);
	assert(c->ncpu_sockets == 2);
	assert(c->ncpu_cores == 2);
	assert(c->ncpu_threads == 2);
}

void
check_test2_0(struct vm_conf *c)
{
	assert_str(c->err_logfile, "/var/log/test2_0.log");;
	assert(c->ncpu == 4);
	assert(c->ncpu_sockets == 1);
	assert(c->ncpu_cores == 2);
	assert(c->ncpu_threads == 2);
}

void
check_test2_1(struct vm_conf *c)
{
	assert_str(c->err_logfile, "/var/log/test2_1.log");;
	assert(c->ncpu == 4);
	assert(c->ncpu_sockets == 2);
	assert(c->ncpu_cores == 1);
	assert(c->ncpu_threads == 2);
}

void
check_test3_0(struct vm_conf *c)
{
	assert(c->ncpu == 4);
	assert_str(c->memory, "2G");;
	assert_str(c->err_logfile, "zzz");;
	assert(c->loadcmd == NULL);
}

void
check_test3_1(struct vm_conf *c)
{
	assert(c->ncpu == 4);
	assert_str(c->memory, "2G");;
	assert_str(c->err_logfile, "/var/log/test3_1.log");;
	assert(c->loadcmd == NULL);
}

void
check_test4_0(struct vm_conf *c)
{
	assert(c->ncpu == 4);
	assert_str(c->memory, "2G");;
	assert_str(c->err_logfile, "zzz");;
	assert_str(c->loadcmd, "");;
}

void
check_test4_1(struct vm_conf *c)
{
	assert(c->ncpu == 4);
	assert_str(c->memory, "2G");;
	assert_str(c->err_logfile, "zzz");;
	assert_str(c->loadcmd, "");;
}

void
check_test4_2(struct vm_conf *c)
{
	assert(c->ncpu == 4);
	assert_str(c->memory, "2G");;
	assert_str(c->err_logfile, "/var/log/test4_2.log");;
	assert_str(c->loadcmd, "");;
}

void
check_test4_3(struct vm_conf *c)
{
	assert(c->ncpu == 4);
	assert_str(c->memory, "2G");;
	assert_str(c->err_logfile, "/var/log/test4_3.log");;
	assert_str(c->loadcmd, "load");;
}

#define TENTRY(num)  {"test"#num, check_test##num}
struct check_func {
	char *vm_name;
	void (*tfunc)(struct vm_conf *);
} check_list[] = {
	TENTRY(),
	TENTRY(0),
	TENTRY(1_0),
	TENTRY(1_1),
	TENTRY(2_0),
	TENTRY(2_1),
	TENTRY(3_0),
	TENTRY(3_1),
	TENTRY(4_0),
	TENTRY(4_1),
	TENTRY(4_2),
	TENTRY(4_3),
};

static int
listcomp(const void *a, const void *b)
{
	const struct check_func *b0 = b;
	return strcmp(a, b0->vm_name);
}

void
test1()
{
	struct vm_conf *conf;
	struct vm_conf_entry *e;
	struct vm_conf_list list = LIST_HEAD_INITIALIZER();
	struct check_func *f;
	init_gl_conf();
	free(gl_conf->config_file);
	gl_conf->config_file = strdup("./test1.conf");
	assert(load_config_file(&list, true) == 0);
	LIST_FOREACH (e, &list, next) {
		conf = &e->conf;
		f = bsearch(conf->name, check_list, nitems(check_list),
			    sizeof(check_list[0]), listcomp);
		assert(f != NULL);
		(f->tfunc)(conf);
		printf("vm %s: ok\n", f->vm_name);
	}
	printf("parser %s: ok\n", __func__);
	free_vm_conf_list(&list);
}

void
test2()
{
	struct vm_conf *conf;
	struct vm_conf_list list = LIST_HEAD_INITIALIZER();
	struct fbuf *f;
	struct disk_conf *dc;
	struct iso_conf *ic;
	struct net_conf *nc;
	struct sharefs_conf *sc;
	struct bhyve_env *be;
	struct bhyveload_env *le;
	struct cpu_pin *cp;
	struct passthru_conf *pc;
	struct hda_conf *hc;
//	openlog("bmd", LOG_PID | LOG_PERROR, LOG_DAEMON);
	init_gl_conf();
	free(gl_conf->config_file);
	gl_conf->config_file = strdup("./test2.conf");
	assert(load_config_file(&list, true) == 0);
	conf = &LIST_FIRST(&list)->conf;
	assert(conf != NULL);
	assert(conf->boot == YES);
	assert(conf->boot_delay == 10);
	assert_str(conf->com[0], "auto");
	assert_str(conf->com[1], "/dev/nmdm1A");
	assert_str(conf->com[2], "/dev/nmdm2A");
	assert_str(conf->com[3], "/dev/nmdm3A");
	assert_str(conf->debug_port, "9876");
	assert(conf->ncpu == 2);
	assert_str(conf->memory, "4G");
	assert_str(conf->loader, "bhyveload");
	dc = STAILQ_FIRST(&conf->disks);
	assert_str(dc->type, "nvme");
	assert(dc->noexist);
	assert(dc->direct);
	assert(dc->nocache);
	assert(dc->readonly);
	assert_str(dc->path, "/dev/zvol/images/test2");
	ic = STAILQ_FIRST(&conf->isoes);
	assert_str(ic->path, "/dev/cd0");
	assert(ic->noexist);
	nc = STAILQ_FIRST(&conf->nets);
	assert_str(nc->type, "e1000");
	assert(nc->wol);
	assert_str(nc->mac, "22:11:33:44:55:66");
	assert_str(nc->bridge, "bridge0");
	sc = STAILQ_FIRST(&conf->sharefss);
	assert_str(sc->name, "myhome");
	assert_str(sc->path, "/users/home");
	f = conf->fbuf;
	assert(f->enable);
	assert_str(f->vgaconf, "on");
	assert(f->height == 768);
	assert(f->width == 1024);
	assert_str(f->ipaddr, "127.0.0.1");
	assert(f->port == 5902);
	assert(f->wait);
	assert_str(f->vgaconf, "on");
	assert_str(f->password, "foo_bar");
	assert(conf->install);
	assert_str(conf->installcmd, "auto");
	assert_str(conf->loadcmd, "kopenbsd");
	assert(conf->loader_timeout == 70);
	assert_str(conf->keymap, "ja");
	assert(conf->owner == getuid());
	assert(conf->virt_random);
	assert(conf->hostbridge == AMD);
	be = STAILQ_FIRST(&conf->bhyve_envs);
	assert_str(be->env, "BHYVE_TMP=/tmp2");
	le = STAILQ_FIRST(&conf->bhyveload_envs);
	assert_str(le->env, "machdep.hyperthreading_allowed=0");
	assert_str(conf->bhyveload_loader, "/boot/usrboot2.so");
	assert_str(conf->name, "test_name");
	cp = STAILQ_FIRST(&conf->cpu_pins);
	assert(cp->vcpu == 1);
	assert(cp->hostcpu == 5);
	assert(conf->owner == getuid());
	assert(conf->reboot_on_change);
	pc = STAILQ_FIRST(&conf->passthrues);
	assert_str(pc->devid, "1/0/12");
	assert(conf->stop_timeout == 98);
	assert(conf->utctime);
	assert(conf->wired_memory);
	assert(conf->x2apic);
	assert(conf->mouse);
	hc = STAILQ_FIRST(&conf->hdas);
	assert_str(hc->play_dev, "/dev/dsp2");
	assert_str(hc->rec_dev, "/dev/dsp0");
	printf("parser %s: ok\n", __func__);
	free_vm_conf_list(&list);
}

int
parser_test(void)
{
	test0();
	test1();
	test2();
	return 0;
}
