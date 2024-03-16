#include <sys/fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../bmd.h"

void
test0()
{
	struct vm_conf_list list = LIST_HEAD_INITIALIZER();
	init_gl_conf();
	free(gl_conf->config_file);
	gl_conf->config_file = strdup("./test0.conf");
	assert(load_config_file(&list, true) == 0);
	printf("parser %s: ok\n", __func__);
}

void
check_test(struct vm_conf *c)
{
	assert(c->ncpu == 4);
	assert(strcmp(c->memory, "2G") == 0);
	assert(strcmp(c->err_logfile, "/var/log/test.log") == 0);
}

void
check_test0(struct vm_conf *c)
{
	assert(strcmp(c->err_logfile, "aaa") == 0);
	assert(c->ncpu == 4);
}

void
check_test1_0(struct vm_conf *c)
{
	assert(strcmp(c->err_logfile, "/var/log/test1_0.log") == 0);
	assert(c->ncpu == 1);
	assert(c->ncpu_sockets == 1);
	assert(c->ncpu_cores == 1);
	assert(c->ncpu_threads == 1);
}

void
check_test1_1(struct vm_conf *c)
{
	assert(strcmp(c->err_logfile, "") == 0);
	assert(c->ncpu == 8);
	assert(c->ncpu_sockets == 2);
	assert(c->ncpu_cores == 2);
	assert(c->ncpu_threads == 2);
}

void
check_test2_0(struct vm_conf *c)
{
	assert(strcmp(c->err_logfile, "/var/log/test2_0.log") == 0);
	assert(c->ncpu == 4);
	assert(c->ncpu_sockets == 1);
	assert(c->ncpu_cores == 2);
	assert(c->ncpu_threads == 2);
}

void
check_test2_1(struct vm_conf *c)
{
	assert(strcmp(c->err_logfile, "/var/log/test2_1.log") == 0);
	assert(c->ncpu == 4);
	assert(c->ncpu_sockets == 2);
	assert(c->ncpu_cores == 1);
	assert(c->ncpu_threads == 2);
}

void
check_test3_0(struct vm_conf *c)
{
	assert(c->ncpu == 4);
	assert(strcmp(c->memory, "2G") == 0);
	assert(strcmp(c->err_logfile, "zzz") == 0);
	assert(c->loadcmd == NULL);
}

void
check_test3_1(struct vm_conf *c)
{
	assert(c->ncpu == 4);
	assert(strcmp(c->memory, "2G") == 0);
	assert(strcmp(c->err_logfile, "/var/log/test3_1.log") == 0);
	assert(c->loadcmd == NULL);
}

void
check_test4_0(struct vm_conf *c)
{
	assert(c->ncpu == 4);
	assert(strcmp(c->memory, "2G") == 0);
	assert(strcmp(c->err_logfile, "zzz") == 0);
	assert(strcmp(c->loadcmd, "") == 0);
}

void
check_test4_1(struct vm_conf *c)
{
	assert(c->ncpu == 4);
	assert(strcmp(c->memory, "2G") == 0);
	assert(strcmp(c->err_logfile, "zzz") == 0);
	assert(strcmp(c->loadcmd, "") == 0);
}

void
check_test4_2(struct vm_conf *c)
{
	assert(c->ncpu == 4);
	assert(strcmp(c->memory, "2G") == 0);
	assert(strcmp(c->err_logfile, "/var/log/test4_2.log") == 0);
	assert(strcmp(c->loadcmd, "") == 0);
}

void
check_test4_3(struct vm_conf *c)
{
	assert(c->ncpu == 4);
	assert(strcmp(c->memory, "2G") == 0);
	assert(strcmp(c->err_logfile, "/var/log/test4_3.log") == 0);
	assert(strcmp(c->loadcmd, "load") == 0);
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
}

int
main(int argc, char *argv[])
{
	test0();
	test1();
	return 0;
}
