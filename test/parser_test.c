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
	struct vm_conf_head list = LIST_HEAD_INITIALIZER();
	init_gl_conf();
	free(gl_conf->config_file);
	gl_conf->config_file = strdup("./test0.conf");
	assert(load_config_file(&list, true) == 0);
	printf("parser %s: ok\n", __func__);
}

void
test1()
{
	struct vm_conf_head list = LIST_HEAD_INITIALIZER();
	init_gl_conf();
	free(gl_conf->config_file);
	gl_conf->config_file = strdup("./test1.conf");
	assert(load_config_file(&list, true) == 0);
	printf("parser %s: ok\n", __func__);
}

int
main(int argc, char *argv[])
{
	test0();
	test1();
	return 0;
}
