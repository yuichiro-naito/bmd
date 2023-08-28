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
	struct vm_conf_head list;
	init_gl_conf();
	free(gl_conf->config_file);
	gl_conf->config_file = strdup("./test0.conf");
	assert(load_config_file(&list, true) == 0);

}

int
main(int argc, char *argv[])
{
	test0();

	puts("parser test: ok");
	return 0;
}
