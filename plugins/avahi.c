#include "stdio.h"
#include "stdlib.h"
#include "../vars.h"

int avahi_initialize(struct global_conf *conf)
{
	return 0;
}

void avahi_finalize(struct global_conf *conf)
{
}

void avahi_status_change(struct vm *vm, void **data)
{
	printf("called plugin for vm %s state %d\n",
	       vm->conf->name, vm->state);
}

PLUGIN_DESC plugin_desc = {
	PLUGIN_VERSION,
	"avahi",
	avahi_initialize,
	avahi_finalize,
	avahi_status_change
};
