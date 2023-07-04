#ifndef _PARSER_H
#define _PARSER_H

#include <sys/nv.h>

struct vm_conf_head;

int load_config_file(struct vm_conf_head *list, bool update_gl_conf);

#endif
