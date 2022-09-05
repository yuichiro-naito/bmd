#ifndef _PARSER_H
#define _PARSER_H

#include <sys/nv.h>

struct plugin_data_head;

struct vm_conf *parse_file(int fd, const char *filename,
			   struct plugin_data_head *head);

#endif
