#ifndef _PARSER_H
#define _PARSER_H

#include <sys/nv.h>

struct plugin_data_head;
struct vm_conf;

struct vm_conf *parse_file(int fd, const char *filename,
			   struct plugin_data_head *head);
int parse_variable(FILE *fp, struct vm_conf *conf, char **value, long *num);
int reverse_polish_notation(FILE *fp, struct vm_conf *conf, int *val);

#endif
