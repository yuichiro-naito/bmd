#ifndef _COMMAND_H
#define _COMMAND_H

#include "vars.h"

int connect_to_server(const struct global_conf *gc);
int create_command_server(const struct global_conf *gc);
int accept_command_socket(int s0);
int recv_command(int s);

#endif
