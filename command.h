#ifndef _COMMAND_H
#define _COMMAND_H

int create_command_server(const struct global_conf *gc);
int accept_command_socket(int s0);
int recv_command(int s);

#endif
