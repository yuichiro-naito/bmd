#ifndef _COMMAND_H
#define _COMMAND_H


struct sock_buf;
struct global_conf;

struct sock_buf *create_sock_buf(int fd);
void destroy_sock_buf(struct sock_buf *p);
struct sock_buf *lookup_sock_buf(int fd);
void clear_sock_buf(struct sock_buf *p);
int recv_sock_buf(struct sock_buf *sb);
void clear_send_sock_buf(struct sock_buf *p);
int send_sock_buf(struct sock_buf *p);

int connect_to_server(const struct global_conf *gc);
int create_command_server(const struct global_conf *gc);
int accept_command_socket(int s0);
int recv_command(struct sock_buf *sb);

#endif
