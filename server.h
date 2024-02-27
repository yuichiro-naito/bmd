#ifndef _SERVER_H
#define _SERVER_H


/*
 * Nmdm number offset for auto assignment.
 */
#define DEFAULT_NMDM_OFFSET 200

struct sock_buf;
struct global_conf;

struct sock_buf *create_sock_buf(int);
void destroy_sock_buf(struct sock_buf *);
void clear_sock_buf(struct sock_buf *);
int recv_sock_buf(struct sock_buf *);
void clear_send_sock_buf(struct sock_buf *);
int send_sock_buf(struct sock_buf *);

int connect_to_server(const struct global_conf *);
int create_command_server(const struct global_conf *);
int accept_command_socket(int s0);
int recv_command(struct sock_buf *);
struct timespec *calc_timeout(int , struct timespec *);
int close_timeout_sock_buf(int);

int attach_console(int);

#endif
