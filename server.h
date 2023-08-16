#ifndef _SERVER_H
#define _SERVER_H


/*
 * Nmdm number offset for auto assignment.
 */
#define DEFAULT_NMDM_OFFSET 200

struct sock_buf;
struct global_conf;

struct sock_buf *create_sock_buf(int fd);
void destroy_sock_buf(struct sock_buf *p);
void clear_sock_buf(struct sock_buf *p);
int recv_sock_buf(struct sock_buf *sb);
void clear_send_sock_buf(struct sock_buf *p);
int send_sock_buf(struct sock_buf *p);

int connect_to_server(const struct global_conf *gc);
int create_command_server(const struct global_conf *gc);
int accept_command_socket(int s0);
int recv_command(struct sock_buf *sb);
struct timespec *calc_timeout(int timeout, struct timespec *ts);
int close_timeout_sock_buf(int timeout);

char *get_peer_comport(const char *comport);
int attach_console(const char *vmname, const char *comport);

#endif
