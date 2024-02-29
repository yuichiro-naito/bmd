#ifndef _VM_H_
#define _VM_H_

struct vm;
struct vm_conf;
extern struct vm_method bhyve_method;

/* Implemented in vm.c */
int remove_taps(struct vm *);
int activate_taps(struct vm *);
int assign_taps(struct vm *);
int write_err_log(int , struct vm *);
int write_mapfile(struct vm_conf *, char **);
char **split_args(char *);

/* Implemented in tap.c */
int add_to_bridge(int , const char *, const char *);
int activate_tap(int , const char *);
int create_tap(int , char **);
int destroy_tap(int , const char *);
int set_tap_description(int , const char *, char *);

#endif
