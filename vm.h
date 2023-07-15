#ifndef _VM_H_
#define _VM_H_

struct vm;

/* Implemented in vm.c */
int remove_taps(struct vm *vm);
int activate_taps(struct vm *vm);
int assign_taps(struct vm *vm);
int write_err_log(int fd, struct vm *vm);
int write_mapfile(struct vm_conf *conf, char **mapfile);

/* Implemented in tap.c */
int add_to_bridge(int s, const char *bridge, const char *tap);
int activate_tap(int s, const char *name);
int create_tap(int s, char **name);
int destroy_tap(int s, const char *name);
int set_tap_description(int s, const char *tap, char *desc);

#endif
