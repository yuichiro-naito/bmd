#ifndef _VM_H_
#define _VM_H_

struct vm;

int remove_taps(struct vm *vm);
int activate_taps(struct vm *vm);
int assign_taps(struct vm *vm);
int write_err_log(int fd, struct vm *vm);

#endif
