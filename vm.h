#ifndef _VM_H_
#define _VM_H_

#include <sys/types.h>
#include "vars.h"

int write_mapfile(struct vm *vm);
pid_t grub_load(struct vm *vm);
pid_t bhyve_load(struct vm *vm);
int remove_taps(struct vm *vm);
int activate_taps(struct vm *vm);
int assign_taps(struct vm *vm);
int exec_bhyve(struct vm *vm);
int destroy_vm(struct vm *vm);
int start_vm(struct vm *vm);
void cleanup_vm(struct vm *vm);

#endif
