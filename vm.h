#ifndef _VM_H_
#define _VM_H_

struct vm;

int remove_taps(struct vm *vm);
int activate_taps(struct vm *vm);
int assign_taps(struct vm *vm);
int destroy_vm(struct vm *vm);
int reset_vm(struct vm *vm);
int poweroff_vm(struct vm *vm);
int acpi_poweroff_vm(struct vm *vm);
int start_vm(struct vm *vm);
void cleanup_vm(struct vm *vm);
int write_err_log(int fd, struct vm *vm);

#endif
