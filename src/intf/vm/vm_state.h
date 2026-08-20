#ifndef ROOTVIEW_VM_STATE_H
#define ROOTVIEW_VM_STATE_H

#include "vm/vm_types.h"

int vm_state_load(const char *name, vm_runtime_state_t *st);
int vm_state_save(const char *name, const vm_runtime_state_t *st);

/* true if st claims to be running and the pid is actually alive */
bool vm_state_is_alive(const vm_runtime_state_t *st);

#endif
