#ifndef ROOTVIEW_VM_H
#define ROOTVIEW_VM_H

#include <stddef.h>

#include "vm/vm_types.h"

/* cfg must be fully resolved (defaults + file + flags already applied by the caller) */
int vm_create(const vm_config_t *cfg, char *err, size_t err_len);

int vm_start(const char *name, char *err, size_t err_len);
int vm_stop(const char *name, char *err, size_t err_len);
int vm_restart(const char *name, char *err, size_t err_len);
int vm_destroy(const char *name, bool force, char *err, size_t err_len);

void vm_inspect(const char *name);
void vm_list(void);

/* connects the calling terminal to the VM's QEMU monitor socket, blocks until ^] */
int vm_console(const char *name, char *err, size_t err_len);

#endif
