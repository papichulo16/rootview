#ifndef ROOTVIEW_VM_STORE_H
#define ROOTVIEW_VM_STORE_H

#include <limits.h>
#include <stdbool.h>

#include "vm/vm_types.h"

/* store root is ./.rootview/vms, created on first use */
const char *vm_store_root(void);

void vm_store_dir(const char *name, char out[PATH_MAX]);
void vm_store_config_path(const char *name, char out[PATH_MAX]);
void vm_store_state_path(const char *name, char out[PATH_MAX]);
void vm_store_log_path(const char *name, char out[PATH_MAX]);

bool vm_store_exists(const char *name);
int vm_store_make_dir(const char *name);
int vm_store_remove_dir(const char *name);

/* fills `names` with up to max VM names found in the store, returns count */
int vm_store_list(char names[][VM_NAME_MAX], int max);

#endif
