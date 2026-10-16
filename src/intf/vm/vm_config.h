#ifndef ROOTVIEW_VM_CONFIG_H
#define ROOTVIEW_VM_CONFIG_H

#include <stddef.h>

#include "vm/vm_types.h"

void vm_config_default(vm_config_t *cfg, const char *name);

/* parses a JSON blob (from a --config file or the stored config.json) into cfg.
 * fields absent from the JSON keep whatever was already in cfg. */
int vm_config_from_json_file(const char *path, vm_config_t *cfg, char *err, size_t err_len);

int vm_config_load(const char *name, vm_config_t *cfg);
int vm_config_save(const vm_config_t *cfg);

#endif
