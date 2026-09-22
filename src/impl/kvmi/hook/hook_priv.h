#ifndef ROOTVIEW_HOOK_PRIV_H
#define ROOTVIEW_HOOK_PRIV_H

#include "hook/hook_types.h"

/* shared helpers used by hook.c and the per-kind hook_*.c files - not part
 * of the public API. */
hook_t *hook_find_by_name(hook_manager_t *mgr, const char *name);
hook_t *hook_find_bp_by_vaddr(hook_manager_t *mgr, uint64_t vaddr);
hook_t *hook_find_cpuid_by_leaf(hook_manager_t *mgr, uint32_t leaf);
hook_t *hook_find_desc(hook_manager_t *mgr, hook_desc_t descriptor);
hook_t *hook_alloc_slot(hook_manager_t *mgr);

#endif
