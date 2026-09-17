#ifndef ROOTVIEW_HOOK_PRIV_H
#define ROOTVIEW_HOOK_PRIV_H

#include "hook/hook_types.h"

/* shared helpers used by hook.c, hook_reg.c and hook_bp.c - not part of the
 * public API. */
hook_t *hook_find_by_name(hook_manager_t *mgr, const char *name);
hook_t *hook_find_bp_by_vaddr(hook_manager_t *mgr, uint64_t vaddr);
hook_t *hook_alloc_slot(hook_manager_t *mgr);

#endif
