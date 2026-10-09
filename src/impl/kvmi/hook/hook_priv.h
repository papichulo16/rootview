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

/* registers the shared single-step event (disabled on every vcpu) once */
int hook_ss_ensure(hook_manager_t *mgr, char *err, size_t err_len);

/* the single-step event's two users: re-plants the pending breakpoint, and
 * finishes the write capture pending on vcpu. each is a no-op when nothing
 * of its kind is pending. */
void hook_bp_stepped(hook_manager_t *mgr);
void hook_mem_stepped(hook_manager_t *mgr, uint32_t vcpu);

/* drops any capture pending for h, which is being torn down */
void hook_mem_forget(hook_manager_t *mgr, hook_t *h);

#endif
