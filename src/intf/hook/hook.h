#ifndef ROOTVIEW_HOOK_H
#define ROOTVIEW_HOOK_H

#include <stddef.h>
#include <stdint.h>

#include "hook/hook_types.h"
#include "vmi/vmi_types.h"

/* mgr must be zero-initialized before calling; session must outlive mgr. */
void hook_manager_init(hook_manager_t *mgr, vmi_session_t *session);

/* tears down every hook still registered - safe to call on an empty manager. */
void hook_manager_clear(hook_manager_t *mgr);

/* watches writes to cr0, cr3, cr4, or every msr at once (msr_all) - the only
 * registers this kvmi build can trap a write to. */
int hook_reg_add(hook_manager_t *mgr, const char *name, const char *reg_name,
                  hook_callback_t callback, void *user_data, char *err, size_t err_len);

/* plants an INT3 at vaddr (walks the current CR3 - pause the vm first).
 * needs the hypervisor's MTF single-step support to re-arm after a hit. */
int hook_bp_add(hook_manager_t *mgr, const char *name, uint64_t vaddr,
                 hook_callback_t callback, void *user_data, char *err, size_t err_len);

/* traps cpuid execution. leaf is a hex leaf value, or "any" to match every
 * leaf. KVMI allows only one CPUID registration at a time, so every cpuid
 * hook is multiplexed off one shared event. */
int hook_cpuid_add(hook_manager_t *mgr, const char *name, const char *leaf,
                    hook_callback_t callback, void *user_data, char *err, size_t err_len);

/* traps loads/stores of one descriptor table register (idtr, gdtr, ldtr,
 * tr). KVMI allows only one DESCRIPTOR registration at a time, so every
 * descriptor hook is multiplexed off one shared event. */
int hook_desc_add(hook_manager_t *mgr, const char *name, const char *table,
                   hook_callback_t callback, void *user_data, char *err, size_t err_len);

/* traps r/w/x access to the guest page containing vaddr (walks the current
 * CR3 - pause the vm first). access is any combination of the letters r,
 * w, x (eg. "rw", "x"). unlike hook_bp_add this never writes to guest
 * memory, so it can't be detected by code that checksums itself. */
int hook_mem_add(hook_manager_t *mgr, const char *name, uint64_t vaddr, const char *access,
                  hook_callback_t callback, void *user_data, char *err, size_t err_len);

int hook_remove(hook_manager_t *mgr, const char *name, char *err, size_t err_len);

/* pumps the vmi event queue for timeout_ms; 0 drains only what's pending. */
int hook_poll(hook_manager_t *mgr, uint32_t timeout_ms, char *err, size_t err_len);

int hook_count(const hook_manager_t *mgr);
const hook_t *hook_at(const hook_manager_t *mgr, int index);

#endif
