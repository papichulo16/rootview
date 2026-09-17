#ifndef ROOTVIEW_HOOK_H
#define ROOTVIEW_HOOK_H

#include <stddef.h>
#include <stdint.h>

#include "hook/hook_types.h"
#include "vmi/vmi_types.h"

/* mgr must be zero-initialized (or already hook_manager_clear()'d) before
 * calling. session must already be attached and must outlive mgr. */
void hook_manager_init(hook_manager_t *mgr, vmi_session_t *session);

/* tears down every hook still registered (register monitoring disabled,
 * planted 0xcc bytes restored) and releases the shared breakpoint
 * infrastructure if it was ever set up. safe to call on an empty manager. */
void hook_manager_clear(hook_manager_t *mgr);

/* watches writes to a control register (cr0, cr3, cr4) or every MSR at once
 * (msr_all) - these are the registers this kvmi build can trap a write to
 * at all, see vmi_reg_lookup() in vmi_reg_names.h for the full name set.
 * classic rootkit hook targets: CR0's write-protect bit, CR3 for stealthy
 * page-table swaps, the syscall MSRs (LSTAR/STAR/CSTAR/...) for syscall
 * table hijacking - msr_all reports which one fired via the callback.
 * fires callback from inside hook_poll(), vcpu paused for its duration. */
int hook_reg_add(hook_manager_t *mgr, const char *name, const char *reg_name,
                  hook_callback_t callback, void *user_data, char *err, size_t err_len);

/* plants an INT3 at vaddr (walks the current CR3, like vmi_read_virt/
 * vmi_write_virt - pause the vm first so the address space doesn't shift
 * mid-plant). fires callback whenever the guest traps there; the original
 * byte is transparently restored, single-stepped over, and replanted so
 * execution isn't otherwise disturbed. a real (non-hook) INT3 elsewhere is
 * reinjected into the guest untouched.
 *
 * the recoil step needs the hypervisor's MTF single-step support - some
 * doubly-nested KVM setups don't expose it (kvmi_control_singlestep fails
 * with EINVAL), in which case a hit still fires the callback correctly but
 * the 0xcc silently fails to replant afterwards, so the hook only fires
 * once. unaffected on bare-metal KVM/KVMI hosts. */
int hook_bp_add(hook_manager_t *mgr, const char *name, uint64_t vaddr,
                 hook_callback_t callback, void *user_data, char *err, size_t err_len);

/* removes a hook by name - disables the underlying register monitoring or
 * restores the original byte, whichever applies. */
int hook_remove(hook_manager_t *mgr, const char *name, char *err, size_t err_len);

/* pumps the vmi event queue for timeout_ms, invoking callbacks for whatever
 * fired. 0 drains only what's already pending. */
int hook_poll(hook_manager_t *mgr, uint32_t timeout_ms, char *err, size_t err_len);

int hook_count(const hook_manager_t *mgr);
const hook_t *hook_at(const hook_manager_t *mgr, int index);

#endif
