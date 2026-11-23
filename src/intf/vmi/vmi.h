#ifndef ROOTVIEW_VMI_H
#define ROOTVIEW_VMI_H

#include <stddef.h>
#include <stdint.h>

#include "vmi/vmi_types.h"

#define VMI_BACKEND_KVMI "kvm-vmi"
#define VMI_BACKEND_PKVMI "pkvm-vmi"

/* backend is "kvm-vmi" or "pkvm-vmi"; every call below then goes to that
 * backend's primitives (vmi_ops.h). target is what that backend attaches to:
 *   kvm-vmi   a vm name: looked up through the vm module, has to be running
 *             with kvmi enabled
 *   pkvm-vmi  an adb serial, or NULL/"" for adb's default device: the phone's
 *             kernel is read from EL2 through the pkvmi CLI on the phone
 * session must be zero-initialized (or already vmi_detach()'d) before calling. */
int vmi_attach(const char *backend, const char *target, vmi_session_t *session, char *err, size_t err_len);
void vmi_detach(vmi_session_t *session);
bool vmi_is_attached(const vmi_session_t *session);

const char *vmi_backend_name(const vmi_session_t *session);
vmi_arch_t vmi_arch(const vmi_session_t *session);
bool vmi_has_hooks(const vmi_session_t *session);
/* the backend's time budget for one kernel walk, 0 for kwalk's default */
uint32_t vmi_walk_budget_ms(const vmi_session_t *session);

int vmi_read_phys(vmi_session_t *session, uint64_t paddr, void *buf, size_t len, char *err, size_t err_len);
int vmi_write_phys(vmi_session_t *session, uint64_t paddr, const void *buf, size_t len, char *err, size_t err_len);

/* walks the kernel's current page tables - call vmi_pause first so the
 * address space doesn't shift mid-read. kvm-vmi walks CR3 (falling back to
 * the KPTI kernel PGD when CR3 is a user PGD that doesn't map vaddr);
 * pkvm-vmi walks TTBR1_EL1/TTBR0_EL1 itself. */
int vmi_read_virt(vmi_session_t *session, uint64_t vaddr, void *buf, size_t len, char *err, size_t err_len);
int vmi_write_virt(vmi_session_t *session, uint64_t vaddr, const void *buf, size_t len, char *err, size_t err_len);

/* resolves vaddr to a physical address the same way vmi_read_virt does -
 * call vmi_pause first so the address space doesn't shift mid-lookup. */
int vmi_translate_virt(vmi_session_t *session, uint64_t vaddr, uint64_t *paddr, char *err, size_t err_len);

/* re-reads the paging mode and drops cached translations and pages. kvm-vmi's
 * attach records the mode once, which is wrong when the guest was still in
 * firmware or the bootloader then. a no-op where the backend caches nothing. */
int vmi_refresh_paging(vmi_session_t *session, char *err, size_t err_len);

/* kvm-vmi stops the vcpus, and both calls drop libvmi's cached translations
 * and pages so nothing cached while the guest ran is used inside a pause, nor
 * carried out of one. pkvm-vmi can't stop the phone (it's reading its own
 * host), so there it means "page tables don't change until resume" and
 * caches them. */
int vmi_pause(vmi_session_t *session, char *err, size_t err_len);
int vmi_resume(vmi_session_t *session, char *err, size_t err_len);

/* one register by name: the x86 set (vmi_reg_names.h) on kvm-vmi, the EL1 and
 * EL2 system registers (sctlr_el1, ttbr1_el1, vbar_el1, hcr_el2, ...) on
 * pkvm-vmi */
int vmi_read_reg_name(vmi_session_t *session, const char *name, uint64_t *value, char *err, size_t err_len);
int vmi_write_reg_name(vmi_session_t *session, const char *name, uint64_t value, char *err, size_t err_len);

/* a kernel text address to find the image from: MSR_LSTAR, VBAR_EL1 */
int vmi_kernel_anchor(vmi_session_t *session, uint64_t *vaddr, char *err, size_t err_len);

/* kvm-vmi only, by libvmi reg_t - see vmi_reg_lookup() in vmi_reg_names.h.
 * vmi_write_reg needs the vm paused first: the KVMI backend refuses to set
 * a running vcpu's registers. it can also only ever write the
 * general-purpose set - see vmi_reg_write_supported() - since this kvmi
 * build's wire protocol has no command for writing CR/DR/MSR registers.
 * the new value is staged kernel-side and only actually lands on the vcpu
 * when the pending pause is replied to, i.e. on the next vmi_resume() - a
 * vmi_read_reg() while still paused will keep reporting the old value. */
int vmi_read_reg(vmi_session_t *session, reg_t reg, uint64_t *value, char *err, size_t err_len);
int vmi_write_reg(vmi_session_t *session, reg_t reg, uint64_t value, char *err, size_t err_len);

/* full x86 register snapshot in one call (kvm-vmi only) */
int vmi_read_regs(vmi_session_t *session, x86_registers_t *regs, char *err, size_t err_len);

#endif
