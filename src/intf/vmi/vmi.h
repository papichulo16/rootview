#ifndef ROOTVIEW_VMI_H
#define ROOTVIEW_VMI_H

#include <stddef.h>
#include <stdint.h>

#include "vmi/vmi_types.h"

/* looks up vm_name through the vm module, confirms it's running with kvmi
 * enabled, and attaches libvmi to its introspection socket. session must be
 * zero-initialized (or already vmi_detach()'d) before calling. this and
 * vmi_detach are the only functions here that know the vm module exists. */
int vmi_attach(const char *vm_name, vmi_session_t *session, char *err, size_t err_len);
void vmi_detach(vmi_session_t *session);
bool vmi_is_attached(const vmi_session_t *session);

int vmi_read_phys(vmi_session_t *session, uint64_t paddr, void *buf, size_t len, char *err, size_t err_len);
int vmi_write_phys(vmi_session_t *session, uint64_t paddr, const void *buf, size_t len, char *err, size_t err_len);

/* walks whatever page table the vm's current CR3 points at - call vmi_pause
 * first so the address space doesn't shift mid-read. */
int vmi_read_virt(vmi_session_t *session, uint64_t vaddr, void *buf, size_t len, char *err, size_t err_len);
int vmi_write_virt(vmi_session_t *session, uint64_t vaddr, const void *buf, size_t len, char *err, size_t err_len);

int vmi_pause(vmi_session_t *session, char *err, size_t err_len);
int vmi_resume(vmi_session_t *session, char *err, size_t err_len);

/* single vcpu register, by reg_t - see vmi_reg_lookup() in vmi_reg_names.h
 * for going from a name (including the control/debug/MSR set) to a reg_t.
 * vmi_write_reg needs the vm paused first: the KVMI backend refuses to set
 * a running vcpu's registers. it can also only ever write the
 * general-purpose set - see vmi_reg_write_supported() - since this kvmi
 * build's wire protocol has no command for writing CR/DR/MSR registers.
 * the new value is staged kernel-side and only actually lands on the vcpu
 * when the pending pause is replied to, i.e. on the next vmi_resume() - a
 * vmi_read_reg() while still paused will keep reporting the old value. */
int vmi_read_reg(vmi_session_t *session, reg_t reg, uint64_t *value, char *err, size_t err_len);
int vmi_write_reg(vmi_session_t *session, reg_t reg, uint64_t value, char *err, size_t err_len);

/* full register snapshot in one call - cheaper than vmi_read_reg per field
 * when dumping most of the set at once. */
int vmi_read_regs(vmi_session_t *session, x86_registers_t *regs, char *err, size_t err_len);

#endif
