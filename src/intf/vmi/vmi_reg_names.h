#ifndef ROOTVIEW_VMI_REG_NAMES_H
#define ROOTVIEW_VMI_REG_NAMES_H

#include <stdbool.h>

#include <libvmi/libvmi.h>

/* case-insensitive name -> reg_t lookup. covers the general-purpose set plus
 * the control/debug/descriptor-table/MSR registers a rootkit would tamper
 * with (CR0 write-protect bit, CR3/CR4, IDTR/GDTR, MSR_LSTAR & co for
 * syscall table hooking). returns 0 and fills *out on a match, -1 if name
 * is not a known register. */
int vmi_reg_lookup(const char *name, reg_t *out);

/* true if this kvmi build can actually persist a write to reg. the
 * KVMI_VCPU_SET_REGISTERS wire command carries a bare struct kvm_regs, so
 * only the general-purpose set (through RFLAGS) is settable - there is no
 * wire command at all for writing CR/DR/MSR/descriptor-table registers. */
bool vmi_reg_write_supported(reg_t reg);

#endif
