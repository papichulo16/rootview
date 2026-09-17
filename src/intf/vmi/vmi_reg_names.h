#ifndef ROOTVIEW_VMI_REG_NAMES_H
#define ROOTVIEW_VMI_REG_NAMES_H

#include <libvmi/libvmi.h>

/* case-insensitive name -> reg_t lookup. covers the general-purpose set plus
 * the control/debug/descriptor-table/MSR registers a rootkit would tamper
 * with (CR0 write-protect bit, CR3/CR4, IDTR/GDTR, MSR_LSTAR & co for
 * syscall table hooking). returns 0 and fills *out on a match, -1 if name
 * is not a known register. */
int vmi_reg_lookup(const char *name, reg_t *out);

#endif
