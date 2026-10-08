#ifndef ROOTVIEW_KPROF_VMI_H
#define ROOTVIEW_KPROF_VMI_H

#include "kern/prof/kprof.h"
#include "vmi/vmi_types.h"

/* kprof_target_t over an attached vmi session: reads through
 * kmem_vmi_open, pauses and resumes the whole vm, and takes the registers
 * from vcpu 0. the session stays owned by the caller. kept apart from
 * kprof.h so the offline tests build without libvmi. */
void kprof_vmi_target(vmi_session_t *session, kprof_target_t *target);

#endif
