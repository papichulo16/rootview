#ifndef ROOTVIEW_KMEM_VMI_H
#define ROOTVIEW_KMEM_VMI_H

#include "kern/prof/kmem.h"
#include "vmi/vmi_types.h"

/* kmem_t over an attached vmi session's physical reads. the session stays
 * owned by the caller - kmem_close() does not detach it. kept out of kmem.h
 * so the offline tests can build without libvmi. */
void kmem_vmi_open(vmi_session_t *session, kmem_t *mem);

#endif
