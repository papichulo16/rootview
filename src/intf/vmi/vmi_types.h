#ifndef ROOTVIEW_VMI_TYPES_H
#define ROOTVIEW_VMI_TYPES_H

#include <stdbool.h>

#include <libvmi/libvmi.h>

#define VMI_NAME_MAX 64

/* vmi_arch_t is libvmi's: VMI_ARCH_X86_64 or VMI_ARCH_ARM64 here */

typedef struct vmi_ops vmi_ops_t;
typedef struct pkvmi_conn pkvmi_conn_t;

typedef struct {
    const vmi_ops_t *ops; /* the backend this session was attached through */
    char vm_name[VMI_NAME_MAX];
    vmi_instance_t vmi;   /* kvm-vmi only */
    pkvmi_conn_t *pkvmi;  /* pkvm-vmi only, owned by the session */
    bool attached;
} vmi_session_t;

#endif
