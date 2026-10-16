#ifndef ROOTVIEW_VMI_TYPES_H
#define ROOTVIEW_VMI_TYPES_H

#include <stdbool.h>

#include <libvmi/libvmi.h>

#define VMI_NAME_MAX 64

typedef struct {
    char vm_name[VMI_NAME_MAX];
    vmi_instance_t vmi;
    bool attached;
} vmi_session_t;

#endif
