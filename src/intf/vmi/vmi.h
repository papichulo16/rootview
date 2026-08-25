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

/* pid = 0 means kernel address space (no per-process cr3) */
int vmi_read_phys(vmi_session_t *session, uint64_t paddr, void *buf, size_t len, char *err, size_t err_len);
int vmi_write_phys(vmi_session_t *session, uint64_t paddr, const void *buf, size_t len, char *err, size_t err_len);
int vmi_read_virt(vmi_session_t *session, uint64_t vaddr, int32_t pid, void *buf, size_t len, char *err,
                   size_t err_len);
int vmi_write_virt(vmi_session_t *session, uint64_t vaddr, int32_t pid, const void *buf, size_t len, char *err,
                    size_t err_len);

int vmi_pause(vmi_session_t *session, char *err, size_t err_len);
int vmi_resume(vmi_session_t *session, char *err, size_t err_len);

#endif
