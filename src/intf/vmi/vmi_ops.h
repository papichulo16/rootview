#ifndef ROOTVIEW_VMI_OPS_H
#define ROOTVIEW_VMI_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "vmi/vmi_types.h"

/* the primitives a backend provides. everything above vmi.h (kern, bind)
 * only ever goes through these, so kvm-vmi and pkvm-vmi share all of it.
 * a NULL op means the backend can't do it, and vmi.h reports that. */
struct vmi_ops {
    const char *name;
    vmi_arch_t arch;
    bool hooks; /* drives the hook module (libvmi events) */
    /* how long one kernel walk may take, 0 for kwalk's default: a backend
     * whose every read is a round trip needs longer */
    uint32_t walk_budget_ms;

    int (*attach)(const char *target, vmi_session_t *session, char *err, size_t err_len);
    void (*detach)(vmi_session_t *session);

    int (*read_phys)(vmi_session_t *session, uint64_t paddr, void *buf, size_t len, char *err, size_t err_len);
    int (*write_phys)(vmi_session_t *session, uint64_t paddr, const void *buf, size_t len, char *err, size_t err_len);
    int (*read_virt)(vmi_session_t *session, uint64_t vaddr, void *buf, size_t len, char *err, size_t err_len);
    int (*write_virt)(vmi_session_t *session, uint64_t vaddr, const void *buf, size_t len, char *err,
                      size_t err_len);
    int (*translate_virt)(vmi_session_t *session, uint64_t vaddr, uint64_t *paddr, char *err, size_t err_len);
    /* NULL when the backend caches nothing that could go stale */
    int (*refresh_paging)(vmi_session_t *session, char *err, size_t err_len);

    int (*pause)(vmi_session_t *session, char *err, size_t err_len);
    int (*resume)(vmi_session_t *session, char *err, size_t err_len);

    int (*read_reg_name)(vmi_session_t *session, const char *name, uint64_t *value, char *err, size_t err_len);
    int (*write_reg_name)(vmi_session_t *session, const char *name, uint64_t value, char *err, size_t err_len);

    /* any kernel text address the image can be found from */
    int (*kernel_anchor)(vmi_session_t *session, uint64_t *vaddr, char *err, size_t err_len);

    /* x86/libvmi only: by reg_t, and the full x86 set */
    int (*read_reg)(vmi_session_t *session, reg_t reg, uint64_t *value, char *err, size_t err_len);
    int (*write_reg)(vmi_session_t *session, reg_t reg, uint64_t value, char *err, size_t err_len);
    int (*read_regs)(vmi_session_t *session, x86_registers_t *regs, char *err, size_t err_len);
};

extern const vmi_ops_t g_kvmi_ops;
extern const vmi_ops_t g_pkvmi_ops;

#endif
