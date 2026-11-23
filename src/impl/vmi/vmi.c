#include "vmi/vmi.h"

#include <stdio.h>
#include <string.h>

#include "vmi/vmi_ops.h"

/* the op, or NULL when it isn't there or nothing is attached */
#define VMI_OP(session, op) ((session)->ops ? (session)->ops->op : NULL)

static const vmi_ops_t *const g_backends[] = {&g_kvmi_ops, &g_pkvmi_ops};

static const vmi_ops_t *vmi_backend_find(const char *name) {
    const vmi_ops_t *ops = NULL;

    for (size_t i = 0; i < sizeof(g_backends) / sizeof(g_backends[0]) && !ops; i++)
        if (strcmp(g_backends[i]->name, name) == 0) ops = g_backends[i];

    return ops;
}

/* the op is there and the session is attached */
static int vmi_need(const vmi_session_t *session, const void *op, const char *what, char *err, size_t err_len) {
    int rc = -1;

    if (!session->attached) {
        if (err) snprintf(err, err_len, "session not attached");
        goto out;
    }
    if (!op) {
        if (err) snprintf(err, err_len, "%s isn't supported by %s", what, session->ops->name);
        goto out;
    }
    rc = 0;

out:
    return rc;
}

int vmi_attach(const char *backend, const char *target, vmi_session_t *session, char *err, size_t err_len) {
    int rc = -1;
    const vmi_ops_t *ops = vmi_backend_find(backend ? backend : "");

    if (session->attached) {
        if (err) snprintf(err, err_len, "session is already attached to '%s'", session->vm_name);
        goto out;
    }
    if (!ops) {
        if (err) snprintf(err, err_len, "unknown backend '%s' (" VMI_BACKEND_KVMI " or " VMI_BACKEND_PKVMI ")",
                          backend ? backend : "");
        goto out;
    }

    session->ops = ops;
    rc = ops->attach(target ? target : "", session, err, err_len);
    if (rc != 0) session->ops = NULL;

out:
    return rc;
}

void vmi_detach(vmi_session_t *session) {
    if (session->attached) session->ops->detach(session);
    memset(session, 0, sizeof(*session));
}

bool vmi_is_attached(const vmi_session_t *session) {
    return session->attached;
}

const char *vmi_backend_name(const vmi_session_t *session) {
    return session->ops ? session->ops->name : "";
}

vmi_arch_t vmi_arch(const vmi_session_t *session) {
    return session->ops ? session->ops->arch : VMI_ARCH_X86_64;
}

bool vmi_has_hooks(const vmi_session_t *session) {
    return session->ops && session->ops->hooks;
}

uint32_t vmi_walk_budget_ms(const vmi_session_t *session) {
    return session->ops ? session->ops->walk_budget_ms : 0;
}

int vmi_read_phys(vmi_session_t *session, uint64_t paddr, void *buf, size_t len, char *err, size_t err_len) {
    if (vmi_need(session, VMI_OP(session, read_phys), "read_phys", err, err_len) != 0) return -1;
    return session->ops->read_phys(session, paddr, buf, len, err, err_len);
}

int vmi_write_phys(vmi_session_t *session, uint64_t paddr, const void *buf, size_t len, char *err, size_t err_len) {
    if (vmi_need(session, VMI_OP(session, write_phys), "write_phys", err, err_len) != 0)
        return -1;
    return session->ops->write_phys(session, paddr, buf, len, err, err_len);
}

int vmi_read_virt(vmi_session_t *session, uint64_t vaddr, void *buf, size_t len, char *err, size_t err_len) {
    if (vmi_need(session, VMI_OP(session, read_virt), "read_virt", err, err_len) != 0) return -1;
    return session->ops->read_virt(session, vaddr, buf, len, err, err_len);
}

int vmi_write_virt(vmi_session_t *session, uint64_t vaddr, const void *buf, size_t len, char *err, size_t err_len) {
    if (vmi_need(session, VMI_OP(session, write_virt), "write_virt", err, err_len) != 0)
        return -1;
    return session->ops->write_virt(session, vaddr, buf, len, err, err_len);
}

int vmi_translate_virt(vmi_session_t *session, uint64_t vaddr, uint64_t *paddr, char *err, size_t err_len) {
    if (vmi_need(session, VMI_OP(session, translate_virt), "translate", err, err_len) != 0)
        return -1;
    return session->ops->translate_virt(session, vaddr, paddr, err, err_len);
}

int vmi_refresh_paging(vmi_session_t *session, char *err, size_t err_len) {
    if (vmi_need(session, session->ops, "refresh_paging", err, err_len) != 0) return -1;
    if (!session->ops->refresh_paging) return 0;
    return session->ops->refresh_paging(session, err, err_len);
}

int vmi_pause(vmi_session_t *session, char *err, size_t err_len) {
    if (vmi_need(session, VMI_OP(session, pause), "pause", err, err_len) != 0) return -1;
    return session->ops->pause(session, err, err_len);
}

int vmi_resume(vmi_session_t *session, char *err, size_t err_len) {
    if (vmi_need(session, VMI_OP(session, resume), "resume", err, err_len) != 0) return -1;
    return session->ops->resume(session, err, err_len);
}

int vmi_read_reg_name(vmi_session_t *session, const char *name, uint64_t *value, char *err, size_t err_len) {
    if (vmi_need(session, VMI_OP(session, read_reg_name), "reading registers", err, err_len) != 0)
        return -1;
    return session->ops->read_reg_name(session, name, value, err, err_len);
}

int vmi_write_reg_name(vmi_session_t *session, const char *name, uint64_t value, char *err, size_t err_len) {
    if (vmi_need(session, VMI_OP(session, write_reg_name), "writing registers", err, err_len) != 0)
        return -1;
    return session->ops->write_reg_name(session, name, value, err, err_len);
}

int vmi_kernel_anchor(vmi_session_t *session, uint64_t *vaddr, char *err, size_t err_len) {
    if (vmi_need(session, VMI_OP(session, kernel_anchor), "kernel_anchor", err, err_len) != 0)
        return -1;
    return session->ops->kernel_anchor(session, vaddr, err, err_len);
}

int vmi_read_reg(vmi_session_t *session, reg_t reg, uint64_t *value, char *err, size_t err_len) {
    if (vmi_need(session, VMI_OP(session, read_reg), "reading registers by reg_t", err,
                 err_len) != 0)
        return -1;
    return session->ops->read_reg(session, reg, value, err, err_len);
}

int vmi_write_reg(vmi_session_t *session, reg_t reg, uint64_t value, char *err, size_t err_len) {
    if (vmi_need(session, VMI_OP(session, write_reg), "writing registers by reg_t", err,
                 err_len) != 0)
        return -1;
    return session->ops->write_reg(session, reg, value, err, err_len);
}

int vmi_read_regs(vmi_session_t *session, x86_registers_t *regs, char *err, size_t err_len) {
    if (vmi_need(session, VMI_OP(session, read_regs), "the x86 register set", err, err_len) != 0)
        return -1;
    return session->ops->read_regs(session, regs, err, err_len);
}
