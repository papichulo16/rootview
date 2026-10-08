#include "kern/prof/kprof_vmi.h"

#include "kern/prof/kmem_vmi.h"
#include "vmi/vmi.h"

static int vmi_target_pause(void *ctx, char *err, size_t err_len) {
    return vmi_pause(ctx, err, err_len);
}

static int vmi_target_resume(void *ctx, char *err, size_t err_len) {
    return vmi_resume(ctx, err, err_len);
}

static int vmi_target_regs(void *ctx, kprof_regs_t *regs, char *err, size_t err_len) {
    if (vmi_read_reg(ctx, CR3, &regs->cr3, err, err_len) != 0) return -1;
    if (vmi_read_reg(ctx, CR4, &regs->cr4, err, err_len) != 0) return -1;
    if (vmi_read_reg(ctx, MSR_LSTAR, &regs->lstar, err, err_len) != 0) return -1;
    return vmi_read_reg(ctx, IDTR_BASE, &regs->idtr_base, err, err_len);
}

void kprof_vmi_target(vmi_session_t *session, kprof_target_t *target) {
    *target = (kprof_target_t) {
        .pause = vmi_target_pause, .resume = vmi_target_resume, .read_regs = vmi_target_regs, .ctx = session};
    kmem_vmi_open(session, &target->mem);
}
