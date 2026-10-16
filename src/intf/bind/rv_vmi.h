#ifndef ROOTVIEW_BIND_RV_VMI_H
#define ROOTVIEW_BIND_RV_VMI_H

#include "bind/rv.h"

typedef struct {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip, rflags;
    uint64_t cr0, cr2, cr3, cr4;
    uint64_t dr6, dr7;
    uint64_t idtr_base, idtr_limit, gdtr_base, gdtr_limit;
    uint64_t fs_base, gs_base, shadow_gs;
    uint64_t msr_efer, msr_star, msr_lstar, msr_cstar;
    uint64_t sysenter_cs, sysenter_esp, sysenter_eip;
} rv_regs_t;

int rv_pause(rv_handle_t *h, char *err, size_t err_len);
int rv_resume(rv_handle_t *h, char *err, size_t err_len);

int rv_read_phys(rv_handle_t *h, uint64_t pa, void *buf, size_t len, char *err, size_t err_len);
int rv_write_phys(rv_handle_t *h, uint64_t pa, const void *buf, size_t len, char *err, size_t err_len);

int rv_read_virt(rv_handle_t *h, uint64_t va, void *buf, size_t len, char *err, size_t err_len);
int rv_write_virt(rv_handle_t *h, uint64_t va, const void *buf, size_t len, char *err, size_t err_len);
int rv_translate(rv_handle_t *h, uint64_t va, uint64_t *pa, char *err, size_t err_len);

int rv_reg(rv_handle_t *h, const char *name, uint64_t *value, char *err, size_t err_len);
int rv_set_reg(rv_handle_t *h, const char *name, uint64_t value, char *err, size_t err_len);
int rv_regs(rv_handle_t *h, rv_regs_t *out, char *err, size_t err_len);

#endif
