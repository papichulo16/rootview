#include "rv_priv.h"

#include <stdio.h>


API int rv_pause(rv_handle_t *h, char *err, size_t err_len) {
    return vmi_pause(&h->session, err, err_len);
}

API int rv_resume(rv_handle_t *h, char *err, size_t err_len) {
    return vmi_resume(&h->session, err, err_len);
}

API int rv_read_phys(rv_handle_t *h, uint64_t pa, void *buf, size_t len, char *err, size_t err_len) {
    return vmi_read_phys(&h->session, pa, buf, len, err, err_len);
}

API int rv_write_phys(rv_handle_t *h, uint64_t pa, const void *buf, size_t len, char *err, size_t err_len) {
    return vmi_write_phys(&h->session, pa, buf, len, err, err_len);
}

API int rv_read_virt(rv_handle_t *h, uint64_t va, void *buf, size_t len, char *err, size_t err_len) {
    return vmi_read_virt(&h->session, va, buf, len, err, err_len);
}

API int rv_write_virt(rv_handle_t *h, uint64_t va, const void *buf, size_t len, char *err, size_t err_len) {
    return vmi_write_virt(&h->session, va, buf, len, err, err_len);
}

API int rv_translate(rv_handle_t *h, uint64_t va, uint64_t *pa, char *err, size_t err_len) {
    return vmi_translate_virt(&h->session, va, pa, err, err_len);
}

API int rv_reg(rv_handle_t *h, const char *name, uint64_t *value, char *err, size_t err_len) {
    return vmi_read_reg_name(&h->session, name, value, err, err_len);
}

API int rv_set_reg(rv_handle_t *h, const char *name, uint64_t value, char *err, size_t err_len) {
    return vmi_write_reg_name(&h->session, name, value, err, err_len);
}

API int rv_regs(rv_handle_t *h, rv_regs_t *out, char *err, size_t err_len) {
    x86_registers_t r;
    if (vmi_read_regs(&h->session, &r, err, err_len) != 0) return -1;
    *out = (rv_regs_t) {.rax = r.rax, .rbx = r.rbx, .rcx = r.rcx, .rdx = r.rdx,
                        .rsi = r.rsi, .rdi = r.rdi, .rbp = r.rbp, .rsp = r.rsp,
                        .r8 = r.r8, .r9 = r.r9, .r10 = r.r10, .r11 = r.r11,
                        .r12 = r.r12, .r13 = r.r13, .r14 = r.r14, .r15 = r.r15,
                        .rip = r.rip, .rflags = r.rflags,
                        .cr0 = r.cr0, .cr2 = r.cr2, .cr3 = r.cr3, .cr4 = r.cr4,
                        .dr6 = r.dr6, .dr7 = r.dr7,
                        .idtr_base = r.idtr_base, .idtr_limit = r.idtr_limit,
                        .gdtr_base = r.gdtr_base, .gdtr_limit = r.gdtr_limit,
                        .fs_base = r.fs_base, .gs_base = r.gs_base, .shadow_gs = r.shadow_gs,
                        .msr_efer = r.msr_efer, .msr_star = r.msr_star,
                        .msr_lstar = r.msr_lstar, .msr_cstar = r.msr_cstar,
                        .sysenter_cs = r.sysenter_cs, .sysenter_esp = r.sysenter_esp,
                        .sysenter_eip = r.sysenter_eip};
    return 0;
}
