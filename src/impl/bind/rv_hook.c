#include "rv_priv.h"

#include <stdio.h>
#include <string.h>

#include "vmi/vmi_reg_names.h"

_Static_assert((int) RV_HOOK_REGISTER == HOOK_KIND_REGISTER && (int) RV_HOOK_BREAKPOINT == HOOK_KIND_BREAKPOINT &&
                   (int) RV_HOOK_CPUID == HOOK_KIND_CPUID && (int) RV_HOOK_DESCRIPTOR == HOOK_KIND_DESCRIPTOR &&
                   (int) RV_HOOK_MEM == HOOK_KIND_MEM,
               "rv hook kinds mirror hook_kind_t");
_Static_assert(RV_NAME_MAX == HOOK_NAME_MAX, "rv names fit hook names");
_Static_assert(RV_WINDOW == HOOK_MEM_WINDOW, "one capture window size");
_Static_assert((int) RV_DESC_IDTR == HOOK_DESC_IDTR && (int) RV_DESC_GDTR == HOOK_DESC_GDTR &&
                   (int) RV_DESC_LDTR == HOOK_DESC_LDTR && (int) RV_DESC_TR == HOOK_DESC_TR,
               "rv descriptors mirror hook_desc_t");

static uint32_t access_out(uint8_t vmi) {
    return (vmi & VMI_MEMACCESS_R ? RV_ACCESS_R : 0) | (vmi & VMI_MEMACCESS_W ? RV_ACCESS_W : 0) |
           (vmi & VMI_MEMACCESS_X ? RV_ACCESS_X : 0);
}

static void name_into(const rv_handle_t *h, uint64_t addr, char *out, size_t out_len, uint64_t *off) {
    const kprof_t *kp = &h->kp;
    const ksym_t *s =
        h->prof && addr >= kp->img_start && addr < kp->img_end ? ksym_by_addr(&kp->ksym, addr, off) : NULL;
    snprintf(out, out_len, "%s", s ? s->name : "");
    if (!s) *off = 0;
}

static rv_event_t *ring_slot(rv_handle_t *h) {
    if (h->count == RV_EVENTS_MAX) {
        h->head = (h->head + 1) % RV_EVENTS_MAX;
        h->count--;
        h->dropped++;
    }
    return &h->events[(h->head + h->count++) % RV_EVENTS_MAX];
}

static void push_event(const hook_event_t *ev, void *user_data) {
    rv_handle_t *h = user_data;
    rv_event_t *e = ring_slot(h);
    *e = (rv_event_t) {.seq = h->seq++,
                       .kind = (int) ev->kind,
                       .vcpu = ev->vcpu_id,
                       .vaddr = ev->vaddr,
                       .old_value = ev->old_value,
                       .new_value = ev->new_value,
                       .cpuid_leaf = ev->cpuid_leaf,
                       .cpuid_subleaf = ev->cpuid_subleaf,
                       .descriptor = (int) ev->descriptor,
                       .desc_is_write = ev->desc_is_write,
                       .mem_gpa = ev->mem_gpa,
                       .mem_access = access_out(ev->mem_access),
                       .rip = ev->rip,
                       .captured = ev->mem_captured,
                       .after_ok = ev->mem_after_ok,
                       .window = ev->mem_window};
    snprintf(e->name, sizeof(e->name), "%s", ev->name ? ev->name : "");
    if (ev->kind == HOOK_KIND_MEM) name_into(h, ev->rip, e->rip_sym, sizeof(e->rip_sym), &e->rip_off);
    memcpy(e->before, ev->mem_before, sizeof(e->before));
    memcpy(e->after, ev->mem_after, sizeof(e->after));
}

static int pause_for_hook(rv_handle_t *h, char *err, size_t err_len) {
    return h->w.in_window ? 0 : vmi_pause(&h->session, err, err_len);
}

static int resume_after_hook(rv_handle_t *h, int rc, char *err, size_t err_len) {
    char rerr[256];
    if (!h->w.in_window && vmi_resume(&h->session, rerr, sizeof(rerr)) != 0 && rc == 0) {
        rv_set_err(err, err_len, rerr);
        return -1;
    }
    return rc;
}

API int rv_hook_reg(rv_handle_t *h, const char *name, const char *reg, char *err, size_t err_len) {
    return hook_reg_add(&h->hooks, name, reg, push_event, h, err, err_len);
}

API int rv_hook_bp(rv_handle_t *h, const char *name, uint64_t va, char *err, size_t err_len) {
    if (pause_for_hook(h, err, err_len) != 0) return -1;
    return resume_after_hook(h, hook_bp_add(&h->hooks, name, va, push_event, h, err, err_len), err, err_len);
}

API int rv_hook_cpuid(rv_handle_t *h, const char *name, const char *leaf, char *err, size_t err_len) {
    return hook_cpuid_add(&h->hooks, name, leaf, push_event, h, err, err_len);
}

API int rv_hook_desc(rv_handle_t *h, const char *name, const char *table, char *err, size_t err_len) {
    return hook_desc_add(&h->hooks, name, table, push_event, h, err, err_len);
}

API int rv_hook_mem(rv_handle_t *h, const char *name, uint64_t va, const char *access, char *err, size_t err_len) {
    if (pause_for_hook(h, err, err_len) != 0) return -1;
    return resume_after_hook(h, hook_mem_add(&h->hooks, name, va, access, push_event, h, err, err_len), err,
                             err_len);
}

API int rv_hook_mem_gfn(rv_handle_t *h, const char *name, uint64_t gfn, const char *access, int capture, char *err,
                        size_t err_len) {
    return hook_mem_add_gfn(&h->hooks, name, gfn, access, capture != 0, push_event, h, err, err_len);
}

API int rv_hook_remove(rv_handle_t *h, const char *name, char *err, size_t err_len) {
    return hook_remove(&h->hooks, name, err, err_len);
}

static const char *reg_name(reg_t reg) {
    static const char *const names[] = {"cr0", "cr3", "cr4"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        reg_t r;
        if (vmi_reg_lookup(names[i], &r) == 0 && r == reg) return names[i];
    }
    return reg == MSR_ALL ? "msr_all" : "?";
}

static void hook_out(const hook_t *in, rv_hook_t *out) {
    *out = (rv_hook_t) {.kind = (int) in->kind,
                        .vaddr = in->vaddr,
                        .cpuid_leaf = in->cpuid_leaf,
                        .cpuid_any = in->cpuid_leaf == HOOK_CPUID_ANY_LEAF,
                        .descriptor = (int) in->descriptor,
                        .mem_gfn = in->mem_gfn,
                        .mem_access = access_out(in->mem_access),
                        .mem_capture = in->mem_capture};
    snprintf(out->name, sizeof(out->name), "%s", in->name);
    if (in->kind != HOOK_KIND_REGISTER) return;
    snprintf(out->reg, sizeof(out->reg), "%s", reg_name(in->reg));
}

API int rv_hooks(rv_handle_t *h, rv_hook_t *out, size_t max, size_t *n, char *err, size_t err_len) {
    (void) err, (void) err_len;
    int count = hook_count(&h->hooks);
    for (int i = 0; i < count && (size_t) i < max; i++) hook_out(hook_at(&h->hooks, i), &out[i]);
    *n = (size_t) count;
    return 0;
}

API int rv_hook_poll(rv_handle_t *h, uint32_t timeout_ms, char *err, size_t err_len) {
    return hook_poll(&h->hooks, timeout_ms, err, err_len);
}

API int rv_events(rv_handle_t *h, rv_event_t *out, size_t max, size_t *n, uint64_t *dropped, char *err,
                  size_t err_len) {
    (void) err, (void) err_len;
    size_t take = h->count < max ? h->count : max;
    for (size_t i = 0; i < take; i++) out[i] = h->events[(h->head + i) % RV_EVENTS_MAX];
    h->head = (h->head + take) % RV_EVENTS_MAX;
    h->count -= take;
    *n = take;
    *dropped = h->dropped;
    h->dropped = 0;
    return 0;
}
