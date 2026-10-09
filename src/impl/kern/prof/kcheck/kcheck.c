#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "kcheck_priv.h"

const char *kcheck_kind_name(kcheck_kind_t kind) {
    switch (kind) {
    case KCHECK_SYSCALL: return "syscall";
    case KCHECK_IDT: return "idt";
    case KCHECK_LSTAR: return "lstar";
    case KCHECK_FTRACE: return "ftrace";
    }
    return "?";
}

void kcheck_free(kcheck_result_t *r) {
    free(r->e);
    r->e = NULL;
    r->n = r->cap = 0;
}

int kcheck_begin(kcheck_ctx_t *c, kwalk_t *w, const kscan_result_t *mods, kcheck_result_t *r, kcheck_kind_t kind,
                 char *err, size_t err_len) {
    *r = (kcheck_result_t) {.kind = kind};
    *c = (kcheck_ctx_t) {.w = w, .mods = mods && mods->kind == KSCAN_MODULE ? mods : NULL};
    const ksym_t *s = ksym_by_name(&w->kp->ksym, "_stext"), *e = ksym_by_name(&w->kp->ksym, "_etext");
    if (!s || !e || s->addr >= e->addr) FAIL("no _stext/_etext in kallsyms");
    c->stext = s->addr;
    c->etext = e->addr;
    c->own = !w->in_window;
    return c->own ? kwalk_begin(w, err, err_len) : 0;
}

int kcheck_end(kcheck_ctx_t *c, kcheck_result_t *r, int rc, char *err, size_t err_len) {
    char rerr[256];
    if (c->own && kwalk_end(c->w, rerr, sizeof(rerr)) != 0 && rc == 0) {
        if (err) snprintf(err, err_len, "%s", rerr);
        rc = -1;
    }
    if (rc != 0) kcheck_free(r);
    return rc;
}

kcheck_entry_t *kcheck_add(kcheck_result_t *r, uint32_t index, uint64_t slot) {
    if (r->n == r->cap) {
        size_t cap = r->cap ? r->cap * 2 : 64;
        kcheck_entry_t *e = realloc(r->e, cap * sizeof(*e));
        if (!e) return NULL;
        r->e = e;
        r->cap = cap;
    }
    kcheck_entry_t *e = &r->e[r->n++];
    *e = (kcheck_entry_t) {.kind = r->kind, .index = index, .slot = slot};
    return e;
}

static bool is_text_type(char t) {
    return t == 'T' || t == 't' || t == 'W' || t == 'w';
}

void kcheck_place(const kcheck_ctx_t *c, kcheck_entry_t *e) {
    const kprof_t *kp = c->w->kp;
    uint64_t t = e->target;
    if (!t) {
        e->flags |= KCHECK_NULL;
        return;
    }
    bool in_text = t >= c->stext && t < c->etext;
    if (!in_text) e->flags |= KCHECK_OUT_OF_TEXT;
    for (size_t i = 0; c->mods && i < c->mods->n; i++) {
        const kscan_object_t *m = &c->mods->objs[i];
        if (m->u.module.text_size && t >= m->u.module.text_base && t - m->u.module.text_base < m->u.module.text_size) {
            e->flags |= KCHECK_IN_MODULE;
            snprintf(e->owner, sizeof(e->owner), "%s", m->name);
            break;
        }
    }
    /* kallsyms here is the core kernel's: below the image's end, a symbol
     * means something; past it, the last core symbol would just be noise */
    const ksym_t *s = t >= kp->img.start && t < kp->img.end ? ksym_by_addr(&kp->ksym, t, &e->sym_off) : NULL;
    e->sym = s ? s->name : NULL;
    if (!s) e->sym_off = 0;
    if (in_text && (!s || !is_text_type(s->type))) e->flags |= KCHECK_NO_SYMBOL;
    else if (in_text && e->sym_off) e->flags |= KCHECK_MID_SYMBOL;
}

uint64_t kcheck_next_sym(const ksym_table_t *tab, uint64_t addr) {
    size_t lo = 0, hi = tab->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (tab->syms[mid].addr <= addr) lo = mid + 1;
        else hi = mid;
    }
    return lo < tab->n ? tab->syms[lo].addr : 0;
}

int kcheck_regs(const kcheck_ctx_t *c, kprof_regs_t *regs, char *err, size_t err_len) {
    const kprof_target_t *t = &c->w->kp->target;
    if (!t->read_regs) FAIL("the target can't read registers");
    return t->read_regs(t->ctx, regs, err, err_len);
}

/* ---- sys_call_table ---- */

#define SYSCALL_MAX 1024

int kcheck_syscalls(kwalk_t *w, const kscan_result_t *mods, kcheck_result_t *r, char *err, size_t err_len) {
    kcheck_ctx_t c;
    if (kcheck_begin(&c, w, mods, r, KCHECK_SYSCALL, err, err_len) != 0) return -1;
    int rc = -1;
    uint64_t *tab = NULL;
    const ksym_t *sct = ksym_by_name(&w->kp->ksym, "sys_call_table");
    if (!sct) {
        if (err) snprintf(err, err_len, "no sys_call_table symbol");
        goto out;
    }
    uint64_t next = kcheck_next_sym(&w->kp->ksym, sct->addr);
    size_t cap = next ? (size_t) ((next - sct->addr) / 8) : SYSCALL_MAX;
    if (cap > SYSCALL_MAX) cap = SYSCALL_MAX;
    if (!(tab = malloc(cap * 8 + 8))) {
        if (err) snprintf(err, err_len, "out of memory");
        goto out;
    }
    if (kwalk_read(w, sct->addr, tab, cap * 8, err, err_len) != 0) goto out;
    size_t n = 0;
    while (n < cap && tab[n]) n++;
    snprintf(r->note, sizeof(r->note), "%zu entries: up to the first NULL of %zu slots before the next symbol", n,
             cap);

    for (size_t i = 0; i < n; i++) {
        kcheck_entry_t *e = kcheck_add(r, (uint32_t) i, sct->addr + 8 * i);
        if (!e) {
            if (err) snprintf(err, err_len, "out of memory");
            goto out;
        }
        e->target = tab[i];
        kcheck_place(&c, e);
        if (!e->sym || strncmp(e->sym, "__x64_sys_", 10) != 0) e->flags |= KCHECK_UNEXPECTED;
        e->suspect = (e->flags & (KCHECK_PLACE_BAD | KCHECK_UNEXPECTED)) != 0;
        r->suspect += e->suspect;
    }
    r->checked = n;
    rc = 0;
out:
    free(tab);
    return kcheck_end(&c, r, rc, err, err_len);
}

/* ---- the IDT ---- */

#define KERNEL_CS 0x10
#define GATE_INTR 0xe
#define GATE_TRAP 0xf

static uint64_t sym_addr(const kprof_t *kp, const char *name) {
    const ksym_t *s = ksym_by_name(&kp->ksym, name);
    return s ? s->addr : 0;
}

/* a reserved vector's early_idt_handler_array stub: EARLY_IDT_HANDLER_SIZE
 * is 9 bytes, 13 with IBT's endbr */
static bool early_stub(uint64_t early, uint32_t vec, uint64_t t) {
    return early && vec < 32 && (t == early + vec * 9ull || t == early + vec * 13ull);
}

/* a device vector's stub: irq_entries_start has one per vector from 32 up,
 * 8 bytes (16 with IBT) apart; spurious_entries_start's run to its next
 * symbol, also 8-byte aligned */
static bool irq_stub(uint64_t irq, uint64_t spur, uint64_t spur_end, uint32_t vec, uint64_t t) {
    if (irq && spur && vec >= 32 && t >= irq && t < spur)
        return t - irq == (vec - 32) * 8ull || t - irq == (vec - 32) * 16ull;
    return spur && t >= spur && t < spur_end && (t - spur) % 8 == 0;
}

int kcheck_idt(kwalk_t *w, const kscan_result_t *mods, kcheck_result_t *r, char *err, size_t err_len) {
    kcheck_ctx_t c;
    if (kcheck_begin(&c, w, mods, r, KCHECK_IDT, err, err_len) != 0) return -1;
    const kprof_t *kp = w->kp;
    int rc = -1;
    unsigned char g[256 * 16];
    kprof_regs_t regs;
    if (kcheck_regs(&c, &regs, err, err_len) != 0 || kwalk_read(w, regs.idtr_base, g, sizeof(g), err, err_len) != 0)
        goto out;

    /* IDTR normally points at the cpu entry area's read-only alias of
     * idt_table: a different frame means the table was swapped */
    uint32_t table_flags = 0;
    uint64_t idt_table = sym_addr(kp, "idt_table"), pa_idtr, pa_table;
    if (!idt_table) snprintf(r->note, sizeof(r->note), "no idt_table symbol: IDTR's table not checked against it");
    else if (pt_translate(&kp->target.mem, &kp->root, regs.idtr_base, &pa_idtr, NULL, NULL, 0) != 0 ||
             pt_translate(&kp->target.mem, &kp->root, idt_table, &pa_table, NULL, NULL, 0) != 0 || pa_idtr != pa_table)
        table_flags = KCHECK_IDT_NOT_IDT_TABLE;

    uint64_t early = sym_addr(kp, "early_idt_handler_array"), irq = sym_addr(kp, "irq_entries_start");
    uint64_t spur = sym_addr(kp, "spurious_entries_start");
    uint64_t spur_end = spur ? kcheck_next_sym(&kp->ksym, spur) : 0;

    for (uint32_t v = 0; v < 256; v++) {
        const unsigned char *d = g + 16 * v;
        uint8_t attr = d[5];
        if (!(attr & 0x80)) continue; /* not present */
        uint16_t lo, mid, sel;
        uint32_t hi;
        memcpy(&lo, d, 2);
        memcpy(&sel, d + 2, 2);
        memcpy(&mid, d + 6, 2);
        memcpy(&hi, d + 8, 4);
        kcheck_entry_t *e = kcheck_add(r, v, regs.idtr_base + 16 * v);
        if (!e) {
            if (err) snprintf(err, err_len, "out of memory");
            goto out;
        }
        e->target = lo | (uint64_t) mid << 16 | (uint64_t) hi << 32;
        e->raw = attr | (uint64_t) sel << 8 | (uint64_t) (d[4] & 7) << 24;
        e->flags = table_flags;
        if (sel != KERNEL_CS || ((attr & 0xf) != GATE_INTR && (attr & 0xf) != GATE_TRAP)) e->flags |= KCHECK_IDT_BAD_GATE;
        bool user = ((attr >> 5) & 3) == 3;
        if (user) e->flags |= KCHECK_IDT_USER;

        if (early_stub(early, v, e->target)) {
            e->flags |= KCHECK_IDT_EARLY_STUB;
            e->sym = ksym_by_name(&kp->ksym, "early_idt_handler_array")->name;
            e->sym_off = e->target - early;
        } else if (irq_stub(irq, spur, spur_end, v, e->target)) {
            e->flags |= KCHECK_IDT_IRQ_STUB;
            bool in_irq = irq && e->target < spur;
            e->sym = ksym_by_name(&kp->ksym, in_irq ? "irq_entries_start" : "spurious_entries_start")->name;
            e->sym_off = e->target - (in_irq ? irq : spur);
        } else {
            kcheck_place(&c, e);
            if (!e->sym || (strncmp(e->sym, "asm_", 4) && strncmp(e->sym, "entry_", 6) && strncmp(e->sym, "xen_", 4)))
                e->flags |= KCHECK_UNEXPECTED;
        }
        bool user_ok = v == 3 || v == 4 || v == 0x80;
        e->suspect = (e->flags & (KCHECK_PLACE_BAD | KCHECK_UNEXPECTED | KCHECK_IDT_BAD_GATE |
                                  KCHECK_IDT_NOT_IDT_TABLE)) != 0 ||
                     (user && !user_ok);
        r->suspect += e->suspect;
    }
    r->checked = 256;
    rc = 0;
out:
    return kcheck_end(&c, r, rc, err, err_len);
}

/* ---- MSR_LSTAR ---- */

int kcheck_lstar(kwalk_t *w, const kscan_result_t *mods, kcheck_result_t *r, char *err, size_t err_len) {
    kcheck_ctx_t c;
    if (kcheck_begin(&c, w, mods, r, KCHECK_LSTAR, err, err_len) != 0) return -1;
    int rc = -1;
    kprof_regs_t regs;
    uint64_t want = sym_addr(w->kp, "entry_SYSCALL_64");
    kcheck_entry_t *e;
    if (!want) {
        if (err) snprintf(err, err_len, "no entry_SYSCALL_64 symbol");
        goto out;
    }
    if (kcheck_regs(&c, &regs, err, err_len) != 0) goto out;
    if (!(e = kcheck_add(r, 0, 0))) {
        if (err) snprintf(err, err_len, "out of memory");
        goto out;
    }
    e->target = regs.lstar;
    kcheck_place(&c, e);
    if (e->target != want) e->flags |= KCHECK_UNEXPECTED;
    e->suspect = (e->flags & (KCHECK_PLACE_BAD | KCHECK_UNEXPECTED)) != 0;
    r->suspect = e->suspect;
    r->checked = 1;
    rc = 0;
out:
    return kcheck_end(&c, r, rc, err, err_len);
}
