/* kcheck tests, over each fixture with a mem.raw. clean first: every
 * sys_call_table entry a __x64_sys_* at its start, every present IDT gate
 * an asm_* handler or one of the stubs the kernel leaves, LSTAR on
 * entry_SYSCALL_64, no ftrace record enabled or patched, and nothing
 * suspect anywhere. then hooked the way rootkits hook: a syscall entry
 * into a module's text, one mid-function, one onto a function that isn't
 * a syscall; an IDT gate into a module, one with a foreign selector, one
 * made callable from user mode; LSTAR into a module; and an ftrace site
 * patched to a call with and without its record agreeing. each time
 * exactly that slot turns suspect, with exactly those flags, and every
 * other slot stays as it was. */
#include <inttypes.h>

#include "fixture.h"
#include "kern/prof/kcheck.h"
#include "kern/prof/kfield.h"

/* ---- a kmem_t that patches bytes over the dump ---- */

typedef struct {
    kmem_t base;
    struct {
        uint64_t pa;
        unsigned char val;
    } patch[256];
    int n;
} overlay_t;

static int overlay_read(void *ctx, uint64_t pa, void *buf, size_t len, char *err, size_t err_len) {
    overlay_t *o = ctx;
    if (kmem_read_pa(&o->base, pa, buf, len, err, err_len) != 0) return -1;
    for (int i = 0; i < o->n; i++)
        if (o->patch[i].pa >= pa && o->patch[i].pa < pa + len) ((unsigned char *) buf)[o->patch[i].pa - pa] = o->patch[i].val;
    return 0;
}

static void poke(const kprof_t *kp, overlay_t *o, uint64_t va, const void *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint64_t pa;
        char err[256];
        if (pt_translate(&kp->target.mem, &kp->root, va + i, &pa, NULL, err, sizeof(err)) != 0) {
            CHECK(0, "poke 0x%016" PRIx64 ": %s", va + i, err);
            return;
        }
        o->patch[o->n].pa = pa;
        o->patch[o->n++].val = ((const unsigned char *) bytes)[i];
    }
}

static uint64_t sym(const kprof_t *kp, const char *name) {
    const ksym_t *s = ksym_by_name(&kp->ksym, name);
    CHECK(s, "no %s", name);
    return s ? s->addr : 0;
}

typedef int (*check_fn)(kwalk_t *w, const kscan_result_t *mods, kcheck_result_t *r, char *err, size_t err_len);

static const kcheck_entry_t *by_index(const kcheck_result_t *r, uint32_t index) {
    for (size_t i = 0; i < r->n; i++)
        if (r->e[i].index == index) return &r->e[i];
    return NULL;
}

static void print_entry(const kcheck_entry_t *e) {
    printf("    %s[%u] -> 0x%016" PRIx64 " %s+0x%" PRIx64 "%s%s flags %#x%s\n", kcheck_kind_name(e->kind), e->index,
           e->target, e->sym ? e->sym : "?", e->sym_off, e->owner[0] ? " in " : "", e->owner, e->flags,
           e->suspect ? " SUSPECT" : "");
}

/* ---- clean ---- */

static void test_clean(kwalk_t *w, const kscan_result_t *mods, kcheck_result_t r[4]) {
    char err[512];
    check_fn fns[4] = {kcheck_syscalls, kcheck_idt, kcheck_lstar, kcheck_ftrace};
    for (int k = 0; k < 4; k++) {
        if (fns[k](w, mods, &r[k], err, sizeof(err)) != 0) {
            CHECK(0, "%s: %s", kcheck_kind_name((kcheck_kind_t) k), err);
            r[k] = (kcheck_result_t) {0};
            continue;
        }
        printf("  %-7s %4zu checked, %3zu listed, %zu suspect%s%s\n", kcheck_kind_name(r[k].kind), r[k].checked,
               r[k].n, r[k].suspect, r[k].note[0] ? "; " : "", r[k].note);
        CHECK(r[k].suspect == 0, "%s: %zu suspect on a clean dump", kcheck_kind_name(r[k].kind), r[k].suspect);
        for (size_t i = 0; i < r[k].n; i++)
            if (r[k].e[i].suspect) print_entry(&r[k].e[i]);
    }

    const kcheck_result_t *sc = &r[KCHECK_SYSCALL], *idt = &r[KCHECK_IDT];
    CHECK(sc->n >= 300 && sc->n == sc->checked, "%zu syscalls", sc->n);
    const kcheck_entry_t *e0 = by_index(sc, 0), *e217 = by_index(sc, 217);
    CHECK(e0 && e0->sym && !strcmp(e0->sym, "__x64_sys_read"), "sys_call_table[0] is %s", e0 && e0->sym ? e0->sym : "?");
    CHECK(e217 && e217->sym && !strcmp(e217->sym, "__x64_sys_getdents64"), "sys_call_table[217] is %s",
          e217 && e217->sym ? e217->sym : "?");

    size_t early = 0, stubs = 0, user = 0;
    for (size_t i = 0; i < idt->n; i++) {
        early += !!(idt->e[i].flags & KCHECK_IDT_EARLY_STUB);
        stubs += !!(idt->e[i].flags & KCHECK_IDT_IRQ_STUB);
        user += !!(idt->e[i].flags & KCHECK_IDT_USER);
    }
    const kcheck_entry_t *de = by_index(idt, 0), *pf = by_index(idt, 14), *i80 = by_index(idt, 0x80);
    CHECK(de && de->sym && !strcmp(de->sym, "asm_exc_divide_error") && pf && pf->sym &&
              !strcmp(pf->sym, "asm_exc_page_fault"),
          "IDT 0 / 14 aren't divide_error / page_fault");
    CHECK(i80 && (i80->flags & KCHECK_IDT_USER), "int 0x80 isn't a user gate");
    CHECK(stubs > 100, "%zu irq stubs", stubs);
    printf("  idt: %zu present, %zu early stubs, %zu irq stubs, %zu user gates\n", idt->n, early, stubs, user);

    const kcheck_entry_t *ls = r[KCHECK_LSTAR].n ? &r[KCHECK_LSTAR].e[0] : NULL;
    CHECK(ls && ls->sym && !strcmp(ls->sym, "entry_SYSCALL_64") && !ls->sym_off, "LSTAR isn't entry_SYSCALL_64");
    CHECK(r[KCHECK_FTRACE].checked > 1000 && r[KCHECK_FTRACE].n == 0, "ftrace: %zu records, %zu listed",
          r[KCHECK_FTRACE].checked, r[KCHECK_FTRACE].n);
}

/* ---- hooked ---- */

/* runs check with o over the dump: exactly slot index turns suspect with
 * flags want_flags (compared under mask), everything else as in clean */
static void check_hooked(kprof_t *kp, kwalk_t *w, const kscan_result_t *mods, check_fn check,
                         const kcheck_result_t *clean, overlay_t *o, uint32_t index, uint32_t want_flags,
                         uint32_t mask, bool want_suspect, const char *want_owner, const char *what) {
    char err[512];
    kmem_t base = kp->target.mem;
    o->base = base;
    kp->target.mem = (kmem_t) {.read_pa = overlay_read, .ctx = o};
    kcheck_result_t r;
    int rc = check(w, mods, &r, err, sizeof(err));
    kp->target.mem = base;
    if (rc != 0) {
        CHECK(0, "%s: %s", what, err);
        return;
    }
    const kcheck_entry_t *e = by_index(&r, index);
    CHECK(e && (e->flags & mask) == want_flags && e->suspect == want_suspect, "%s: flags %#x want %#x, suspect %d",
          what, e ? e->flags & mask : 0, want_flags, e ? e->suspect : -1);
    if (want_owner) CHECK(e && !strcmp(e->owner, want_owner), "%s: owner '%s'", what, e ? e->owner : "");
    CHECK(r.suspect == (size_t) want_suspect, "%s: %zu suspect", what, r.suspect);
    size_t changed = 0;
    for (size_t i = 0; i < clean->n; i++) {
        const kcheck_entry_t *c = &clean->e[i], *h = by_index(&r, c->index);
        if (c->index != index && (!h || h->target != c->target || h->flags != c->flags || h->suspect)) changed++;
    }
    CHECK(!changed && r.n == clean->n + (by_index(clean, index) ? 0 : 1), "%s: %zu others changed, %zu listed", what,
          changed, r.n);
    printf("  %s:\n", what);
    if (e) print_entry(e);
    kcheck_free(&r);
}

/* a module with text to aim at, or NULL */
static const kscan_object_t *some_module(const kscan_result_t *mods) {
    for (size_t i = 0; i < mods->n; i++)
        if (mods->objs[i].u.module.text_size > 0x100) return &mods->objs[i];
    return NULL;
}

static void test_syscalls(kprof_t *kp, kwalk_t *w, const kscan_result_t *mods, const kcheck_result_t *clean) {
    const kscan_object_t *m = some_module(mods);
    uint64_t sct = sym(kp, "sys_call_table");
    if (m) {
        overlay_t o = {0};
        uint64_t evil = m->u.module.text_base + 0x40;
        poke(kp, &o, sct + 217 * 8, &evil, 8);
        check_hooked(kp, w, mods, kcheck_syscalls, clean, &o, 217, KCHECK_OUT_OF_TEXT | KCHECK_IN_MODULE | KCHECK_UNEXPECTED,
                     ~0u, true, m->name, "getdents64 into a module");
    } else {
        printf("  syscall into a module: SKIP (no module with text)\n");
    }
    overlay_t mid = {0}, other = {0};
    uint64_t kill = sym(kp, "__x64_sys_kill") + 0x10, filldir = sym(kp, "filldir");
    poke(kp, &mid, sct + 62 * 8, &kill, 8);
    check_hooked(kp, w, mods, kcheck_syscalls, clean, &mid, 62, KCHECK_MID_SYMBOL, ~0u, true, NULL,
                 "kill mid-function");
    poke(kp, &other, sct + 0 * 8, &filldir, 8);
    check_hooked(kp, w, mods, kcheck_syscalls, clean, &other, 0, KCHECK_UNEXPECTED, ~0u, true, NULL,
                 "read onto filldir");
}

/* a 64-bit gate: handler, selector, ist and type/attr */
static void gate(unsigned char d[16], uint64_t h, uint16_t sel, uint8_t ist, uint8_t attr) {
    memset(d, 0, 16);
    uint16_t lo = (uint16_t) h, mid = (uint16_t) (h >> 16);
    uint32_t hi = (uint32_t) (h >> 32);
    memcpy(d, &lo, 2);
    memcpy(d + 2, &sel, 2);
    d[4] = ist;
    d[5] = attr;
    memcpy(d + 6, &mid, 2);
    memcpy(d + 8, &hi, 4);
}

static void test_idt(kprof_t *kp, kwalk_t *w, const kscan_result_t *mods, const kcheck_result_t *clean,
                     uint64_t idtr) {
    const kscan_object_t *m = some_module(mods);
    unsigned char d[16];
    const uint32_t mask = ~(KCHECK_IDT_USER);
    if (m) {
        overlay_t o = {0};
        gate(d, m->u.module.text_base + 0x80, 0x10, 0, 0xee);
        poke(kp, &o, idtr + 16 * 0x80, d, 16);
        check_hooked(kp, w, mods, kcheck_idt, clean, &o, 0x80, KCHECK_OUT_OF_TEXT | KCHECK_IN_MODULE | KCHECK_UNEXPECTED,
                     mask, true, m->name, "int 0x80 into a module");
    }
    const kcheck_entry_t *pf = by_index(clean, 14), *db = by_index(clean, 1);
    if (!pf || !db) return;
    overlay_t sel = {0}, user = {0};
    gate(d, pf->target, 0x33, 0, 0x8e);
    poke(kp, &sel, idtr + 16 * 14, d, 16);
    check_hooked(kp, w, mods, kcheck_idt, clean, &sel, 14, KCHECK_IDT_BAD_GATE, ~0u, true, NULL,
                 "page fault gate with a user selector");
    gate(d, db->target, 0x10, (uint8_t) (db->raw >> 24), 0xee);
    poke(kp, &user, idtr + 16 * 1, d, 16);
    check_hooked(kp, w, mods, kcheck_idt, clean, &user, 1, KCHECK_IDT_USER, ~0u, true, NULL, "debug gate DPL 3");
}

static void test_lstar(kprof_t *kp, kwalk_t *w, const kscan_result_t *mods, const kcheck_result_t *clean,
                       dump_ctx_t *ctx) {
    const kscan_object_t *m = some_module(mods);
    if (!m) return;
    uint64_t saved = ctx->regs.lstar;
    ctx->regs.lstar = m->u.module.text_base;
    overlay_t none = {0};
    check_hooked(kp, w, mods, kcheck_lstar, clean, &none, 0, KCHECK_OUT_OF_TEXT | KCHECK_IN_MODULE | KCHECK_UNEXPECTED,
                 ~0u, true, m->name, "LSTAR into a module");
    ctx->regs.lstar = saved;
}

static void test_ftrace(kprof_t *kp, kwalk_t *w, const kscan_result_t *mods, const kcheck_result_t *clean) {
    /* a record from the first ftrace page, and its ip */
    char err[256];
    kfield_t f_rec;
    uint64_t pg, recs, ip, flags;
    if (kfield_resolve(&kp->btf, "ftrace_page", "records", &f_rec, err, sizeof(err)) != 0 ||
        kwalk_read(w, sym(kp, "ftrace_pages_start"), &pg, 8, err, sizeof(err)) != 0 ||
        kwalk_read(w, pg + f_rec.offset, &recs, 8, err, sizeof(err)) != 0) {
        CHECK(0, "ftrace record: %s", err);
        return;
    }
    const uint32_t idx = 7;
    uint64_t rec = recs + idx * 16ull; /* dyn_ftrace: ip, flags, and an empty arch on x86 */
    kwalk_read(w, rec, &ip, 8, NULL, 0);
    kwalk_read(w, rec + 8, &flags, 8, NULL, 0);

    /* call to ftrace_regs_caller (ftrace_caller on kernels that merged them) */
    uint64_t to = ksym_by_name(&kp->ksym, "ftrace_regs_caller") ? sym(kp, "ftrace_regs_caller") : sym(kp, "ftrace_caller");
    unsigned char call[5] = {0xe8};
    int32_t rel = (int32_t) (to - (ip + 5));
    memcpy(call + 1, &rel, 4);
    uint64_t on = flags | (1ull << 31) | (1ull << 26) | 1; /* ENABLED | IPMODIFY, one ops */

    overlay_t hooked = {0}, bytes = {0}, flag = {0};
    poke(kp, &hooked, ip, call, 5);
    poke(kp, &hooked, rec + 8, &on, 8);
    const uint32_t ft = KCHECK_FTRACE_ENABLED | KCHECK_FTRACE_IPMODIFY | KCHECK_FTRACE_DIRECT | KCHECK_FTRACE_CALL |
                        KCHECK_FTRACE_MISMATCH;
    check_hooked(kp, w, mods, kcheck_ftrace, clean, &hooked, idx, KCHECK_FTRACE_ENABLED | KCHECK_FTRACE_IPMODIFY |
                 KCHECK_FTRACE_CALL, ft, false, NULL, "ipmodify ops attached");
    poke(kp, &bytes, ip, call, 5);
    check_hooked(kp, w, mods, kcheck_ftrace, clean, &bytes, idx, KCHECK_FTRACE_CALL | KCHECK_FTRACE_MISMATCH, ft, true,
                 NULL, "call patched in, record says off");
    poke(kp, &flag, rec + 8, &on, 8);
    check_hooked(kp, w, mods, kcheck_ftrace, clean, &flag, idx, KCHECK_FTRACE_ENABLED | KCHECK_FTRACE_IPMODIFY |
                 KCHECK_FTRACE_MISMATCH, ft, true, NULL, "record says on, nop in place");
}

static void test_fixture(const char *dir, const char *name) {
    if (fixture_has_dump(dir, name) <= 0) return;
    printf("fixture %s: kcheck\n", name);
    dump_ctx_t ctx;
    kprof_target_t target;
    kprof_t kp;
    if (fixture_kprof(dir, name, &ctx, &target, &kp) != 0) return;
    kwalk_t w;
    kwalk_init(&w, &kp, 0);
    char err[512];
    kscan_result_t mods = {0};
    CHECK(kscan_modules(&w, &mods, err, sizeof(err)) == 0, "kscan_modules: %s", err);

    kcheck_result_t r[4] = {0};
    test_clean(&w, &mods, r);
    if (r[KCHECK_SYSCALL].n) test_syscalls(&kp, &w, &mods, &r[KCHECK_SYSCALL]);
    if (r[KCHECK_IDT].n) test_idt(&kp, &w, &mods, &r[KCHECK_IDT], ctx.regs.idtr_base);
    if (r[KCHECK_LSTAR].n) test_lstar(&kp, &w, &mods, &r[KCHECK_LSTAR], &ctx);
    if (r[KCHECK_FTRACE].checked) test_ftrace(&kp, &w, &mods, &r[KCHECK_FTRACE]);
    CHECK(ctx.pauses == ctx.resumes && ctx.pauses > 0, "%d pauses, %d resumes", ctx.pauses, ctx.resumes);

    for (int k = 0; k < 4; k++) kcheck_free(&r[k]);
    kscan_free(&mods);
    kwalk_free(&w);
    kprof_free(&kp);
    kmem_close(&target.mem);
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "tests/fixtures";
    for_each_fixture(dir, test_fixture);
    printf(failures ? "\n%d FAILED\n" : "\nall passed\n", failures);
    return failures ? 1 : 0;
}
