/* kwatch tests, over each fixture with a mem.raw: the regions' frames are
 * the ones the canonical root maps the tables to, sys_call_table's length
 * matches kcheck's, and the IDT region is idt_table's frame. then writes
 * are decoded the way the EPT hook hands them over - gpa, the 16-byte
 * window before and after, the writing rip - for a syscall entry swapped
 * through either of its slots in a window, an IDT gate redirected, a byte
 * on the frame but outside the table, and a gpa on no watched frame. */
#include <inttypes.h>

#include "fixture.h"
#include "kern/prof/kwatch.h"

static uint64_t sym(const kprof_t *kp, const char *name) {
    const ksym_t *s = ksym_by_name(&kp->ksym, name);
    CHECK(s, "no %s", name);
    return s ? s->addr : 0;
}

static uint64_t pa_of(const kprof_t *kp, uint64_t va) {
    uint64_t pa = 0;
    CHECK(pt_translate(&kp->target.mem, &kp->root, va, &pa, NULL, NULL, 0) == 0, "translate 0x%016" PRIx64, va);
    return pa;
}

/* the window around va, as the hook would read it from guest memory */
static void window(const kprof_t *kp, uint64_t va, uint8_t out[KWATCH_WINDOW]) {
    char err[256];
    CHECK(kprof_read(kp, va & ~15ull, out, KWATCH_WINDOW, err, sizeof(err)) == 0, "read window: %s", err);
}

static void test_syscall(const kprof_t *kp, const kwatch_region_t *r) {
    uint64_t sct = sym(kp, "sys_call_table"), rip = sym(kp, "native_write_cr0") + 0x10;
    uint64_t evil = 0xffffffffc0de0040ull;
    for (int nr = 216; nr <= 217; nr++) { /* both halves of one window */
        uint64_t va = sct + nr * 8ull;
        uint8_t before[16], after[16];
        window(kp, va, before);
        memcpy(after, before, 16);
        memcpy(after + (va & 15), &evil, 8);
        kwatch_write_t w;
        char err[256];
        CHECK(kwatch_decode(kp, r, pa_of(kp, va), before, after, rip, &w, err, sizeof(err)) == 0, "decode: %s", err);
        const char *want = nr == 217 ? "__x64_sys_getdents64" : "__x64_sys_remap_file_pages";
        CHECK(w.slot == nr && w.va == va && w.new_target == evil && !w.new_sym && w.old_sym &&
                  !strcmp(w.old_sym, want) && !w.old_off,
              "syscall %d: slot %" PRId64 ", old %s new 0x%016" PRIx64, nr, w.slot, w.old_sym ? w.old_sym : "?",
              w.new_target);
        CHECK(w.rip_sym && !strcmp(w.rip_sym, "native_write_cr0") && w.rip_off == 0x10, "rip %s+0x%" PRIx64,
              w.rip_sym ? w.rip_sym : "?", w.rip_off);
        printf("  sys_call_table[%" PRId64 "]: %s -> 0x%016" PRIx64 " by %s+0x%" PRIx64 "\n", w.slot, w.old_sym,
               w.new_target, w.rip_sym, w.rip_off);
    }

    /* past the table's end, still on its last frame */
    uint64_t past = r->va + r->len + 8;
    uint8_t b[16] = {0};
    kwatch_write_t w;
    char err[256];
    CHECK(kwatch_decode(kp, r, pa_of(kp, past), b, b, 0, &w, err, sizeof(err)) == 0 && w.slot == -1,
          "past the table: slot %" PRId64, w.slot);
    /* a frame nobody watches */
    CHECK(kwatch_decode(kp, r, pa_of(kp, sym(kp, "init_task")), b, b, 0, &w, err, sizeof(err)) != 0,
          "init_task's frame decoded");
}

static void gate(uint8_t d[16], uint64_t h) {
    uint16_t lo = (uint16_t) h, mid = (uint16_t) (h >> 16);
    uint32_t hi = (uint32_t) (h >> 32);
    memcpy(d, &lo, 2);
    memcpy(d + 6, &mid, 2);
    memcpy(d + 8, &hi, 4);
}

static void test_idt(const kprof_t *kp, const kwatch_region_t *r, uint64_t idtr) {
    CHECK(pa_of(kp, idtr) == pa_of(kp, sym(kp, "idt_table")), "IDTR's frame isn't idt_table's");
    uint64_t evil = 0xffffffffc0de0080ull;
    /* written through idt_table's own mapping: the same frame, so the same slot */
    uint64_t va = sym(kp, "idt_table") + 0x80 * 16 + 6;
    uint8_t before[16], after[16];
    window(kp, va, before);
    memcpy(after, before, 16);
    gate(after, evil);
    kwatch_write_t w;
    char err[256];
    CHECK(kwatch_decode(kp, r, pa_of(kp, va), before, after, sym(kp, "memcpy"), &w, err, sizeof(err)) == 0,
          "decode: %s", err);
    CHECK(w.slot == 0x80 && w.va == idtr + 0x80 * 16 + 6 && w.new_target == evil && w.old_sym &&
              !strcmp(w.old_sym, "asm_int80_emulation"),
          "idt: slot %" PRId64 ", old %s", w.slot, w.old_sym ? w.old_sym : "?");
    printf("  idt[%#" PRIx64 "]: %s -> 0x%016" PRIx64 " by %s\n", w.slot, w.old_sym, w.new_target,
           w.rip_sym ? w.rip_sym : "?");
}

static void test_fixture(const char *dir, const char *name) {
    if (fixture_has_dump(dir, name) <= 0) return;
    printf("fixture %s: kwatch\n", name);
    dump_ctx_t ctx;
    kprof_target_t target;
    kprof_t kp;
    if (fixture_kprof(dir, name, &ctx, &target, &kp) != 0) return;
    kwatch_region_t r[KWATCH_TABLES];
    char err[256];
    if (kwatch_regions(&kp, ctx.regs.idtr_base, r, err, sizeof(err)) != 0) {
        CHECK(0, "kwatch_regions: %s", err);
    } else {
        for (int t = 0; t < KWATCH_TABLES; t++) {
            printf("  %-14s 0x%016" PRIx64 " %4" PRIu64 " bytes, %zu frame(s):", kwatch_table_name(t), r[t].va,
                   r[t].len, r[t].npages);
            size_t bad = 0;
            for (size_t i = 0; i < r[t].npages; i++) {
                printf(" %#" PRIx64, r[t].gfn[i]);
                bad += pa_of(&kp, r[t].page_va[i]) / 4096 != r[t].gfn[i];
            }
            putchar('\n');
            CHECK(!bad && r[t].npages >= 1, "%s: %zu frames don't match the root", kwatch_table_name(t), bad);
        }
        /* the counts kcheck found: 449 on 5.15, 470 on 6.18 */
        size_t n = r[KWATCH_SYSCALL].len / 8;
        CHECK(n == (kp.major == 5 ? 449u : 470u), "%zu syscalls", n);
        CHECK(r[KWATCH_IDT].len == 4096 && r[KWATCH_IDT].npages == 1, "idt region");
        test_syscall(&kp, &r[KWATCH_SYSCALL]);
        test_idt(&kp, &r[KWATCH_IDT], ctx.regs.idtr_base);
    }
    kprof_free(&kp);
    kmem_close(&target.mem);
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "tests/fixtures";
    for_each_fixture(dir, test_fixture);
    printf(failures ? "\n%d FAILED\n" : "\nall passed\n", failures);
    return failures ? 1 : 0;
}
