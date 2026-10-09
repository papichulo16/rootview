#include "kern/prof/kwatch.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define FAIL(...)                                                                                                      \
    do {                                                                                                               \
        if (err) snprintf(err, err_len, __VA_ARGS__);                                                                  \
        return -1;                                                                                                     \
    } while (0)

#define PAGE 4096ull
#define SYSCALL_MAX 1024

const char *kwatch_table_name(kwatch_table_t table) {
    return table == KWATCH_SYSCALL ? "sys_call_table" : table == KWATCH_IDT ? "idt" : "?";
}

/* the first symbol above addr's own address, or 0 */
static uint64_t next_sym(const ksym_table_t *tab, uint64_t addr) {
    size_t lo = 0, hi = tab->n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (tab->syms[mid].addr <= addr) lo = mid + 1;
        else hi = mid;
    }
    return lo < tab->n ? tab->syms[lo].addr : 0;
}

/* the frames under [va, va + extent) */
static int frames(const kprof_t *kp, kwatch_region_t *r, uint64_t extent, char *err, size_t err_len) {
    r->npages = 0;
    for (uint64_t p = r->va & ~(PAGE - 1); p < r->va + extent; p += PAGE) {
        if (r->npages == KWATCH_MAX_PAGES) FAIL("%s spans more than %d pages", kwatch_table_name(r->table), KWATCH_MAX_PAGES);
        uint64_t pa;
        char e[200];
        if (pt_translate(&kp->target.mem, &kp->root, p, &pa, NULL, e, sizeof(e)) != 0)
            FAIL("%s page 0x%016" PRIx64 ": %s", kwatch_table_name(r->table), p, e);
        r->page_va[r->npages] = p;
        r->gfn[r->npages++] = pa / PAGE;
    }
    return 0;
}

int kwatch_regions(const kprof_t *kp, uint64_t idtr_base, kwatch_region_t out[KWATCH_TABLES], char *err,
                   size_t err_len) {
    /* sys_call_table: no length of its own, so up to the first NULL, inside
     * the gap to the next symbol - every page of which is watched */
    const ksym_t *sct = ksym_by_name(&kp->ksym, "sys_call_table");
    if (!sct) FAIL("no sys_call_table symbol");
    uint64_t next = next_sym(&kp->ksym, sct->addr);
    uint64_t extent = next ? next - sct->addr : SYSCALL_MAX * 8;
    if (extent > SYSCALL_MAX * 8) extent = SYSCALL_MAX * 8;
    uint64_t tab[SYSCALL_MAX];
    if (kprof_read(kp, sct->addr, tab, extent & ~7ull, err, err_len) != 0) return -1;
    size_t n = 0;
    while (n < extent / 8 && tab[n]) n++;
    out[KWATCH_SYSCALL] = (kwatch_region_t) {.table = KWATCH_SYSCALL, .va = sct->addr, .len = n * 8, .slot_size = 8};
    if (frames(kp, &out[KWATCH_SYSCALL], extent, err, err_len) != 0) return -1;

    /* the IDT through IDTR's own mapping (the cpu entry area's read-only
     * alias): idt_table's writable mapping lands on the same frame */
    out[KWATCH_IDT] = (kwatch_region_t) {.table = KWATCH_IDT, .va = idtr_base, .len = 256 * 16, .slot_size = 16};
    return frames(kp, &out[KWATCH_IDT], 256 * 16, err, err_len);
}

static uint64_t gate_handler(const uint8_t *d) {
    uint16_t lo, mid;
    uint32_t hi;
    memcpy(&lo, d, 2);
    memcpy(&mid, d + 6, 2);
    memcpy(&hi, d + 8, 4);
    return lo | (uint64_t) mid << 16 | (uint64_t) hi << 32;
}

static const char *name_at(const kprof_t *kp, uint64_t addr, uint64_t *off) {
    *off = 0;
    if (addr < kp->img.start || addr >= kp->img.end) return NULL;
    const ksym_t *s = ksym_by_addr(&kp->ksym, addr, off);
    if (!s) *off = 0;
    return s ? s->name : NULL;
}

int kwatch_decode(const kprof_t *kp, const kwatch_region_t *r, uint64_t gpa, const uint8_t before[KWATCH_WINDOW],
                  const uint8_t after[KWATCH_WINDOW], uint64_t rip, kwatch_write_t *out, char *err, size_t err_len) {
    *out = (kwatch_write_t) {.table = r->table, .slot = -1, .rip = rip};
    out->rip_sym = name_at(kp, rip, &out->rip_off);
    size_t i = 0;
    while (i < r->npages && r->gfn[i] != gpa / PAGE) i++;
    if (i == r->npages) FAIL("gpa 0x%" PRIx64 " isn't on a %s frame", gpa, kwatch_table_name(r->table));
    out->va = r->page_va[i] + gpa % PAGE;
    if (out->va < r->va || out->va >= r->va + r->len) return 0;

    uint64_t slot = (out->va - r->va) / r->slot_size;
    out->slot = (int64_t) slot;
    /* the slot's start inside the window: the window is 16-aligned in
     * physical and virtual memory alike, and so is every slot */
    size_t at = (size_t) ((r->va + slot * r->slot_size) & (KWATCH_WINDOW - 1));
    if (r->table == KWATCH_IDT) {
        out->old_target = gate_handler(before + at);
        out->new_target = gate_handler(after + at);
    } else {
        memcpy(&out->old_target, before + at, 8);
        memcpy(&out->new_target, after + at, 8);
    }
    out->old_sym = name_at(kp, out->old_target, &out->old_off);
    out->new_sym = name_at(kp, out->new_target, &out->new_off);
    return 0;
}
