#include "pkvmi/pkvmi_walk.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAGE 4096ull
#define OA_MASK 0x0000fffffffff000ull
#define TTBR_BADDR_MASK 0x0000fffffffffffeull

#define DESC_VALID (1ull << 0)
#define DESC_TABLE (1ull << 1) /* table at levels 0-2, page at level 3 */

#define TCR_T0SZ(tcr) ((tcr) & 0x3f)
#define TCR_T1SZ(tcr) (((tcr) >> 16) & 0x3f)
#define TCR_TG0(tcr) (((tcr) >> 14) & 3)
#define TCR_TG1(tcr) (((tcr) >> 30) & 3)
#define TCR_TBI0(tcr) (((tcr) >> 37) & 1)
#define TCR_TBI1(tcr) (((tcr) >> 38) & 1)

#define TG0_4K 0
#define TG1_4K 2

/* which half of the address space va is in, and that half's settings */
typedef struct {
    uint64_t ttbr;
    unsigned va_bits;
    bool tbi;
    bool upper;
} walk_half_t;

static void walk_half(const pkvmi_walk_t *w, uint64_t va, walk_half_t *h) {
    h->upper = (va >> 55) & 1;
    h->ttbr = h->upper ? w->ttbr1 : w->ttbr0;
    h->va_bits = 64 - (unsigned) (h->upper ? TCR_T1SZ(w->tcr) : TCR_T0SZ(w->tcr));
    h->tbi = h->upper ? TCR_TBI1(w->tcr) : TCR_TBI0(w->tcr);
}

/* the bits above the va range have to be all ones (upper) or all zeros */
static bool walk_va_ok(const walk_half_t *h, uint64_t va) {
    unsigned top = h->tbi ? 56 : 64;
    uint64_t hi = (va & (top == 64 ? ~0ull : (1ull << top) - 1)) >> h->va_bits;
    uint64_t want = h->upper ? (1ull << (top - h->va_bits)) - 1 : 0;

    return hi == want;
}

static size_t walk_slot(const pkvmi_walk_t *w, uint64_t pa) {
    size_t i = (size_t) ((pa >> 12) * 0x9e3779b97f4a7c15ull) & (w->cap - 1);

    while (w->slots[i].page && w->slots[i].pa != pa) i = (i + 1) & (w->cap - 1);
    return i;
}

static int walk_grow(pkvmi_walk_t *w) {
    int rc = -1;
    pkvmi_walk_t bigger = *w;

    bigger.cap = w->cap ? w->cap * 2 : 256;
    bigger.slots = calloc(bigger.cap, sizeof(*bigger.slots));
    if (!bigger.slots) goto out;
    for (size_t i = 0; i < w->cap; i++)
        if (w->slots[i].page) bigger.slots[walk_slot(&bigger, w->slots[i].pa)] = w->slots[i];
    free(w->slots);
    *w = bigger;
    rc = 0;

out:
    return rc;
}

/* the table page at pa, from the cache or read once into it */
static const unsigned char *walk_table(pkvmi_walk_t *w, uint64_t pa, char *err, size_t err_len) {
    const unsigned char *page = NULL;
    unsigned char *fresh = NULL;
    size_t i;

    if ((w->used + 1) * 2 > w->cap && walk_grow(w) != 0) goto oom;
    i = walk_slot(w, pa);
    if (w->slots[i].page) {
        page = w->slots[i].page;
        goto out;
    }
    fresh = malloc(PAGE);
    if (!fresh) goto oom;
    if (w->read(w->ctx, pa, fresh, err, err_len) != 0) goto out;
    w->slots[i] = (pkvmi_walk_slot_t) {.pa = pa, .page = fresh};
    w->used++;
    page = fresh;
    fresh = NULL;
    goto out;

oom:
    if (err) snprintf(err, err_len, "out of memory for page tables");
out:
    free(fresh);
    return page;
}

int pkvmi_walk_init(pkvmi_walk_t *w, uint64_t ttbr0, uint64_t ttbr1, uint64_t tcr, pkvmi_walk_read_fn read, void *ctx,
                    char *err, size_t err_len) {
    int rc = -1;

    *w = (pkvmi_walk_t) {.ttbr0 = ttbr0, .ttbr1 = ttbr1, .tcr = tcr, .read = read, .ctx = ctx};
    if (TCR_TG0(tcr) != TG0_4K || TCR_TG1(tcr) != TG1_4K) {
        if (err) snprintf(err, err_len, "tcr_el1 0x%" PRIx64 " isn't a 4KiB granule", tcr);
        goto out;
    }
    rc = 0;

out:
    return rc;
}

int pkvmi_walk_translate(pkvmi_walk_t *w, uint64_t va, uint64_t *pa, char *err, size_t err_len) {
    int rc = -1;
    walk_half_t h;
    unsigned start, level, shift;
    uint64_t table, desc = 0;

    walk_half(w, va, &h);
    if (h.va_bits < 25 || h.va_bits > 48 || !walk_va_ok(&h, va)) {
        if (err) snprintf(err, err_len, "0x%" PRIx64 " is outside the %u-bit address space", va, h.va_bits);
        goto out;
    }
    /* the first level only resolves the bits left over above the others */
    start = 4 - (h.va_bits - 12 + 8) / 9;
    level = start;
    table = h.ttbr & TTBR_BADDR_MASK;

    for (;; level++) {
        shift = 12 + 9 * (3 - level);
        unsigned idx_bits = level == start ? h.va_bits - shift : 9;
        uint64_t entry = table + ((va >> shift) & ((1ull << idx_bits) - 1)) * 8;
        const unsigned char *page = walk_table(w, entry & ~(PAGE - 1), err, err_len);
        if (!page) goto out;
        memcpy(&desc, page + (entry & (PAGE - 1)), 8);

        if (!(desc & DESC_VALID)) goto unmapped;
        if (level == 3 && !(desc & DESC_TABLE)) goto unmapped;
        if (level == 3 || !(desc & DESC_TABLE)) break;
        table = desc & OA_MASK;
    }
    if (level == 0) goto unmapped; /* no 512GiB blocks with 4KiB pages */
    *pa = (desc & OA_MASK & ~((1ull << shift) - 1)) | (va & ((1ull << shift) - 1));
    rc = 0;
    goto out;

unmapped:
    if (err) snprintf(err, err_len, "0x%" PRIx64 " isn't mapped", va);
out:
    return rc;
}

void pkvmi_walk_flush(pkvmi_walk_t *w) {
    for (size_t i = 0; i < w->cap; i++) free(w->slots[i].page);
    free(w->slots);
    w->slots = NULL;
    w->cap = w->used = 0;
}

void pkvmi_walk_free(pkvmi_walk_t *w) {
    pkvmi_walk_flush(w);
    *w = (pkvmi_walk_t) {0};
}
