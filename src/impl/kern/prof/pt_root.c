#include "kern/prof/pt.h"

#include <inttypes.h>
#include <stdio.h>

/* 16 x 2MiB = 32MiB above the anchor's 2MiB page. under KPTI the user PGD
 * maps entry text (and, without PCID, the rest of .text) but never rodata or
 * data, so the kernel PGD always scores higher once the probes reach past
 * .text. */
#define PROBES 16
#define PROBE_STEP (2ull << 20)

static int score(const kmem_t *mem, const pt_root_t *root, uint64_t anchor_va) {
    uint64_t pa;
    if (pt_translate(mem, root, anchor_va, &pa, NULL, NULL, 0) != 0) return 0;

    int n = 1;
    uint64_t base = anchor_va & ~(PROBE_STEP - 1);
    for (int i = 1; i <= PROBES; i++)
        if (pt_translate(mem, root, base + i * PROBE_STEP, &pa, NULL, NULL, 0) == 0) n++;
    return n;
}

int pt_root_from_cr3(const kmem_t *mem, uint64_t cr3, uint64_t cr4, uint64_t anchor_va, pt_root_t *root, char *err,
                     size_t err_len) {
    bool la57 = (cr4 & PT_CR4_LA57) != 0;
    pt_root_t kept = {.pgd = cr3 & PT_PA_MASK, .la57 = la57};
    int kept_score = score(mem, &kept, anchor_va);

    pt_root_t best = kept;
    int best_score = kept_score;
    if (kept.pgd & PT_CR3_PTI_USER) {
        pt_root_t cleared = {.pgd = kept.pgd & ~PT_CR3_PTI_USER, .la57 = la57};
        int cleared_score = score(mem, &cleared, anchor_va);
        if (cleared_score > best_score) {
            best = cleared;
            best_score = cleared_score;
        }
    }

    if (best_score == 0) {
        if (err) snprintf(err, err_len, "no root derived from CR3 0x%" PRIx64 " maps the anchor 0x%" PRIx64, cr3,
                          anchor_va);
        return -1;
    }

    *root = best;
    return 0;
}
