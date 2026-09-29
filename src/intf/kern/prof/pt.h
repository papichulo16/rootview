#ifndef ROOTVIEW_PT_H
#define ROOTVIEW_PT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "kern/prof/kmem.h"

/* physical-address bits 51:12 of a CR3 or page-table entry */
#define PT_PA_MASK 0x000ffffffffff000ull
/* KPTI keeps the kernel and user PGDs as an 8KiB pair; the user half is the
 * kernel one with this bit set */
#define PT_CR3_PTI_USER (1ull << 12)
#define PT_CR4_LA57 (1ull << 12)

typedef struct {
    uint64_t pgd; /* physical address of the top-level table */
    bool la57;    /* 5-level paging */
} pt_root_t;

/* turns a vcpu's CR3 into a root that maps the kernel image. the candidates
 * are CR3 masked to bits 51:12 as-is, and - when bit 12 is set - the same
 * with bit 12 cleared (the kernel PGD, if KPTI has the vcpu on its user
 * PGD). each candidate is scored by how much of the image it maps, probing
 * 2MiB steps upward from anchor_va (any kernel text address, e.g.
 * MSR_LSTAR). CR3 as-is wins ties, so a non-KPTI root on an odd page is
 * never swapped for the unrelated page below it. */
int pt_root_from_cr3(const kmem_t *mem, uint64_t cr3, uint64_t cr4, uint64_t anchor_va, pt_root_t *root, char *err,
                     size_t err_len);

/* walks root for va. page_size (optional) gets 4KiB, 2MiB or 1GiB. */
int pt_translate(const kmem_t *mem, const pt_root_t *root, uint64_t va, uint64_t *pa, uint64_t *page_size, char *err,
                 size_t err_len);

/* reads len bytes at va, re-translating at every page boundary */
int pt_read(const kmem_t *mem, const pt_root_t *root, uint64_t va, void *buf, size_t len, char *err, size_t err_len);

#endif
