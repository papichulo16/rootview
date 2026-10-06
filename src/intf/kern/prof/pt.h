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

/* the kernel image mapping: PDPT[510] of PML4[511], 0xffffffff80000000 up */
#define PT_KIMG_BASE 0xffffffff80000000ull

/* present pages that are virtually contiguous and share the effective NX bit
 * (set at any level of the walk). data holds the run's bytes once
 * pt_image_read_nx has loaded it, and is NULL otherwise. */
typedef struct {
    uint64_t va;
    uint64_t len;
    bool nx;
    unsigned char *data;
} pt_run_t;

typedef struct {
    uint64_t start, end; /* [start, end): the image's run of present PD entries */
    pt_run_t *runs;
    size_t n_runs;
} pt_image_t;

/* finds the image extent: the contiguous run of present PD entries in
 * PDPT[510], starting from the lowest one. head64 clears the entries below
 * _text, so start is _text rounded down to 2MiB. each PD entry is a 2MiB
 * page or a page table; the pages inside a table can be holes (freed init
 * memory), which split runs but not the extent. with nokaslr the modules
 * can follow the image in the same PD, which makes the extent longer but
 * doesn't move start. */
int pt_image(const kmem_t *mem, const pt_root_t *root, pt_image_t *img, char *err, size_t err_len);

/* reads every NX run into memory, for the kallsyms and banner scans */
int pt_image_read_nx(const kmem_t *mem, const pt_root_t *root, pt_image_t *img, char *err, size_t err_len);

/* points at len loaded bytes at va, or NULL unless one loaded run holds all of them */
const unsigned char *pt_image_ptr(const pt_image_t *img, uint64_t va, size_t len);

void pt_image_free(pt_image_t *img);

#endif
