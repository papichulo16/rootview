#ifndef ROOTVIEW_PKVMI_WALK_H
#define ROOTVIEW_PKVMI_WALK_H

#include <stddef.h>
#include <stdint.h>

/* arm64 stage-1 EL1 translation done host-side: the phone only gives out
 * physical pages, so virtual reads walk TTBR1_EL1/TTBR0_EL1 here. 4KiB
 * granule only (what Android ships). table pages are cached until
 * pkvmi_walk_flush. */

typedef int (*pkvmi_walk_read_fn)(void *ctx, uint64_t pa, unsigned char *page, char *err, size_t err_len);

typedef struct {
    uint64_t pa;
    unsigned char *page; /* NULL is an empty slot */
} pkvmi_walk_slot_t;

typedef struct {
    uint64_t ttbr0, ttbr1, tcr;
    pkvmi_walk_read_fn read;
    void *ctx;

    pkvmi_walk_slot_t *slots;
    size_t cap, used;
} pkvmi_walk_t;

int pkvmi_walk_init(pkvmi_walk_t *w, uint64_t ttbr0, uint64_t ttbr1, uint64_t tcr, pkvmi_walk_read_fn read, void *ctx,
                    char *err, size_t err_len);

int pkvmi_walk_translate(pkvmi_walk_t *w, uint64_t va, uint64_t *pa, char *err, size_t err_len);

/* drops the cached table pages */
void pkvmi_walk_flush(pkvmi_walk_t *w);

void pkvmi_walk_free(pkvmi_walk_t *w);

#endif
