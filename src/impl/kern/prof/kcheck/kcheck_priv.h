#ifndef ROOTVIEW_KCHECK_PRIV_H
#define ROOTVIEW_KCHECK_PRIV_H

#include <stdio.h>

#include "kern/prof/kcheck.h"

/* shared by the kcheck_*.c checks - not part of the public api */

#define FAIL(...)                                                                                                      \
    do {                                                                                                               \
        if (err) snprintf(err, err_len, __VA_ARGS__);                                                                  \
        return -1;                                                                                                     \
    } while (0)

/* where-a-target-points flags: any of them in a slot that should hold
 * kernel text at a symbol's start */
#define KCHECK_PLACE_BAD (KCHECK_OUT_OF_TEXT | KCHECK_IN_MODULE | KCHECK_NO_SYMBOL | KCHECK_MID_SYMBOL | KCHECK_NULL)

typedef struct {
    kwalk_t *w;
    const kscan_result_t *mods; /* NULL, or a KSCAN_MODULE result */
    uint64_t stext, etext;
    bool own; /* the window is ours to close */
} kcheck_ctx_t;

/* a fresh result for kind, the text bounds, and a window if the caller has none */
int kcheck_begin(kcheck_ctx_t *c, kwalk_t *w, const kscan_result_t *mods, kcheck_result_t *r, kcheck_kind_t kind,
                 char *err, size_t err_len);
/* closes what kcheck_begin opened; rc passes through unless the close fails.
 * frees r on failure. */
int kcheck_end(kcheck_ctx_t *c, kcheck_result_t *r, int rc, char *err, size_t err_len);

/* a zeroed entry of r's kind, or NULL out of memory */
kcheck_entry_t *kcheck_add(kcheck_result_t *r, uint32_t index, uint64_t slot);

/* fills target's flags, sym and owner from e->target */
void kcheck_place(const kcheck_ctx_t *c, kcheck_entry_t *e);

/* the first symbol above addr's own address, or 0 */
uint64_t kcheck_next_sym(const ksym_table_t *tab, uint64_t addr);

/* the vcpu's registers now, not as kprof_init saw them */
int kcheck_regs(const kcheck_ctx_t *c, kprof_regs_t *regs, char *err, size_t err_len);

#endif
