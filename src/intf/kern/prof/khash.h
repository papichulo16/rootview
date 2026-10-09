#ifndef ROOTVIEW_KHASH_H
#define ROOTVIEW_KHASH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "kern/prof/kprof.h"

/* static integrity: the kernel's text and rodata, hashed a 4KiB page at a
 * time with SHA-256. the boundaries come from kallsyms - _stext/_etext and
 * __start_rodata/__end_rodata - and a region that doesn't start or end on a
 * page boundary has a short first or last page holding only its own bytes.
 *
 * per page rather than per section, because a clean kernel rewrites its own
 * text after boot: jump labels and static keys, ftrace's fentry nops,
 * alternatives, paravirt patching, and ro_after_init data (which sits in
 * the rodata range) settling once init finishes. a whole-section hash would
 * differ from any precomputed value and from itself across a static-key
 * flip; per page, the baseline is taken once the guest has settled and a
 * later diff names only the pages that moved.
 *
 * baseline drift is expected, and a changed page is evidence, not a
 * verdict. legitimate changes after the baseline include a static key
 * flipped late (a sysctl, a tracepoint enabled, a module loading and
 * enabling one), ftrace or a kprobe patching a function, and livepatch.
 * khash reports what changed, where, and which symbol the page starts in;
 * deciding whether that's a rootkit's inline hook or a tracer is left to
 * the analyst, and nothing here says clean or dirty from the hashes alone. */

#define KHASH_PAGE_SIZE 4096u
/* a region longer than this is rejected as absurd: 256MiB */
#define KHASH_MAX_REGION_PAGES (1u << 16)

typedef enum {
    KHASH_TEXT,   /* [_stext, _etext) */
    KHASH_RODATA, /* [__start_rodata, __end_rodata) */
} khash_region_id_t;
#define KHASH_REGIONS 2

typedef struct {
    uint64_t start, end; /* as kallsyms gives them */
    size_t first, n;     /* its pages in the vector */
} khash_region_t;

typedef struct {
    uint64_t va; /* the first byte hashed: page-aligned unless it's a region's first page */
    uint32_t len;
    bool ok; /* false: unmapped or unreadable when hashed, and hash is zeros */
    uint8_t hash[32];
} khash_page_t;

/* one allocation, header and pages together, so kprof_free can free the
 * baseline kprof_t holds without linking khash */
struct khash_baseline {
    khash_region_t region[KHASH_REGIONS];
    size_t n, unreadable;
    khash_page_t pages[];
};
typedef struct khash_baseline khash_baseline_t;

typedef enum {
    KHASH_MODIFIED,   /* readable both times, different hash */
    KHASH_UNREADABLE, /* readable at baseline, not now: unmapped, or a frame that can't be read */
    KHASH_READABLE,   /* unreadable at baseline, readable now */
} khash_change_kind_t;

typedef struct {
    khash_change_kind_t kind;
    khash_region_id_t region;
    size_t index; /* into the page vector */
    uint64_t va;
    uint32_t len;
    uint8_t before[32], after[32];
    const char *sym; /* the kallsyms symbol va falls in, or NULL; points into kp->ksym */
    uint64_t sym_off;
} khash_change_t;

typedef struct {
    bool baselined; /* there was no baseline: this call took it, and changes is empty */
    size_t pages, unreadable; /* this hashing pass */
    khash_change_t *changes;  /* in page order */
    size_t n;
} khash_diff_t;

const char *khash_region_name(khash_region_id_t region);
const char *khash_change_name(khash_change_kind_t kind);

/* the page-hash vector as the guest is now, with the guest paused for the
 * whole pass so every page comes from the same instant. *out is one
 * allocation; free() it. an unreadable page is recorded, not an error. */
int khash_snapshot(const kprof_t *kp, khash_baseline_t **out, char *err, size_t err_len);

/* takes a snapshot as kp->hash, replacing any baseline already there */
int khash_baseline(kprof_t *kp, char *err, size_t err_len);

/* hashes again and lists the pages that differ from kp->hash. the first
 * call after kprof_init, with no baseline yet, takes one instead and
 * reports baselined. the baseline is left as it was, so changes accumulate
 * until the caller calls khash_baseline to accept them. */
int khash_diff(kprof_t *kp, khash_diff_t *d, char *err, size_t err_len);
void khash_diff_free(khash_diff_t *d);

#endif
