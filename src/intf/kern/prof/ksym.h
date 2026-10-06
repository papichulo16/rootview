#ifndef ROOTVIEW_KSYM_H
#define ROOTVIEW_KSYM_H

#include <stddef.h>
#include <stdint.h>

#include "kern/prof/pt.h"

/* kallsyms decoder over the image's loaded NX runs (pt_image_read_nx). the
 * tables are found by content, not by symbol, since kallsyms is how symbols
 * get found in the first place. two switches pick the decoder, and a wrong
 * pick is rejected rather than decoded into garbage. */

/* where scripts/kallsyms puts the tables. every label is .balign 8 and the
 * markers are u32 in all three. */
typedef enum {
    KSYM_LAYOUT_V5,   /* <= 6.1: offsets, relative_base, num_syms, names, markers, token_table, token_index */
    KSYM_LAYOUT_V6_2, /* 6.2-6.3: as above with seqs_of_names between markers and token_table */
    KSYM_LAYOUT_V6_4, /* >= 6.4: num_syms, names, markers, token_table, token_index, offsets, relative_base, seqs */
} ksym_layout_t;

/* how kallsyms_offsets[i] turns into an address */
typedef enum {
    KSYM_ADDR_RELATIVE,   /* relative_base + (u32)off: >= 6.15, or no CONFIG_KALLSYMS_ABSOLUTE_PERCPU */
    KSYM_ADDR_ABS_PERCPU, /* off >= 0 ? off : relative_base - 1 - off: x86_64 SMP <= 6.14 */
} ksym_addr_t;

typedef struct {
    ksym_layout_t layout;
    ksym_addr_t addr;
} ksym_cfg_t;

typedef struct {
    uint64_t addr;
    const char *name;
    char type;
} ksym_t;

typedef struct {
    ksym_t *syms; /* kallsyms order, which is sorted by address */
    size_t n;
    char *strs;
    uint32_t *hash; /* open addressing over syms, index + 1, 0 is empty */
    size_t hash_cap;

    /* where the tables were found */
    uint64_t va_num_syms, va_names, va_markers, va_token_table, va_token_index, va_offsets, va_seqs;
    uint64_t relative_base;
} ksym_table_t;

const char *ksym_layout_name(ksym_layout_t layout);
const char *ksym_addr_name(ksym_addr_t addr);

/* the switches for the kernel that printed banner ("Linux version X.Y..."):
 * the version picks the layout and the cutoff for absolute percpu, and the
 * banner's " SMP " says whether absolute percpu was possible at all */
int ksym_cfg_from_banner(const char *banner, ksym_cfg_t *cfg, char *err, size_t err_len);

/* raw scan of the loaded runs for "Linux version ". fills up to max hit
 * addresses and returns how many there were in total. */
size_t ksym_banner_scan(const pt_image_t *img, uint64_t *hits, size_t max);

/* finds and decodes the tables. on top of the structural checks, the
 * addresses must be non-decreasing and _text must decode to img->start. */
int ksym_load(const pt_image_t *img, const ksym_cfg_t *cfg, ksym_table_t *tab, char *err, size_t err_len);

/* resolves linux_banner, reads it out of the loaded runs and checks it
 * against the raw scan: it must be one of the hits. banner (optional) gets
 * the string, NUL-terminated and cut to banner_len. */
int ksym_check_banner(const pt_image_t *img, const ksym_table_t *tab, char *banner, size_t banner_len, char *err,
                      size_t err_len);

/* first symbol with that name, in address order */
const ksym_t *ksym_by_name(const ksym_table_t *tab, const char *name);

/* last symbol at or below addr (the last of several at the same address);
 * off (optional) gets addr minus its address */
const ksym_t *ksym_by_addr(const ksym_table_t *tab, uint64_t addr, uint64_t *off);

void ksym_free(ksym_table_t *tab);

#endif
