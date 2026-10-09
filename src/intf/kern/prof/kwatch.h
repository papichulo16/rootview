#ifndef ROOTVIEW_KWATCH_H
#define ROOTVIEW_KWATCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "kern/prof/kprof.h"

/* the tables worth write-protecting, as guest frames, and what a write to
 * one of those frames did. kcheck finds a table already patched when it
 * polls; an EPT write hook on these frames (hook_mem_add_gfn) catches the
 * moment of patching, with the instruction that did it. both are needed:
 * the hook sees nothing that happened before it was attached, and the
 * poll sees nothing about who did it.
 *
 * this half is offline - frames come from kprof's canonical root, and a
 * write is decoded from its gpa and the bytes before and after - so it's
 * tested against dumps. the hook half lives in kvmi/hook and bind. */

typedef enum {
    KWATCH_SYSCALL, /* sys_call_table: 8-byte entries */
    KWATCH_IDT,     /* the IDT at IDTR: 16-byte gates */
} kwatch_table_t;
#define KWATCH_TABLES 2

#define KWATCH_MAX_PAGES 4

/* the bytes a write capture holds: a 16-byte-aligned window around the
 * written address, which covers one gate or two syscall entries */
#define KWATCH_WINDOW 16

typedef struct {
    kwatch_table_t table;
    uint64_t va;  /* the table */
    uint64_t len; /* bytes of it that are slots: sys_call_table up to its first NULL, the IDT's 4096 */
    uint32_t slot_size;
    /* every page the table touches, padding included, and its frame */
    uint64_t page_va[KWATCH_MAX_PAGES];
    uint64_t gfn[KWATCH_MAX_PAGES];
    size_t npages;
} kwatch_region_t;

typedef struct {
    kwatch_table_t table;
    int64_t slot;     /* syscall nr or vector; -1 when the write landed on the frame but outside the table */
    uint64_t va;      /* the written address, through the table's own mapping */
    uint64_t old_target, new_target; /* the slot's pointer or handler, before and after */
    const char *old_sym, *new_sym;   /* kallsyms, or NULL outside the image; point into kp->ksym */
    uint64_t old_off, new_off;
    uint64_t rip;
    const char *rip_sym;
    uint64_t rip_off;
} kwatch_write_t;

const char *kwatch_table_name(kwatch_table_t table);

/* both regions. idtr_base is IDTR as read now (a vcpu's, so the table
 * that vcpu actually uses). a table's pages that don't translate fail the
 * call. */
int kwatch_regions(const kprof_t *kp, uint64_t idtr_base, kwatch_region_t out[KWATCH_TABLES], char *err,
                   size_t err_len);

/* the window a write to gpa is captured in */
static inline uint64_t kwatch_window(uint64_t gpa) {
    return gpa & ~(uint64_t) (KWATCH_WINDOW - 1);
}

/* what a write to gpa did, from the window's bytes before and after (as
 * kwatch_window places them) and the instruction that wrote. -1 when gpa
 * isn't on one of the region's frames. a write touching two slots is
 * decoded for the slot gpa is in. */
int kwatch_decode(const kprof_t *kp, const kwatch_region_t *r, uint64_t gpa, const uint8_t before[KWATCH_WINDOW],
                  const uint8_t after[KWATCH_WINDOW], uint64_t rip, kwatch_write_t *out, char *err, size_t err_len);

#endif
