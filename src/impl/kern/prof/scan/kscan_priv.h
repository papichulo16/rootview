#ifndef ROOTVIEW_KSCAN_PRIV_H
#define ROOTVIEW_KSCAN_PRIV_H

#include <stdio.h>

#include "kern/prof/kfield.h"
#include "kern/prof/kscan.h"

/* shared by the kscan_*.c sources - not part of the public api */

#define FAIL(...)                                                                                                      \
    do {                                                                                                               \
        if (err) snprintf(err, err_len, __VA_ARGS__);                                                                  \
        return -1;                                                                                                     \
    } while (0)

/* a fresh result for kind */
int kscan_start(kscan_result_t *r, kscan_kind_t kind, char *err, size_t err_len);

/* the object at addr, added with only kind, addr and id -1 if it's new;
 * NULL when the table is full. *added says which. src's bit is set and its
 * count bumped. the pointer is good until the next kscan_add. */
kscan_object_t *kscan_add(kscan_result_t *r, kscan_kind_t kind, uint64_t addr, unsigned src, bool *added);

/* records src as failed with the reason in err */
void kscan_source_failed(kscan_result_t *r, unsigned src, const char *err);
void kscan_source_ran(kscan_result_t *r, unsigned src);

/* opens a window unless the caller has one; kscan_window_end closes only
 * what kscan_window_begin opened */
int kscan_window_begin(kwalk_t *w, bool *own, char *err, size_t err_len);
int kscan_window_end(kwalk_t *w, bool own, int rc, char *err, size_t err_len);

/* the field's offset, or -1 with err set */
int kscan_off(const kwalk_t *w, const char *type, const char *path, uint64_t *off, char *err, size_t err_len);

/* copies a printable NUL-terminated name, '?' for anything else */
void kscan_name(char *dst, size_t dst_len, const void *src, size_t src_len);

/* src failed: the reason, formatted, into source_err */
void kscan_source_failf(kscan_result_t *r, unsigned src, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

/* the symbol's address, or -1 with err set */
int kscan_sym(const kwalk_t *w, const char *name, uint64_t *addr, char *err, size_t err_len);

/* reads a u64 / u32 at va; 0 on success */
int kscan_u64(kwalk_t *w, uint64_t va, uint64_t *v, char *err, size_t err_len);
int kscan_u32(kwalk_t *w, uint64_t va, uint32_t *v, char *err, size_t err_len);

/* a set of addresses, for walking each shared structure once */
typedef struct {
    uint64_t *slots; /* open addressing, 0 is empty */
    size_t cap, n;
} kscan_set_t;

/* true if addr was new; false if it was there already or memory ran out */
bool kscan_set_add(kscan_set_t *s, uint64_t addr);
void kscan_set_free(kscan_set_t *s);

/* lists and trees under one object are capped here, well below the walker's own ceiling */
#define KSCAN_WALK_MAX 65536

#endif
