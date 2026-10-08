#ifndef ROOTVIEW_KFIELD_H
#define ROOTVIEW_KFIELD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "kern/prof/btf.h"
#include "kern/prof/kprof.h"

/* fields of kernel structs by name. kfield_resolve is pure BTF work - no
 * guest reads - so a caller resolves each (type, path) once and keeps the
 * kfield_t. kfield_read reads one field; for many fields of one struct, read
 * the struct once with kprof_read and kfield_decode each field out of the
 * buffer. pointers are never followed: a PTR value carries its pointee's
 * type id, and the caller reads the next struct itself. */

typedef enum {
    KF_U,     /* unsigned integer, bool, unsigned bitfield */
    KF_S,     /* signed integer or bitfield */
    KF_PTR,   /* pointer: the address, plus the pointee type */
    KF_BYTES, /* struct, union, non-char array, anything else with a size */
    KF_CSTR,  /* char array, cut at the first NUL */
    KF_ENUM,  /* enum: the value, plus the enumerator's name */
} kfield_kind_t;

typedef struct {
    uint32_t type;   /* the member's declared type */
    uint64_t offset; /* first byte read, from the start of the struct */
    uint32_t size;   /* bytes read; a flexible array is 0 */
    /* bitfields: the value is bits [bit_off, bit_off + bit_size) of the
     * size bytes read as little-endian. bit_size is 0 otherwise. */
    uint32_t bit_off, bit_size;
    kfield_kind_t kind;
    bool is_signed; /* KF_S, and signed enums */
    uint32_t ref;   /* KF_PTR: pointee, modifiers resolved, 0 for void; KF_ENUM: the enum */
} kfield_t;

typedef struct {
    kfield_kind_t kind;
    uint64_t u;            /* U, PTR, ENUM: the value zero-extended; S: its bits */
    int64_t s;             /* S and signed ENUM: sign-extended; otherwise == u */
    uint32_t ref;          /* the field's ref */
    const char *enum_name; /* ENUM: the matching enumerator (in the btf), NULL if none */
    unsigned char *bytes;  /* BYTES, CSTR: a copy, NUL-terminated past len; kval_free */
    size_t len;            /* BYTES: size; CSTR: up to the first NUL */
} kval_t;

const char *kfield_kind_name(kfield_kind_t kind);

/* type is a struct or union name ("task_struct", or "struct task_struct"),
 * or a typedef of one. path is dotted through embedded structs, with
 * anonymous members flattened: "se.vruntime". stepping through a pointer
 * ("mm.pgd") is an error that says so. */
int kfield_resolve(const btf_t *btf, const char *type, const char *path, kfield_t *f, char *err, size_t err_len);

/* decodes f out of base, which holds base_len bytes from the start of the struct */
int kfield_decode(const btf_t *btf, const kfield_t *f, const void *base, size_t base_len, kval_t *v, char *err,
                  size_t err_len);

/* reads f of the struct at base_va and decodes it */
int kfield_read(const kprof_t *kp, const kfield_t *f, uint64_t base_va, kval_t *v, char *err, size_t err_len);

void kval_free(kval_t *v);

#endif
