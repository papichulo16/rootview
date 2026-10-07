#ifndef ROOTVIEW_BTF_H
#define ROOTVIEW_BTF_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "kern/prof/ksym.h"
#include "kern/prof/pt.h"

/* the kernel's own BTF (.BTF, what /sys/kernel/btf/vmlinux serves), copied
 * out of the guest once and parsed host-side. the blob is guest data, so
 * every offset, string and type reference is checked at parse time and every
 * walk over the type graph is depth-limited. */

/* the header as the kernel emits it: magic 0xeb9f, version 1, flags 0,
 * hdr_len 24, little-endian */
#define BTF_MAGIC_BYTES "\x9f\xeb\x01\x00\x18\x00\x00\x00"
#define BTF_MAGIC_LEN 8

typedef enum {
    BTF_KIND_UNKN = 0, /* void (id 0); as a btf_find filter, any kind */
    BTF_KIND_INT = 1,
    BTF_KIND_PTR = 2,
    BTF_KIND_ARRAY = 3,
    BTF_KIND_STRUCT = 4,
    BTF_KIND_UNION = 5,
    BTF_KIND_ENUM = 6,
    BTF_KIND_FWD = 7,
    BTF_KIND_TYPEDEF = 8,
    BTF_KIND_VOLATILE = 9,
    BTF_KIND_CONST = 10,
    BTF_KIND_RESTRICT = 11,
    BTF_KIND_FUNC = 12,
    BTF_KIND_FUNC_PROTO = 13,
    BTF_KIND_VAR = 14,
    BTF_KIND_DATASEC = 15,
    BTF_KIND_FLOAT = 16,
    BTF_KIND_DECL_TAG = 17,
    BTF_KIND_TYPE_TAG = 18,
    BTF_KIND_ENUM64 = 19,
} btf_kind_t;

#define BTF_KIND_ANY BTF_KIND_UNKN

typedef struct {
    unsigned char *data; /* the copied blob */
    size_t len;
    const char *strs;
    uint32_t str_len;
    uint32_t *type_off; /* type_off[id] into data, ids 1..n-1 */
    uint32_t n;         /* type count, void included */
    uint32_t *hash;     /* named types by name: open addressing over ids, 0 is empty */
    size_t hash_cap;

    uint64_t va;    /* where the blob was found, 0 if parsed from a buffer */
    bool by_symbol; /* found through __start_BTF/__stop_BTF rather than the scan */
} btf_t;

/* one type, decoded. fields that don't apply to its kind are 0. */
typedef struct {
    uint32_t id;
    btf_kind_t kind;
    const char *name; /* "" if anonymous */
    bool kflag;       /* STRUCT/UNION: bitfield offsets; ENUM/ENUM64: signed; FWD: union */
    uint16_t vlen;
    uint32_t size; /* INT, STRUCT, UNION, ENUM, ENUM64, FLOAT, DATASEC */
    uint32_t type; /* PTR, TYPEDEF, VOLATILE, CONST, RESTRICT, TYPE_TAG, FUNC, VAR, DECL_TAG */

    /* INT only */
    uint8_t int_bits, int_off;
    bool int_signed, int_char, int_bool;

    /* ARRAY only */
    uint32_t elem_type, index_type, nelems;
} btf_type_t;

typedef struct {
    const char *name;
    uint32_t type;     /* as declared, modifiers and typedefs not stripped */
    uint64_t bit_off;  /* from the start of the type the lookup started at */
    uint32_t bit_size; /* bitfield width, 0 for a plain member */
} btf_member_t;

/* finds .BTF in the image: [__start_BTF, __stop_BTF) when tab (optional) has
 * both and a valid header sits there, otherwise a scan of the loaded NX runs
 * for BTF_MAGIC_BYTES, keeping the largest blob that parses. len is the
 * length the header gives. */
int btf_find_blob(const pt_image_t *img, const ksym_table_t *tab, uint64_t *va, uint64_t *len, bool *by_symbol,
                  char *err, size_t err_len);

/* btf_find_blob, then copies the blob out of the loaded runs and parses it */
int btf_load(const pt_image_t *img, const ksym_table_t *tab, btf_t *btf, char *err, size_t err_len);

/* parses a copy of data[0, len) */
int btf_parse(const void *data, size_t len, btf_t *btf, char *err, size_t err_len);

void btf_free(btf_t *btf);

/* the lowest id with that name and kind, or 0. BTF_KIND_ANY takes any kind
 * but prefers a definition over a FWD. */
uint32_t btf_find(const btf_t *btf, const char *name, btf_kind_t kind);

/* decodes id; -1 if it's out of range */
int btf_type(const btf_t *btf, uint32_t id, btf_type_t *out);

/* follows TYPEDEF, CONST, VOLATILE, RESTRICT and TYPE_TAG down to the
 * underlying type; 0 (void) if the chain is broken or too long */
uint32_t btf_resolve(const btf_t *btf, uint32_t id);

/* sizeof the type in bytes, modifiers resolved; pointers are 8 (x86_64)
 * and a flexible array is 0. -1 for void, FWD, FUNC and FUNC_PROTO. */
int64_t btf_size(const btf_t *btf, uint32_t id);

/* finds a member of a struct or union (id may be a typedef or modifier of
 * one). anonymous struct/union members are searched as if their members
 * were the parent's, which is how C sees them. path can be dotted
 * ("se.vruntime") to step into named struct members; offsets add up along
 * the way. returns -1 if any step isn't found. */
int btf_member(const btf_t *btf, uint32_t id, const char *path, btf_member_t *out);

/* what a pointer points at, modifiers resolved: 0 if id isn't a pointer
 * (after resolving) or points at void */
uint32_t btf_pointee(const btf_t *btf, uint32_t id);

/* the enumerator of an ENUM or ENUM64 with value val, or NULL. val is the
 * raw field as read: an ENUM compares its low 32 bits, so the result doesn't
 * depend on whether the caller sign-extended. */
const char *btf_enum_name(const btf_t *btf, uint32_t id, uint64_t val);

/* the inverse: the value of enumerator name, sign-extended if the enum is signed */
int btf_enum_value(const btf_t *btf, uint32_t id, const char *name, int64_t *val);

const char *btf_kind_name(btf_kind_t kind);

#endif
