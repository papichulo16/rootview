#include "kern/prof/kfield.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAIL(...)                                                                                                      \
    do {                                                                                                               \
        if (err) snprintf(err, err_len, __VA_ARGS__);                                                                  \
        return -1;                                                                                                     \
    } while (0)

const char *kfield_kind_name(kfield_kind_t kind) {
    switch (kind) {
    case KF_U: return "u";
    case KF_S: return "s";
    case KF_PTR: return "ptr";
    case KF_BYTES: return "bytes";
    case KF_CSTR: return "cstr";
    case KF_ENUM: return "enum";
    }
    return "?";
}

/* the struct or union a type name means */
static uint32_t find_type(const btf_t *b, const char *type) {
    if (strncmp(type, "struct ", 7) == 0) return btf_find(b, type + 7, BTF_KIND_STRUCT);
    if (strncmp(type, "union ", 6) == 0) return btf_find(b, type + 6, BTF_KIND_UNION);
    uint32_t id = btf_find(b, type, BTF_KIND_STRUCT);
    if (!id) id = btf_find(b, type, BTF_KIND_UNION);
    if (!id) {
        btf_type_t t;
        id = btf_find(b, type, BTF_KIND_TYPEDEF);
        if (btf_type(b, btf_resolve(b, id), &t) != 0 || (t.kind != BTF_KIND_STRUCT && t.kind != BTF_KIND_UNION))
            return 0;
    }
    return id;
}

/* char comm[16] is a string; u8 digest[32] isn't */
static bool is_char(const btf_t *b, uint32_t id) {
    btf_type_t t;
    if (btf_type(b, btf_resolve(b, id), &t) != 0 || t.kind != BTF_KIND_INT || t.size != 1) return false;
    return t.int_char || strcmp(t.name, "char") == 0;
}

/* after btf_member fails: which segment broke, and was it a pointer */
static void explain(const btf_t *b, uint32_t id, const char *type, const char *path, char *err, size_t err_len) {
    char prefix[256];
    btf_member_t m;
    const char *seg = path;
    for (const char *dot; (dot = strchr(seg, '.')) != NULL; seg = dot + 1) {
        size_t n = (size_t) (dot - path);
        if (n >= sizeof(prefix)) break;
        memcpy(prefix, path, n);
        prefix[n] = '\0';
        if (btf_member(b, id, prefix, &m) != 0) break;
        btf_type_t t;
        if (btf_type(b, btf_resolve(b, m.type), &t) == 0 && t.kind == BTF_KIND_PTR) {
            btf_type_t p;
            btf_type(b, btf_pointee(b, m.type), &p);
            if (err) snprintf(err, err_len, "%s.%s is a pointer (to %s %s); read it and resolve the rest against "
                              "the pointee", type, prefix, btf_kind_name(p.kind), p.name[0] ? p.name : "<anon>");
            return;
        }
    }
    if (err) snprintf(err, err_len, "%s has no member %s", type, path);
}

int kfield_resolve(const btf_t *b, const char *type, const char *path, kfield_t *f, char *err, size_t err_len) {
    *f = (kfield_t) {0};
    uint32_t id = find_type(b, type);
    if (!id) FAIL("no struct or union %s in BTF", type);
    btf_member_t m;
    if (btf_member(b, id, path, &m) != 0) {
        explain(b, id, type, path, err, err_len);
        return -1;
    }

    btf_type_t t;
    uint32_t rid = btf_resolve(b, m.type);
    if (btf_type(b, rid, &t) != 0 || rid == 0) FAIL("%s.%s has no type", type, path);
    f->type = m.type;

    if (m.bit_size) {
        if (t.kind != BTF_KIND_INT && t.kind != BTF_KIND_ENUM && t.kind != BTF_KIND_ENUM64)
            FAIL("%s.%s is a %u-bit bitfield of %s", type, path, m.bit_size, btf_kind_name(t.kind));
        if (m.bit_size > 64) FAIL("%s.%s is a %u-bit bitfield", type, path, m.bit_size);
        f->offset = m.bit_off / 8;
        f->bit_off = (uint32_t) (m.bit_off % 8);
        f->bit_size = m.bit_size;
        f->size = (f->bit_off + m.bit_size + 7) / 8;
    } else {
        if (m.bit_off % 8) FAIL("%s.%s isn't byte-aligned (bit %" PRIu64 ")", type, path, m.bit_off);
        int64_t size = btf_size(b, m.type);
        if (size < 0 || size > UINT32_MAX) FAIL("%s.%s (%s) has no size", type, path, btf_kind_name(t.kind));
        f->offset = m.bit_off / 8;
        f->size = (uint32_t) size;
    }

    switch (t.kind) {
    case BTF_KIND_INT:
        if (!m.bit_size && t.size > 8) {
            f->kind = KF_BYTES; /* __int128 */
            break;
        }
        f->is_signed = t.int_signed;
        f->kind = t.int_signed ? KF_S : KF_U;
        break;
    case BTF_KIND_ENUM:
    case BTF_KIND_ENUM64:
        f->kind = KF_ENUM;
        f->is_signed = t.kflag;
        f->ref = rid;
        break;
    case BTF_KIND_PTR:
        f->kind = KF_PTR;
        f->ref = btf_pointee(b, rid);
        break;
    case BTF_KIND_ARRAY: f->kind = is_char(b, t.elem_type) ? KF_CSTR : KF_BYTES; break;
    default: f->kind = KF_BYTES; break;
    }
    return 0;
}

int kfield_decode(const btf_t *b, const kfield_t *f, const void *base, size_t base_len, kval_t *v, char *err,
                  size_t err_len) {
    *v = (kval_t) {.kind = f->kind, .ref = f->ref};
    if (f->offset > base_len || f->size > base_len - f->offset)
        FAIL("field at +0x%" PRIx64 " (%u bytes) is past the %zu bytes given", f->offset, f->size, base_len);
    const unsigned char *p = (const unsigned char *) base + f->offset;

    if (f->kind == KF_BYTES || f->kind == KF_CSTR) {
        v->bytes = malloc((size_t) f->size + 1);
        if (!v->bytes) FAIL("out of memory for %u bytes", f->size);
        memcpy(v->bytes, p, f->size);
        v->bytes[f->size] = '\0';
        v->len = f->kind == KF_CSTR ? strlen((const char *) v->bytes) : f->size;
        return 0;
    }

    /* little-endian, up to 9 bytes for a bitfield that straddles them */
    unsigned __int128 raw = 0;
    for (uint32_t i = f->size; i-- > 0;) raw = raw << 8 | p[i];
    uint32_t bits = f->bit_size ? f->bit_size : 8 * f->size;
    if (bits == 0 || bits > 64) FAIL("can't decode a %u-bit value", bits);
    uint64_t u = (uint64_t) (raw >> f->bit_off);
    if (bits < 64) u &= (1ull << bits) - 1;

    v->u = u;
    v->s = (int64_t) u;
    if (f->is_signed && bits < 64 && (u >> (bits - 1)) & 1) v->s = (int64_t) (u | ~((1ull << bits) - 1));
    if (f->kind == KF_ENUM) v->enum_name = btf_enum_name(b, f->ref, f->is_signed ? (uint64_t) v->s : u);
    return 0;
}

int kfield_read(const kprof_t *kp, const kfield_t *f, uint64_t base_va, kval_t *v, char *err, size_t err_len) {
    unsigned char small[16], *buf = small;
    if (f->size > sizeof(small) && !(buf = malloc(f->size))) {
        *v = (kval_t) {0};
        FAIL("out of memory for %u bytes", f->size);
    }
    int rc = kprof_read(kp, base_va + f->offset, buf, f->size, err, err_len);
    if (rc == 0) {
        /* decode against a base that starts f->offset bytes before buf */
        kfield_t at = *f;
        at.offset = 0;
        rc = kfield_decode(&kp->btf, &at, buf, f->size, v, err, err_len);
    } else {
        *v = (kval_t) {0};
    }
    if (buf != small) free(buf);
    return rc;
}

void kval_free(kval_t *v) {
    free(v->bytes);
    v->bytes = NULL;
}
