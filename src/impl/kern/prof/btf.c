#define _GNU_SOURCE /* memmem */
#include "kern/prof/btf.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* limits that keep a bad blob from walking off into the weeds. vmlinux BTF
 * is ~5-6MiB and ~150k types; type chains in it are a handful deep. */
#define MAX_BLOB (256u << 20)
#define MAX_DEPTH 32
#define PTR_SIZE 8
#define HDR_LEN 24
#define TYPE_LEN 12 /* name_off, info, size/type */

#define FAIL(...)                                                                                                      \
    do {                                                                                                               \
        if (err) snprintf(err, err_len, __VA_ARGS__);                                                                  \
        return false;                                                                                                  \
    } while (0)

static uint32_t u32_at(const unsigned char *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

/* ---- header ---- */

typedef struct {
    uint32_t hdr_len, type_off, type_len, str_off, str_len;
    uint64_t total; /* hdr_len + the end of the later section */
} hdr_t;

/* checks the header at p against avail bytes. the sections are relative to
 * the end of the header and mustn't overlap; a header longer than ours is
 * accepted only if the extra bytes are zero, as the kernel does. */
static bool check_hdr(const unsigned char *p, uint64_t avail, hdr_t *h, char *err, size_t err_len) {
    if (avail < HDR_LEN) FAIL("%" PRIu64 " bytes is too short for a BTF header", avail);
    uint16_t magic;
    memcpy(&magic, p, 2);
    if (magic != 0xeb9f) FAIL("bad magic 0x%04x", magic);
    if (p[2] != 1) FAIL("version %u, want 1", p[2]);
    if (p[3] != 0) FAIL("flags 0x%02x, want 0", p[3]);

    h->hdr_len = u32_at(p + 4);
    h->type_off = u32_at(p + 8);
    h->type_len = u32_at(p + 12);
    h->str_off = u32_at(p + 16);
    h->str_len = u32_at(p + 20);
    if (h->hdr_len < HDR_LEN || h->hdr_len > avail) FAIL("hdr_len %u out of range", h->hdr_len);
    for (uint32_t i = HDR_LEN; i < h->hdr_len; i++)
        if (p[i]) FAIL("hdr_len %u with non-zero bytes past the ones we know", h->hdr_len);
    if (h->type_off & 3) FAIL("type section at %u isn't 4-aligned", h->type_off);
    if (h->type_len % 4) FAIL("type section length %u isn't a multiple of 4", h->type_len);
    if (h->str_len == 0) FAIL("empty string section");

    uint64_t type_end = (uint64_t) h->type_off + h->type_len;
    uint64_t str_end = (uint64_t) h->str_off + h->str_len;
    if (h->type_off < str_end && h->str_off < type_end) FAIL("type and string sections overlap");
    h->total = h->hdr_len + (type_end > str_end ? type_end : str_end);
    if (h->total > avail) FAIL("sections end at %" PRIu64 ", past the %" PRIu64 " bytes there", h->total, avail);
    if (h->total > MAX_BLOB) FAIL("%" PRIu64 " bytes is past the %u limit", h->total, MAX_BLOB);
    return true;
}

/* ---- types ---- */

static btf_kind_t kind_of(uint32_t info) {
    return (btf_kind_t) ((info >> 24) & 0x1f);
}
static uint16_t vlen_of(uint32_t info) {
    return info & 0xffff;
}
static bool kflag_of(uint32_t info) {
    return info >> 31;
}

/* bytes after the 12-byte common part, or false for a kind we don't know */
static bool extra_len(btf_kind_t kind, uint16_t vlen, uint32_t *out) {
    switch (kind) {
    case BTF_KIND_INT: *out = 4; return true;
    case BTF_KIND_ARRAY: *out = 12; return true;
    case BTF_KIND_STRUCT:
    case BTF_KIND_UNION: *out = 12u * vlen; return true;
    case BTF_KIND_ENUM: *out = 8u * vlen; return true;
    case BTF_KIND_FUNC_PROTO: *out = 8u * vlen; return true;
    case BTF_KIND_VAR: *out = 4; return true;
    case BTF_KIND_DATASEC: *out = 12u * vlen; return true;
    case BTF_KIND_DECL_TAG: *out = 4; return true;
    case BTF_KIND_ENUM64: *out = 12u * vlen; return true;
    case BTF_KIND_PTR:
    case BTF_KIND_FWD:
    case BTF_KIND_TYPEDEF:
    case BTF_KIND_VOLATILE:
    case BTF_KIND_CONST:
    case BTF_KIND_RESTRICT:
    case BTF_KIND_FUNC:
    case BTF_KIND_FLOAT:
    case BTF_KIND_TYPE_TAG: *out = 0; return true;
    default: return false;
    }
}

static const unsigned char *type_ptr(const btf_t *b, uint32_t id) {
    return b->data + b->type_off[id];
}

/* checks every string offset and type reference in type id, once the type
 * count is known */
static bool check_refs(const btf_t *b, uint32_t id, char *err, size_t err_len) {
    const unsigned char *t = type_ptr(b, id), *x = t + TYPE_LEN;
    uint32_t info = u32_at(t + 4), st = u32_at(t + 8);
    btf_kind_t kind = kind_of(info);
    uint16_t vlen = vlen_of(info);

#define STR(off, what)                                                                                                 \
    if ((off) >= b->str_len) FAIL("type %u: %s name offset %u past the string section", id, what, off)
#define REF(ref, what)                                                                                                 \
    if ((ref) >= b->n) FAIL("type %u: %s refers to type %u of %u", id, what, ref, b->n)

    STR(u32_at(t), "its");
    switch (kind) {
    case BTF_KIND_INT: {
        uint32_t enc = u32_at(x), bits = enc & 0xff, off = (enc >> 16) & 0xff;
        if (st == 0 || st > 16 || (st & (st - 1))) FAIL("type %u: int of size %u", id, st);
        if (bits == 0 || bits > 128 || off + bits > 8 * st) FAIL("type %u: int bits %u at %u in %u bytes", id, bits, off,
                                                               st);
        break;
    }
    case BTF_KIND_PTR:
    case BTF_KIND_TYPEDEF:
    case BTF_KIND_VOLATILE:
    case BTF_KIND_CONST:
    case BTF_KIND_RESTRICT:
    case BTF_KIND_TYPE_TAG:
    case BTF_KIND_FUNC:
    case BTF_KIND_VAR:
    case BTF_KIND_DECL_TAG: REF(st, "it"); break;
    case BTF_KIND_ARRAY:
        REF(u32_at(x), "elem");
        REF(u32_at(x + 4), "index");
        break;
    case BTF_KIND_STRUCT:
    case BTF_KIND_UNION:
        for (uint16_t i = 0; i < vlen; i++) {
            STR(u32_at(x + 12u * i), "member");
            REF(u32_at(x + 12u * i + 4), "member");
        }
        break;
    case BTF_KIND_ENUM:
        for (uint16_t i = 0; i < vlen; i++) STR(u32_at(x + 8u * i), "enumerator");
        break;
    case BTF_KIND_ENUM64:
        for (uint16_t i = 0; i < vlen; i++) STR(u32_at(x + 12u * i), "enumerator");
        break;
    case BTF_KIND_FUNC_PROTO:
        REF(st, "return");
        for (uint16_t i = 0; i < vlen; i++) {
            STR(u32_at(x + 8u * i), "param");
            REF(u32_at(x + 8u * i + 4), "param");
        }
        break;
    case BTF_KIND_DATASEC:
        for (uint16_t i = 0; i < vlen; i++) REF(u32_at(x + 12u * i), "datasec var");
        break;
    default: break;
    }
#undef STR
#undef REF
    return true;
}

static uint32_t hash_name(const char *s) {
    uint32_t h = 2166136261u;
    for (; *s; s++) h = (h ^ (unsigned char) *s) * 16777619u;
    return h;
}

static const char *name_of(const btf_t *b, uint32_t id) {
    return id ? b->strs + u32_at(type_ptr(b, id)) : "";
}

static bool build_hash(btf_t *b) {
    size_t named = 0;
    for (uint32_t id = 1; id < b->n; id++) named += name_of(b, id)[0] != '\0';
    size_t cap = 16;
    while (cap < named * 2) cap <<= 1;
    b->hash = calloc(cap, sizeof(*b->hash));
    if (!b->hash) return false;
    b->hash_cap = cap;
    for (uint32_t id = 1; id < b->n; id++) {
        const char *name = name_of(b, id);
        if (!name[0]) continue;
        size_t h = hash_name(name) & (cap - 1);
        while (b->hash[h]) h = (h + 1) & (cap - 1);
        b->hash[h] = id;
    }
    return true;
}

/* takes ownership of data, which is freed on failure */
static bool parse_owned(unsigned char *data, size_t len, btf_t *b, char *err, size_t err_len) {
    *b = (btf_t) {.data = data, .len = len};
    hdr_t h;
    if (!check_hdr(data, len, &h, err, err_len)) goto fail;

    b->strs = (const char *) data + h.hdr_len + h.str_off;
    b->str_len = h.str_len;
    if (b->strs[0] != '\0' || b->strs[h.str_len - 1] != '\0') {
        if (err) snprintf(err, err_len, "string section doesn't start and end with a NUL");
        goto fail;
    }

    /* walk the types once for the offsets; void is id 0 and isn't in the section */
    size_t cap = 1024;
    b->type_off = malloc(cap * sizeof(*b->type_off));
    if (!b->type_off) goto oom;
    b->n = 1;
    b->type_off[0] = 0;
    uint64_t at = (uint64_t) h.hdr_len + h.type_off, end = at + h.type_len;
    while (at < end) {
        if (end - at < TYPE_LEN) {
            if (err) snprintf(err, err_len, "type %u is cut off by the end of the section", b->n);
            goto fail;
        }
        uint32_t info = u32_at(data + at + 4), extra;
        if (!extra_len(kind_of(info), vlen_of(info), &extra)) {
            if (err) snprintf(err, err_len, "type %u has unknown kind %u", b->n, kind_of(info));
            goto fail;
        }
        if (end - at - TYPE_LEN < extra) {
            if (err) snprintf(err, err_len, "type %u (%s) is cut off by the end of the section", b->n,
                              btf_kind_name(kind_of(info)));
            goto fail;
        }
        if (b->n == cap) {
            uint32_t *n = realloc(b->type_off, (cap *= 2) * sizeof(*n));
            if (!n) goto oom;
            b->type_off = n;
        }
        b->type_off[b->n++] = (uint32_t) at;
        at += TYPE_LEN + extra;
    }

    for (uint32_t id = 1; id < b->n; id++)
        if (!check_refs(b, id, err, err_len)) goto fail;
    if (!build_hash(b)) goto oom;
    return true;

oom:
    if (err) snprintf(err, err_len, "out of memory for %u types", b->n);
fail:
    btf_free(b);
    return false;
}

int btf_parse(const void *data, size_t len, btf_t *btf, char *err, size_t err_len) {
    *btf = (btf_t) {0};
    if (len > MAX_BLOB) {
        if (err) snprintf(err, err_len, "%zu bytes is past the %u limit", len, MAX_BLOB);
        return -1;
    }
    unsigned char *copy = malloc(len ? len : 1);
    if (!copy) {
        if (err) snprintf(err, err_len, "out of memory for %zu bytes", len);
        return -1;
    }
    memcpy(copy, data, len);
    return parse_owned(copy, len, btf, err, err_len) ? 0 : -1;
}

void btf_free(btf_t *btf) {
    free(btf->data);
    free(btf->type_off);
    free(btf->hash);
    *btf = (btf_t) {0};
}

/* ---- finding it in the image ---- */

/* the loaded run holding va, or NULL */
static const pt_run_t *run_at(const pt_image_t *img, uint64_t va) {
    for (size_t i = 0; i < img->n_runs; i++) {
        const pt_run_t *r = &img->runs[i];
        if (r->data && va >= r->va && va - r->va < r->len) return r;
    }
    return NULL;
}

/* the blob at va, at most max bytes of it: header check and full parse */
static bool try_blob(const pt_image_t *img, uint64_t va, uint64_t max, btf_t *out, char *err, size_t err_len) {
    const pt_run_t *r = run_at(img, va);
    if (!r) FAIL("0x%" PRIx64 " isn't in a loaded NX run", va);
    uint64_t room = r->len - (va - r->va);
    if (room > max) room = max;
    const unsigned char *p = r->data + (va - r->va);
    hdr_t h;
    if (!check_hdr(p, room, &h, err, err_len)) return false;
    if (btf_parse(p, h.total, out, err, err_len) != 0) return false;
    out->va = va;
    return true;
}

static bool locate(const pt_image_t *img, const ksym_table_t *tab, btf_t *out, char *err, size_t err_len) {
    char sym_err[256] = "";
    const ksym_t *start = tab ? ksym_by_name(tab, "__start_BTF") : NULL;
    const ksym_t *stop = tab ? ksym_by_name(tab, "__stop_BTF") : NULL;
    if (start && stop && stop->addr > start->addr) {
        char e[200];
        if (try_blob(img, start->addr, stop->addr - start->addr, out, e, sizeof(e))) {
            out->by_symbol = true;
            return true;
        }
        snprintf(sym_err, sizeof(sym_err), "__start_BTF 0x%" PRIx64 ": %s; ", start->addr, e);
    } else if (tab) {
        snprintf(sym_err, sizeof(sym_err), "no __start_BTF/__stop_BTF; ");
    }

    /* the scan keeps the largest blob that parses: a module's split BTF
     * refers to types it doesn't have, so it never parses on its own */
    btf_t best = {0};
    int hits = 0;
    char last[200] = "";
    for (size_t i = 0; i < img->n_runs; i++) {
        const pt_run_t *r = &img->runs[i];
        if (!r->nx || !r->data) continue;
        const unsigned char *p = r->data, *end = r->data + r->len;
        while ((p = memmem(p, (size_t) (end - p), BTF_MAGIC_BYTES, BTF_MAGIC_LEN)) != NULL) {
            uint64_t va = r->va + (uint64_t) (p - r->data);
            hits++;
            btf_t cand;
            char e[160];
            if (try_blob(img, va, UINT64_MAX, &cand, e, sizeof(e))) {
                if (cand.len > best.len) {
                    btf_free(&best);
                    best = cand;
                } else {
                    btf_free(&cand);
                }
            } else {
                snprintf(last, sizeof(last), "; 0x%" PRIx64 ": %s", va, e);
            }
            p++;
        }
    }
    if (best.data) {
        *out = best;
        return true;
    }
    FAIL("%sscan: %d header hit(s) in the NX runs, none parsed%s", sym_err, hits, last);
}

int btf_find_blob(const pt_image_t *img, const ksym_table_t *tab, uint64_t *va, uint64_t *len, bool *by_symbol,
                  char *err, size_t err_len) {
    btf_t b;
    if (!locate(img, tab, &b, err, err_len)) return -1;
    *va = b.va;
    *len = b.len;
    if (by_symbol) *by_symbol = b.by_symbol;
    btf_free(&b);
    return 0;
}

int btf_load(const pt_image_t *img, const ksym_table_t *tab, btf_t *btf, char *err, size_t err_len) {
    *btf = (btf_t) {0};
    return locate(img, tab, btf, err, err_len) ? 0 : -1;
}

/* ---- queries ---- */

int btf_type(const btf_t *b, uint32_t id, btf_type_t *out) {
    *out = (btf_type_t) {.id = id, .name = ""};
    if (id >= b->n) return -1;
    if (id == 0) return 0;

    const unsigned char *t = type_ptr(b, id), *x = t + TYPE_LEN;
    uint32_t info = u32_at(t + 4), st = u32_at(t + 8);
    out->kind = kind_of(info);
    out->name = name_of(b, id);
    out->kflag = kflag_of(info);
    out->vlen = vlen_of(info);
    switch (out->kind) {
    case BTF_KIND_INT: {
        uint32_t enc = u32_at(x);
        out->size = st;
        out->int_bits = enc & 0xff;
        out->int_off = (enc >> 16) & 0xff;
        out->int_signed = (enc >> 24) & 1;
        out->int_char = (enc >> 24) & 2;
        out->int_bool = (enc >> 24) & 4;
        break;
    }
    case BTF_KIND_ARRAY:
        out->elem_type = u32_at(x);
        out->index_type = u32_at(x + 4);
        out->nelems = u32_at(x + 8);
        break;
    case BTF_KIND_STRUCT:
    case BTF_KIND_UNION:
    case BTF_KIND_ENUM:
    case BTF_KIND_ENUM64:
    case BTF_KIND_FLOAT:
    case BTF_KIND_DATASEC: out->size = st; break;
    case BTF_KIND_PTR:
    case BTF_KIND_TYPEDEF:
    case BTF_KIND_VOLATILE:
    case BTF_KIND_CONST:
    case BTF_KIND_RESTRICT:
    case BTF_KIND_TYPE_TAG:
    case BTF_KIND_FUNC:
    case BTF_KIND_VAR:
    case BTF_KIND_DECL_TAG: out->type = st; break;
    default: break;
    }
    return 0;
}

uint32_t btf_find(const btf_t *b, const char *name, btf_kind_t kind) {
    if (!b->hash_cap || !name[0]) return 0;
    uint32_t def = 0, fwd = 0;
    for (size_t h = hash_name(name) & (b->hash_cap - 1); b->hash[h]; h = (h + 1) & (b->hash_cap - 1)) {
        uint32_t id = b->hash[h];
        if (strcmp(name_of(b, id), name) != 0) continue;
        btf_kind_t k = kind_of(u32_at(type_ptr(b, id) + 4));
        if (kind != BTF_KIND_ANY && k != kind) continue;
        uint32_t *slot = kind == BTF_KIND_ANY && k == BTF_KIND_FWD ? &fwd : &def;
        if (!*slot || id < *slot) *slot = id;
    }
    return def ? def : fwd;
}

static bool is_modifier(btf_kind_t k) {
    return k == BTF_KIND_TYPEDEF || k == BTF_KIND_CONST || k == BTF_KIND_VOLATILE || k == BTF_KIND_RESTRICT ||
           k == BTF_KIND_TYPE_TAG;
}

uint32_t btf_resolve(const btf_t *b, uint32_t id) {
    for (int i = 0; i < MAX_DEPTH; i++) {
        btf_type_t t;
        if (btf_type(b, id, &t) != 0) return 0;
        if (!is_modifier(t.kind)) return id;
        id = t.type;
    }
    return 0;
}

static int64_t size_depth(const btf_t *b, uint32_t id, int depth) {
    btf_type_t t;
    if (depth > MAX_DEPTH || btf_type(b, id, &t) != 0) return -1;
    switch (t.kind) {
    case BTF_KIND_INT:
    case BTF_KIND_STRUCT:
    case BTF_KIND_UNION:
    case BTF_KIND_ENUM:
    case BTF_KIND_ENUM64:
    case BTF_KIND_FLOAT:
    case BTF_KIND_DATASEC: return t.size;
    case BTF_KIND_PTR: return PTR_SIZE;
    case BTF_KIND_ARRAY: {
        int64_t es = size_depth(b, t.elem_type, depth + 1);
        if (es < 0 || (t.nelems && es > INT64_MAX / t.nelems)) return -1;
        return es * t.nelems;
    }
    case BTF_KIND_TYPEDEF:
    case BTF_KIND_CONST:
    case BTF_KIND_VOLATILE:
    case BTF_KIND_RESTRICT:
    case BTF_KIND_TYPE_TAG:
    case BTF_KIND_VAR: return size_depth(b, t.type, depth + 1);
    default: return -1;
    }
}

int64_t btf_size(const btf_t *b, uint32_t id) {
    return size_depth(b, id, 0);
}

/* name[0, nl) among id's members, anonymous members searched in place */
static int find_member(const btf_t *b, uint32_t id, const char *name, size_t nl, uint64_t base, btf_member_t *out,
                       int depth) {
    btf_type_t t;
    if (depth > MAX_DEPTH || btf_type(b, btf_resolve(b, id), &t) != 0) return -1;
    if (t.kind != BTF_KIND_STRUCT && t.kind != BTF_KIND_UNION) return -1;

    const unsigned char *x = type_ptr(b, t.id) + TYPE_LEN;
    for (uint16_t i = 0; i < t.vlen; i++, x += 12) {
        const char *mname = b->strs + u32_at(x);
        uint32_t mtype = u32_at(x + 4), off = u32_at(x + 8);
        uint64_t bit_off = t.kflag ? off & 0xffffff : off;
        uint32_t bit_size = t.kflag ? off >> 24 : 0;

        if (!mname[0]) {
            if (find_member(b, mtype, name, nl, base + bit_off, out, depth + 1) == 0) return 0;
            continue;
        }
        if (strlen(mname) != nl || memcmp(mname, name, nl) != 0) continue;

        /* without kflag, a bitfield is an INT member whose encoding is
         * narrower than its size */
        btf_type_t mt;
        if (!t.kflag && btf_type(b, btf_resolve(b, mtype), &mt) == 0 && mt.kind == BTF_KIND_INT &&
            (mt.int_off || mt.int_bits != 8 * mt.size)) {
            bit_off += mt.int_off;
            bit_size = mt.int_bits;
        }
        *out = (btf_member_t) {.name = mname, .type = mtype, .bit_off = base + bit_off, .bit_size = bit_size};
        return 0;
    }
    return -1;
}

int btf_member(const btf_t *b, uint32_t id, const char *path, btf_member_t *out) {
    uint64_t base = 0;
    for (;;) {
        const char *dot = strchr(path, '.');
        size_t nl = dot ? (size_t) (dot - path) : strlen(path);
        if (nl == 0 || find_member(b, id, path, nl, base, out, 0) != 0) return -1;
        if (!dot) return 0;
        if (out->bit_size) return -1; /* can't step into a bitfield */
        base = out->bit_off;
        id = out->type;
        path = dot + 1;
    }
}

uint32_t btf_pointee(const btf_t *b, uint32_t id) {
    btf_type_t t;
    if (btf_type(b, btf_resolve(b, id), &t) != 0 || t.kind != BTF_KIND_PTR) return 0;
    return btf_resolve(b, t.type);
}

const char *btf_enum_name(const btf_t *b, uint32_t id, uint64_t val) {
    btf_type_t t;
    if (btf_type(b, btf_resolve(b, id), &t) != 0) return NULL;
    const unsigned char *x = type_ptr(b, t.id) + TYPE_LEN;
    if (t.kind == BTF_KIND_ENUM) {
        for (uint16_t i = 0; i < t.vlen; i++, x += 8)
            if (u32_at(x + 4) == (uint32_t) val) return b->strs + u32_at(x);
    } else if (t.kind == BTF_KIND_ENUM64) {
        for (uint16_t i = 0; i < t.vlen; i++, x += 12)
            if ((u32_at(x + 4) | (uint64_t) u32_at(x + 8) << 32) == val) return b->strs + u32_at(x);
    }
    return NULL;
}

int btf_enum_value(const btf_t *b, uint32_t id, const char *name, int64_t *val) {
    btf_type_t t;
    if (btf_type(b, btf_resolve(b, id), &t) != 0) return -1;
    const unsigned char *x = type_ptr(b, t.id) + TYPE_LEN;
    if (t.kind == BTF_KIND_ENUM) {
        for (uint16_t i = 0; i < t.vlen; i++, x += 8) {
            if (strcmp(b->strs + u32_at(x), name) != 0) continue;
            uint32_t v = u32_at(x + 4);
            *val = t.kflag ? (int64_t) (int32_t) v : (int64_t) v;
            return 0;
        }
    } else if (t.kind == BTF_KIND_ENUM64) {
        for (uint16_t i = 0; i < t.vlen; i++, x += 12) {
            if (strcmp(b->strs + u32_at(x), name) != 0) continue;
            *val = (int64_t) (u32_at(x + 4) | (uint64_t) u32_at(x + 8) << 32);
            return 0;
        }
    }
    return -1;
}

const char *btf_kind_name(btf_kind_t kind) {
    static const char *const names[] = {
        "void",  "int",      "ptr",  "array", "struct",     "union", "enum",  "fwd",      "typedef",  "volatile",
        "const", "restrict", "func", "func_proto", "var", "datasec", "float", "decl_tag", "type_tag", "enum64",
    };
    return (unsigned) kind < sizeof(names) / sizeof(names[0]) ? names[kind] : "?";
}
