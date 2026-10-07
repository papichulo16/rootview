/* M3 tests: BTF. a synthetic blob with every kind (always run) and corrupted
 * copies of it; each fixture's vmlinux.btf.gz parsed and checked field by
 * field against its pahole.txt (always run, both are committed); and for
 * each fixture with a mem.raw, .BTF found in the dump by symbol and by scan
 * and compared byte for byte with /sys/kernel/btf/vmlinux. */
#include <inttypes.h>

#include "fixture.h"
#include "kern/prof/btf.h"
#include "kern/prof/ksym.h"

/* ---- synthetic blob builder ---- */

typedef struct {
    unsigned char types[4096];
    size_t tl;
    uint32_t at[64]; /* at[id]: the type's offset in types */
    char strs[1024];
    size_t sl;
    uint32_t n; /* last id */
} syn_t;

static void s_u32(syn_t *s, uint32_t v) {
    memcpy(s->types + s->tl, &v, 4);
    s->tl += 4;
}

static uint32_t s_str(syn_t *s, const char *str) {
    if (!str || !*str) return 0;
    uint32_t off = (uint32_t) s->sl;
    memcpy(s->strs + s->sl, str, strlen(str) + 1);
    s->sl += strlen(str) + 1;
    return off;
}

/* the common part of a type; the caller appends what the kind needs */
static uint32_t s_type(syn_t *s, const char *name, btf_kind_t kind, int kflag, uint16_t vlen, uint32_t size_type) {
    s->at[++s->n] = (uint32_t) s->tl;
    s_u32(s, s_str(s, name));
    s_u32(s, (uint32_t) kflag << 31 | (uint32_t) kind << 24 | vlen);
    s_u32(s, size_type);
    return s->n;
}

static void s_member(syn_t *s, const char *name, uint32_t type, uint32_t off) {
    s_u32(s, s_str(s, name));
    s_u32(s, type);
    s_u32(s, off);
}

static uint32_t s_int(syn_t *s, const char *name, uint32_t size, uint32_t enc, uint32_t off, uint32_t bits) {
    uint32_t id = s_type(s, name, BTF_KIND_INT, 0, 0, size);
    s_u32(s, enc << 24 | off << 16 | bits);
    return id;
}

static uint32_t s_array(syn_t *s, uint32_t elem, uint32_t index, uint32_t nelems) {
    uint32_t id = s_type(s, NULL, BTF_KIND_ARRAY, 0, 0, 0);
    s_u32(s, elem);
    s_u32(s, index);
    s_u32(s, nelems);
    return id;
}

#define HDR 24

/* header + types + strings, the way the kernel lays them out */
static unsigned char *s_blob(const syn_t *s, size_t *len) {
    *len = HDR + s->tl + s->sl;
    unsigned char *b = calloc(1, *len);
    uint16_t magic = 0xeb9f;
    uint32_t h[5] = {HDR, 0, (uint32_t) s->tl, (uint32_t) s->tl, (uint32_t) s->sl};
    memcpy(b, &magic, 2);
    b[2] = 1;
    memcpy(b + 4, h, sizeof(h));
    memcpy(b + HDR, s->types, s->tl);
    memcpy(b + HDR + s->tl, s->strs, s->sl);
    return b;
}

typedef struct {
    uint32_t t_int, t_uint, t_char, t_long, t_voidp, inner, inner_t, cv, ptr_cv, restrict_p, char16, flex, anon_u,
        empty, anon_flex, color, sgn, big, fwd_outer, fwd_s, ptr_fwd, outer, bf_x, bf_y, oldbf, proto, func, var,
        datasec, dbl, decl_tag, type_tag, ptr_tag, loop_td, loop_s;
} ids_t;

/* C-ish:
 *   struct inner { int a; int b; };  typedef struct inner inner_t;
 *   enum color { RED, GREEN, BLUE = 0xffffffff };  enum sgn { NEG = -1, POS = 5 } (signed);
 *   enum64 big { ONE = 1, HUGE = 0x123456789 };
 *   struct outer {                              (kflag)        bits
 *       unsigned int flags:3;                                     0
 *       unsigned int mode:5;                                      3
 *       char name[16];                                           32
 *       inner_t in;                                             160
 *       union { int u1; long u2; };                             256
 *       const volatile inner_t *restrict p;                     320
 *       struct fwd_s *f;                                        384
 *       enum color c;                                           448
 *       struct { struct {} __empty; long tail[]; };             512
 *   };                                                       64 bytes
 *   struct oldbf { x:3; y:4 } as kflag-0 INT encodings
 * plus FUNC_PROTO, FUNC, VAR, DATASEC, FLOAT, DECL_TAG, TYPE_TAG, a FWD
 * named like a struct, a typedef cycle and a struct that contains itself
 * anonymously. */
static unsigned char *build_synthetic(size_t *len, ids_t *id, syn_t *s) {
    memset(s, 0, sizeof(*s));
    s->sl = 1; /* strs[0] is "" */

    id->fwd_outer = s_type(s, "outer", BTF_KIND_FWD, 0, 0, 0); /* lower id than the definition */
    id->t_int = s_int(s, "int", 4, 1, 0, 32);
    id->t_uint = s_int(s, "unsigned int", 4, 0, 0, 32);
    id->t_char = s_int(s, "char", 1, 1 | 2, 0, 8);
    id->t_long = s_int(s, "long", 8, 1, 0, 64);
    id->t_voidp = s_type(s, NULL, BTF_KIND_PTR, 0, 0, 0);

    id->inner = s_type(s, "inner", BTF_KIND_STRUCT, 0, 2, 8);
    s_member(s, "a", id->t_int, 0);
    s_member(s, "b", id->t_int, 32);
    id->inner_t = s_type(s, "inner_t", BTF_KIND_TYPEDEF, 0, 0, id->inner);
    uint32_t c = s_type(s, NULL, BTF_KIND_CONST, 0, 0, id->inner_t);
    id->cv = s_type(s, NULL, BTF_KIND_VOLATILE, 0, 0, c);
    id->ptr_cv = s_type(s, NULL, BTF_KIND_PTR, 0, 0, id->cv);
    id->restrict_p = s_type(s, NULL, BTF_KIND_RESTRICT, 0, 0, id->ptr_cv);

    id->char16 = s_array(s, id->t_char, id->t_int, 16);
    id->flex = s_array(s, id->t_long, id->t_int, 0);

    id->anon_u = s_type(s, NULL, BTF_KIND_UNION, 0, 2, 8);
    s_member(s, "u1", id->t_int, 0);
    s_member(s, "u2", id->t_long, 0);
    id->empty = s_type(s, NULL, BTF_KIND_STRUCT, 0, 0, 0);
    id->anon_flex = s_type(s, NULL, BTF_KIND_STRUCT, 0, 2, 0);
    s_member(s, "__empty", id->empty, 0);
    s_member(s, "tail", id->flex, 0);

    id->color = s_type(s, "color", BTF_KIND_ENUM, 0, 3, 4);
    s_u32(s, s_str(s, "RED")), s_u32(s, 0);
    s_u32(s, s_str(s, "GREEN")), s_u32(s, 1);
    s_u32(s, s_str(s, "BLUE")), s_u32(s, 0xffffffffu);
    id->sgn = s_type(s, "sgn", BTF_KIND_ENUM, 1, 2, 4);
    s_u32(s, s_str(s, "NEG")), s_u32(s, (uint32_t) -1);
    s_u32(s, s_str(s, "POS")), s_u32(s, 5);
    id->big = s_type(s, "big", BTF_KIND_ENUM64, 0, 2, 8);
    s_u32(s, s_str(s, "ONE")), s_u32(s, 1), s_u32(s, 0);
    s_u32(s, s_str(s, "HUGE")), s_u32(s, 0x23456789), s_u32(s, 0x1);

    id->fwd_s = s_type(s, "fwd_s", BTF_KIND_FWD, 0, 0, 0);
    id->ptr_fwd = s_type(s, NULL, BTF_KIND_PTR, 0, 0, id->fwd_s);

    id->outer = s_type(s, "outer", BTF_KIND_STRUCT, 1, 9, 64);
    s_member(s, "flags", id->t_uint, 3u << 24 | 0);
    s_member(s, "mode", id->t_uint, 5u << 24 | 3);
    s_member(s, "name", id->char16, 32);
    s_member(s, "in", id->inner_t, 160);
    s_member(s, NULL, id->anon_u, 256);
    s_member(s, "p", id->restrict_p, 320);
    s_member(s, "f", id->ptr_fwd, 384);
    s_member(s, "c", id->color, 448);
    s_member(s, NULL, id->anon_flex, 512);

    id->bf_x = s_int(s, "unsigned int", 4, 0, 0, 3);
    id->bf_y = s_int(s, "unsigned int", 4, 0, 3, 4);
    id->oldbf = s_type(s, "oldbf", BTF_KIND_STRUCT, 0, 2, 4);
    s_member(s, "x", id->bf_x, 0);
    s_member(s, "y", id->bf_y, 0);

    id->proto = s_type(s, NULL, BTF_KIND_FUNC_PROTO, 0, 1, id->t_int);
    s_u32(s, s_str(s, "arg")), s_u32(s, id->t_long);
    id->func = s_type(s, "fn", BTF_KIND_FUNC, 0, 1, id->proto);
    id->var = s_type(s, "gv", BTF_KIND_VAR, 0, 0, id->t_int);
    s_u32(s, 1);
    id->datasec = s_type(s, ".data", BTF_KIND_DATASEC, 0, 1, 4);
    s_u32(s, id->var), s_u32(s, 0), s_u32(s, 4);
    id->dbl = s_type(s, "double", BTF_KIND_FLOAT, 0, 0, 8);
    id->decl_tag = s_type(s, "tag", BTF_KIND_DECL_TAG, 0, 0, id->outer);
    s_u32(s, (uint32_t) -1);
    id->type_tag = s_type(s, "user", BTF_KIND_TYPE_TAG, 0, 0, id->outer);
    id->ptr_tag = s_type(s, NULL, BTF_KIND_PTR, 0, 0, id->type_tag);

    /* hostile shapes: typedef loop_td loop_td; struct loop_s { struct loop_s; } */
    id->loop_td = s_type(s, "loop_td", BTF_KIND_TYPEDEF, 0, 0, s->n + 1);
    id->loop_s = s_type(s, "loop_s", BTF_KIND_STRUCT, 0, 1, 4);
    s_member(s, NULL, s->n, 0);

    return s_blob(s, len);
}

static void check_member(const btf_t *b, uint32_t id, const char *path, uint64_t bit_off, uint32_t bit_size,
                         uint32_t type) {
    btf_member_t m;
    int rc = btf_member(b, id, path, &m);
    CHECK(rc == 0, "member %s not found", path);
    if (rc != 0) return;
    CHECK(m.bit_off == bit_off && m.bit_size == bit_size && (!type || m.type == type),
          "%s: bit_off %" PRIu64 " size %u type %u, want %" PRIu64 " %u %u", path, m.bit_off, m.bit_size, m.type,
          bit_off, bit_size, type);
}

static void test_synthetic(void) {
    printf("synthetic blob, every kind\n");
    syn_t s;
    ids_t id;
    size_t len;
    unsigned char *blob = build_synthetic(&len, &id, &s);
    btf_t b;
    char err[256];
    if (btf_parse(blob, len, &b, err, sizeof(err)) != 0) {
        CHECK(0, "parse: %s", err);
        free(blob);
        return;
    }
    CHECK(b.n == s.n + 1, "%u types, want %u", b.n, s.n + 1);

    /* find */
    CHECK(btf_find(&b, "outer", BTF_KIND_STRUCT) == id.outer, "find outer struct");
    CHECK(btf_find(&b, "outer", BTF_KIND_ANY) == id.outer, "ANY prefers the definition over the lower-id FWD");
    CHECK(btf_find(&b, "outer", BTF_KIND_FWD) == id.fwd_outer, "find outer fwd");
    CHECK(btf_find(&b, "fwd_s", BTF_KIND_ANY) == id.fwd_s, "ANY falls back to a FWD");
    CHECK(btf_find(&b, "unsigned int", BTF_KIND_INT) == id.t_uint, "lowest id of several");
    CHECK(btf_find(&b, "nope", BTF_KIND_ANY) == 0 && btf_find(&b, "", BTF_KIND_ANY) == 0, "missing names");
    CHECK(btf_find(&b, "inner", BTF_KIND_UNION) == 0, "kind filter");

    /* decode */
    btf_type_t t;
    CHECK(btf_type(&b, id.t_char, &t) == 0 && t.kind == BTF_KIND_INT && t.int_char && t.int_signed && t.int_bits == 8,
          "char encoding");
    CHECK(btf_type(&b, id.char16, &t) == 0 && t.elem_type == id.t_char && t.nelems == 16, "array");
    CHECK(btf_type(&b, id.sgn, &t) == 0 && t.kflag && t.vlen == 2, "signed enum");
    CHECK(btf_type(&b, b.n, &t) != 0, "id past the end");
    CHECK(btf_type(&b, 0, &t) == 0 && t.kind == BTF_KIND_UNKN && !t.name[0], "void");

    /* resolve and size */
    CHECK(btf_resolve(&b, id.cv) == id.inner, "const volatile typedef resolves to the struct");
    CHECK(btf_resolve(&b, id.restrict_p) == id.ptr_cv, "restrict resolves to the pointer");
    CHECK(btf_resolve(&b, id.loop_td) == 0, "typedef cycle resolves to void");
    static const struct {
        size_t off;
        int64_t size;
    } sizes[] = {
        {offsetof(ids_t, outer), 64},  {offsetof(ids_t, inner_t), 8},  {offsetof(ids_t, cv), 8},
        {offsetof(ids_t, ptr_cv), 8},  {offsetof(ids_t, char16), 16},  {offsetof(ids_t, flex), 0},
        {offsetof(ids_t, color), 4},   {offsetof(ids_t, big), 8},      {offsetof(ids_t, dbl), 8},
        {offsetof(ids_t, anon_flex), 0}, {offsetof(ids_t, var), 4},    {offsetof(ids_t, type_tag), 64},
        {offsetof(ids_t, fwd_s), -1},  {offsetof(ids_t, proto), -1},   {offsetof(ids_t, func), -1},
        {offsetof(ids_t, loop_td), -1},
    };
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        uint32_t tid;
        memcpy(&tid, (char *) &id + sizes[i].off, 4);
        CHECK(btf_size(&b, tid) == sizes[i].size, "size of %u (%s): %" PRId64 ", want %" PRId64, tid,
              btf_type(&b, tid, &t) == 0 ? btf_kind_name(t.kind) : "?", btf_size(&b, tid), sizes[i].size);
    }
    CHECK(btf_size(&b, 0) == -1, "size of void");

    /* members: bitfields, flattened anonymous ones, dotted paths */
    check_member(&b, id.outer, "flags", 0, 3, id.t_uint);
    check_member(&b, id.outer, "mode", 3, 5, id.t_uint);
    check_member(&b, id.outer, "name", 32, 0, id.char16);
    check_member(&b, id.outer, "in", 160, 0, id.inner_t);
    check_member(&b, id.outer, "in.b", 192, 0, id.t_int);
    check_member(&b, id.outer, "u1", 256, 0, id.t_int);
    check_member(&b, id.outer, "u2", 256, 0, id.t_long);
    check_member(&b, id.outer, "p", 320, 0, id.restrict_p);
    check_member(&b, id.outer, "c", 448, 0, id.color);
    check_member(&b, id.outer, "tail", 512, 0, id.flex);
    check_member(&b, id.outer, "__empty", 512, 0, id.empty);
    check_member(&b, id.type_tag, "in.a", 160, 0, id.t_int); /* lookup through a type tag */
    check_member(&b, id.oldbf, "x", 0, 3, id.bf_x);
    check_member(&b, id.oldbf, "y", 3, 4, id.bf_y);
    btf_member_t m;
    CHECK(btf_member(&b, id.outer, "nope", &m) != 0, "missing member");
    CHECK(btf_member(&b, id.outer, "in.c", &m) != 0, "missing nested member");
    CHECK(btf_member(&b, id.outer, "flags.x", &m) != 0, "stepping into a bitfield");
    CHECK(btf_member(&b, id.outer, "p.a", &m) != 0, "stepping through a pointer");
    CHECK(btf_member(&b, id.outer, "in.", &m) != 0 && btf_member(&b, id.outer, "", &m) != 0, "empty path segment");
    CHECK(btf_member(&b, id.t_int, "a", &m) != 0, "member of an int");
    CHECK(btf_member(&b, id.loop_s, "x", &m) != 0, "self-containing anonymous member terminates");

    /* pointee */
    CHECK(btf_pointee(&b, id.restrict_p) == id.inner, "restrict ptr to const volatile typedef");
    CHECK(btf_pointee(&b, id.ptr_fwd) == id.fwd_s, "ptr to fwd");
    CHECK(btf_pointee(&b, id.ptr_tag) == id.outer, "ptr to type tag");
    CHECK(btf_pointee(&b, id.t_voidp) == 0, "void *");
    CHECK(btf_pointee(&b, id.outer) == 0, "not a pointer");

    /* enums */
    const char *e;
    CHECK((e = btf_enum_name(&b, id.color, 1)) && !strcmp(e, "GREEN"), "color 1");
    CHECK((e = btf_enum_name(&b, id.color, 0xffffffffu)) && !strcmp(e, "BLUE"), "color 0xffffffff");
    CHECK((e = btf_enum_name(&b, id.color, UINT64_MAX)) && !strcmp(e, "BLUE"), "color, sign-extended");
    CHECK(btf_enum_name(&b, id.color, 7) == NULL, "color 7");
    CHECK((e = btf_enum_name(&b, id.sgn, (uint64_t) -1)) && !strcmp(e, "NEG"), "sgn -1");
    CHECK((e = btf_enum_name(&b, id.big, 0x123456789ull)) && !strcmp(e, "HUGE"), "big");
    CHECK(btf_enum_name(&b, id.big, 0x23456789ull) == NULL, "enum64 compares all 64 bits");
    CHECK(btf_enum_name(&b, id.outer, 0) == NULL, "not an enum");
    int64_t v;
    CHECK(btf_enum_value(&b, id.color, "BLUE", &v) == 0 && v == 0xffffffffll, "BLUE unsigned");
    CHECK(btf_enum_value(&b, id.sgn, "NEG", &v) == 0 && v == -1, "NEG signed");
    CHECK(btf_enum_value(&b, id.big, "HUGE", &v) == 0 && v == 0x123456789ll, "HUGE");
    CHECK(btf_enum_value(&b, id.color, "PINK", &v) != 0, "PINK");
    btf_free(&b);

    /* a longer header is fine as long as the extra bytes are zero */
    unsigned char *big = calloc(1, len + 8);
    memcpy(big, blob, HDR);
    memcpy(big + HDR + 8, blob + HDR, len - HDR);
    uint32_t hl = HDR + 8;
    memcpy(big + 4, &hl, 4);
    CHECK(btf_parse(big, len + 8, &b, err, sizeof(err)) == 0, "hdr_len 32: %s", err);
    btf_free(&b);
    big[HDR + 3] = 1;
    CHECK(btf_parse(big, len + 8, &b, err, sizeof(err)) != 0, "hdr_len 32 with non-zero extra accepted");
    free(big);

    /* corrupted copies */
    printf("synthetic blob, corrupted\n");
    uint32_t bad_ref = s.n + 6, bad_str = (uint32_t) s.sl + 3, bad_kind = 25u << 24;
    static const char *what[] = {
        "magic", "version", "flags", "truncated by a byte", "type ref out of range", "member type out of range",
        "name past the strings", "unknown kind", "strings not NUL-terminated", "type section cut mid-type",
        "type_off misaligned",
    };
    for (size_t i = 0; i < sizeof(what) / sizeof(what[0]); i++) {
        unsigned char *c = malloc(len);
        memcpy(c, blob, len);
        size_t clen = len;
        uint32_t u;
        switch (i) {
        case 0: c[0] = 0x9e; break;
        case 1: c[2] = 2; break;
        case 2: c[3] = 1; break;
        case 3: clen--; break;
        case 4: memcpy(c + HDR + s.at[id.ptr_cv] + 8, &bad_ref, 4); break;
        case 5: memcpy(c + HDR + s.at[id.inner] + 12 + 4, &bad_ref, 4); break;
        case 6: memcpy(c + HDR + s.at[id.outer] + 12 + 12 * 2, &bad_str, 4); break;
        case 7: memcpy(c + HDR + s.at[id.dbl] + 4, &bad_kind, 4); break;
        case 8: c[len - 1] = 'x'; break;
        case 9:
            /* drop the last 4 bytes of the type section: loop_s's member is cut off */
            u = (uint32_t) s.tl - 4;
            memcpy(c + 12, &u, 4);
            break;
        case 10:
            u = 2;
            memcpy(c + 8, &u, 4);
            break;
        }
        int rc = btf_parse(c, clen, &b, err, sizeof(err));
        CHECK(rc != 0, "%s accepted", what[i]);
        if (rc == 0) btf_free(&b);
        else printf("  %-28s %s\n", what[i], err);
        free(c);
    }
    free(blob);
}

/* ---- fixtures: parse vmlinux.btf.gz, diff against pahole ---- */

static unsigned char *gunzip(const char *dir, const char *name, const char *file, size_t *len) {
    char cmd[4200];
    snprintf(cmd, sizeof(cmd), "gzip -dc '%s/%s/%s' 2>/dev/null", dir, name, file);
    FILE *f = popen(cmd, "r");
    if (!f) return NULL;
    size_t cap = 1 << 23, n = 0, got;
    unsigned char *buf = malloc(cap);
    while ((got = fread(buf + n, 1, cap - n, f)) > 0)
        if ((n += got) == cap) buf = realloc(buf, cap *= 2);
    if (pclose(f) != 0 || n == 0) {
        free(buf);
        return NULL;
    }
    *len = n;
    return buf;
}

/* "struct name {" up to the "};" that closes it */
static const char *pahole_block(const char *txt, const char *name, size_t *len) {
    char open[256];
    snprintf(open, sizeof(open), "struct %s {\n", name);
    const char *p = txt;
    while ((p = strstr(p, open)) && p != txt && p[-1] != '\n') p++;
    if (!p) return NULL;
    const char *end = strstr(p, "\n};");
    if (!end) return NULL;
    *len = (size_t) (end - p);
    return p;
}

static bool ident(char c) {
    return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

typedef struct {
    uint64_t bit_off; /* off * 8 + the bit pahole prints after ':' */
    uint32_t size;    /* sizeof the member's type */
    uint32_t bits;    /* the ":N" width, 0 if not a bitfield */
} pahole_t;

/* the line in the block whose declarator is name: the last time name shows
 * up as a whole identifier before the comment, followed by '[', ';', ':',
 * ')' or an __attribute__. that skips type names ("struct pid *thread_pid",
 * "struct seccomp seccomp") and finds function pointers' names. it has to
 * be the only such line. */
static int pahole_member(const char *block, size_t blen, const char *name, pahole_t *out) {
    size_t nl = strlen(name);
    int found = 0;
    for (const char *line = block; line < block + blen;) {
        const char *eol = memchr(line, '\n', (size_t) (block + blen - line));
        if (!eol) eol = block + blen;
        const char *cmt = NULL;
        for (const char *q = line; q + 1 < eol; q++)
            if (q[0] == '/' && q[1] == '*') {
                cmt = q;
                break;
            }
        const char *decl = NULL;
        for (const char *q = line; cmt && q + nl <= cmt; q++) {
            if (memcmp(q, name, nl) != 0 || (q > line && ident(q[-1])) || ident(q[nl])) continue;
            const char *a = q + nl;
            while (*a == ' ') a++;
            if (strchr("[;:)", *a) || strncmp(a, "__attribute__", 13) == 0) decl = q;
        }
        if (decl) {
            const char *a = decl + nl;
            out->bits = *a == ':' ? (uint32_t) strtoul(a + 1, NULL, 10) : 0;
            char *e;
            uint64_t off = strtoull(cmt + 2, &e, 10);
            uint64_t bit = 0;
            if (*e == ':') bit = strtoull(e + 1, &e, 10);
            out->size = (uint32_t) strtoul(e, NULL, 10);
            out->bit_off = off * 8 + bit;
            found++;
        }
        line = eol + 1;
    }
    return found == 1 ? 0 : -1;
}

static const char *const TASK_FIELDS[] = {
    "thread_info", "__state",  "stack",      "usage",        "flags",       "on_cpu",     "prio",
    "se",          "policy",   "tasks",      "mm",           "active_mm",   "exit_state", "sched_reset_on_fork",
    "in_execve",   "pid",      "tgid",       "real_parent",  "parent",      "children",   "sibling",
    "pid_links",   "start_time", "real_cred", "cred",        "comm",        "files",      "nsproxy",
    "signal",      "seccomp",  "rcu_users",  "thread",
};
static const char *const PROG_FIELDS[] = {
    "pages", "jited", "gpl_compatible", "type", "expected_attach_type", "len",  "jited_len", "tag",
    "stats", "active", "bpf_func",      "aux",  "orig_prog",            "insns", "insnsi",
};

/* every listed field of struct name, in BTF and in pahole: offset, bitfield
 * width and size. counts what matched. */
static void diff_struct(const btf_t *b, const char *pahole, const char *name, const char *const *fields, size_t n,
                        int *matched, int *bitfields) {
    uint32_t id = btf_find(b, name, BTF_KIND_STRUCT);
    size_t blen;
    const char *block = pahole_block(pahole, name, &blen);
    CHECK(id && block, "struct %s: btf id %u, pahole %s", name, id, block ? "found" : "missing");
    if (!id || !block) return;

    const char *sz = strstr(block, "/* size: ");
    int64_t want_size = sz ? strtoll(sz + 9, NULL, 10) : -1;
    CHECK(btf_size(b, id) == want_size, "sizeof(struct %s): btf %" PRId64 ", pahole %" PRId64, name, btf_size(b, id),
          want_size);

    for (size_t i = 0; i < n; i++) {
        pahole_t p;
        btf_member_t m;
        if (pahole_member(block, blen, fields[i], &p) != 0) {
            CHECK(0, "%s.%s: not exactly one line in pahole.txt", name, fields[i]);
            continue;
        }
        if (btf_member(b, id, fields[i], &m) != 0) {
            CHECK(0, "%s.%s: not in BTF", name, fields[i]);
            continue;
        }
        int64_t msize = btf_size(b, m.type);
        bool ok = m.bit_off == p.bit_off && m.bit_size == p.bits && msize == p.size;
        CHECK(ok, "%s.%s: btf bit %" PRIu64 ":%u size %" PRId64 ", pahole bit %" PRIu64 ":%u size %u", name, fields[i],
              m.bit_off, m.bit_size, msize, p.bit_off, p.bits, p.size);
        *matched += ok;
        *bitfields += ok && p.bits;
    }
}

static void test_fixture_btf(const char *dir, const char *name) {
    size_t len;
    unsigned char *raw = gunzip(dir, name, "vmlinux.btf.gz", &len);
    char *pahole = fixture_file(dir, name, "pahole.txt", NULL);
    if (!raw && !pahole) return; /* not a fixture */
    printf("fixture %s: vmlinux.btf vs pahole\n", name);
    CHECK(raw && pahole, "missing vmlinux.btf.gz or pahole.txt");
    btf_t b;
    char err[256];
    if (!raw || !pahole || btf_parse(raw, len, &b, err, sizeof(err)) != 0) {
        if (raw && pahole) CHECK(0, "parse: %s", err);
        free(raw);
        free(pahole);
        return;
    }

    int matched = 0, bitfields = 0;
    diff_struct(&b, pahole, "task_struct", TASK_FIELDS, sizeof(TASK_FIELDS) / sizeof(*TASK_FIELDS), &matched,
                &bitfields);
    diff_struct(&b, pahole, "bpf_prog", PROG_FIELDS, sizeof(PROG_FIELDS) / sizeof(*PROG_FIELDS), &matched,
                &bitfields);
    printf("  %u types; %d fields match pahole, %d of them bitfields\n", b.n, matched, bitfields);
    CHECK(matched >= 20 && bitfields >= 1, "done-when: >= 20 fields and a bitfield");

    /* pointees */
    uint32_t task = btf_find(&b, "task_struct", BTF_KIND_STRUCT), prog = btf_find(&b, "bpf_prog", BTF_KIND_STRUCT);
    static const struct {
        int prog;
        const char *field, *pointee;
    } ptrs[] = {
        {0, "real_cred", "cred"}, {0, "parent", "task_struct"}, {0, "mm", "mm_struct"}, {1, "aux", "bpf_prog_aux"},
    };
    for (size_t i = 0; i < sizeof(ptrs) / sizeof(ptrs[0]); i++) {
        btf_member_t m;
        uint32_t want = btf_find(&b, ptrs[i].pointee, BTF_KIND_STRUCT);
        CHECK(btf_member(&b, ptrs[i].prog ? prog : task, ptrs[i].field, &m) == 0 && want &&
                  btf_pointee(&b, m.type) == want,
              "%s points at struct %s", ptrs[i].field, ptrs[i].pointee);
    }

    /* a dotted path adds up */
    btf_member_t se, vr, path;
    uint32_t sched = btf_find(&b, "sched_entity", BTF_KIND_STRUCT);
    CHECK(btf_member(&b, task, "se", &se) == 0 && btf_member(&b, sched, "vruntime", &vr) == 0 &&
              btf_member(&b, task, "se.vruntime", &path) == 0 && path.bit_off == se.bit_off + vr.bit_off,
          "se.vruntime");

    /* bpf_prog.type through its enum: the UAPI's first values, then every
     * enumerator round-trips */
    btf_member_t tm;
    btf_type_t et;
    const char *e;
    CHECK(btf_member(&b, prog, "type", &tm) == 0 && btf_type(&b, btf_resolve(&b, tm.type), &et) == 0 &&
              et.kind == BTF_KIND_ENUM && !strcmp(et.name, "bpf_prog_type"),
          "bpf_prog.type is enum bpf_prog_type");
    CHECK((e = btf_enum_name(&b, tm.type, 1)) && !strcmp(e, "BPF_PROG_TYPE_SOCKET_FILTER"), "prog type 1");
    CHECK((e = btf_enum_name(&b, tm.type, 2)) && !strcmp(e, "BPF_PROG_TYPE_KPROBE"), "prog type 2");
    int64_t v;
    int round = 0;
    for (int64_t i = 0; i < 256; i++) {
        if (!(e = btf_enum_name(&b, tm.type, (uint64_t) i))) continue;
        CHECK(btf_enum_value(&b, tm.type, e, &v) == 0 && v == i, "%s round trip", e);
        round++;
    }
    printf("  bpf_prog_type: %d enumerators by value, e.g. 2 = %s\n", round, btf_enum_name(&b, tm.type, 2));

    btf_free(&b);
    free(raw);
    free(pahole);
}

/* ---- fixtures with a dump: find .BTF in guest memory ---- */

static bool cfg_from_scan(const pt_image_t *img, ksym_cfg_t *cfg) {
    uint64_t hits[16];
    size_t n = ksym_banner_scan(img, hits, 16);
    for (size_t i = 0; i < n && i < 16; i++) {
        char b[512] = "";
        for (size_t l = 0; l < sizeof(b) - 1 && pt_image_ptr(img, hits[i] + l, 1); l++)
            if (!(b[l] = (char) *pt_image_ptr(img, hits[i] + l, 1))) break;
        if (ksym_cfg_from_banner(b, cfg, NULL, 0) == 0) return true;
    }
    return false;
}

static void test_fixture_dump(const char *dir, const char *name) {
    if (fixture_has_dump(dir, name) <= 0) return;
    printf("fixture %s: .BTF in the dump\n", name);

    size_t want_len;
    unsigned char *want = gunzip(dir, name, "vmlinux.btf.gz", &want_len);
    char *syms = fixture_file(dir, name, "symcheck", NULL);
    CHECK(want, "no vmlinux.btf.gz");
    kmem_t m;
    pt_root_t r;
    pt_image_t img;
    char err[512];
    if (!want || fixture_open(dir, name, &m, &r, NULL) != 0) goto out;
    if (pt_image(&m, &r, &img, err, sizeof(err)) != 0) {
        CHECK(0, "pt_image: %s", err);
        kmem_close(&m);
        goto out;
    }
    CHECK(pt_image_read_nx(&m, &r, &img, err, sizeof(err)) == 0, "%s", err);
    kmem_close(&m);

    ksym_cfg_t cfg;
    ksym_table_t tab;
    if (!cfg_from_scan(&img, &cfg) || ksym_load(&img, &cfg, &tab, err, sizeof(err)) != 0) {
        CHECK(0, "kallsyms: %s", err);
        pt_image_free(&img);
        goto out;
    }

    /* by symbol: the blob is /sys/kernel/btf/vmlinux, byte for byte */
    btf_t b;
    if (btf_load(&img, &tab, &b, err, sizeof(err)) == 0) {
        const ksym_t *start = ksym_by_name(&tab, "__start_BTF"), *stop = ksym_by_name(&tab, "__stop_BTF");
        uint64_t sym_start = 0;
        CHECK(sym_get(syms, "__start_BTF", &sym_start) != 0 || sym_start == b.va, "__start_BTF differs from symcheck");
        printf("  by symbol: 0x%" PRIx64 " +0x%zx (__stop_BTF - __start_BTF = 0x%" PRIx64 "), %u types\n", b.va,
               b.len, stop->addr - start->addr, b.n);
        CHECK(b.by_symbol && b.va == start->addr, "not found by symbol");
        CHECK(b.len == want_len && memcmp(b.data, want, want_len) == 0, "blob differs from /sys/kernel/btf/vmlinux");
        uint32_t task = btf_find(&b, "task_struct", BTF_KIND_STRUCT);
        btf_member_t pid;
        CHECK(task && btf_member(&b, task, "pid", &pid) == 0, "task_struct.pid from the dump's BTF");
    } else {
        CHECK(0, "btf_load by symbol: %s", err);
    }

    /* by scan: no kallsyms at all, same place */
    uint64_t va, len;
    bool by_symbol = true;
    if (btf_find_blob(&img, NULL, &va, &len, &by_symbol, err, sizeof(err)) == 0) {
        printf("  by scan:   0x%" PRIx64 " +0x%" PRIx64 "\n", va, len);
        CHECK(!by_symbol && b.data && va == b.va && len == b.len, "scan found a different blob");
    } else {
        CHECK(0, "btf_find_blob by scan: %s", err);
    }
    btf_free(&b);

    ksym_free(&tab);
    pt_image_free(&img);
out:
    free(want);
    free(syms);
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "tests/fixtures";
    test_synthetic();
    for_each_fixture(dir, test_fixture_btf);
    for_each_fixture(dir, test_fixture_dump);

    printf(failures ? "\n%d FAILED\n" : "\nall passed\n", failures);
    return failures ? 1 : 0;
}
