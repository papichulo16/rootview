#define _GNU_SOURCE /* memmem */
#include "kern/prof/ksym.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* limits that keep a bad candidate from walking off into the weeds. real
 * kernels sit far below them (~150-200k symbols). */
#define MAX_SYMS (1u << 22)
#define MAX_MARKERS (MAX_SYMS / 256)
#define MAX_ENTRY (2 + 0x3fff) /* two-byte ULEB128 length + the bytes */
#define MAX_NAME 1024          /* expanded, type char included (KSYM_NAME_LEN is 512) */

static const char DIGITS[] = "0\0001\0002\0003\0004\0005\0006\0007\0008\0009"; /* + the trailing NUL */
#define DIGITS_LEN 20

#define BANNER "Linux version "

/* one loaded run, every read bounds-checked against it */
typedef struct {
    const unsigned char *p;
    uint64_t va, len;
} view_t;

static bool in_view(const view_t *v, uint64_t va, uint64_t len) {
    return va >= v->va && va - v->va <= v->len && len <= v->len - (va - v->va);
}

static const unsigned char *at(const view_t *v, uint64_t va) {
    return v->p + (va - v->va);
}

static bool rd16(const view_t *v, uint64_t va, uint16_t *out) {
    if (!in_view(v, va, 2)) return false;
    memcpy(out, at(v, va), 2);
    return true;
}

static bool rd32(const view_t *v, uint64_t va, uint32_t *out) {
    if (!in_view(v, va, 4)) return false;
    memcpy(out, at(v, va), 4);
    return true;
}

static bool rd64(const view_t *v, uint64_t va, uint64_t *out) {
    if (!in_view(v, va, 8)) return false;
    memcpy(out, at(v, va), 8);
    return true;
}

static uint64_t align8(uint64_t x) {
    return (x + 7) & ~7ull;
}

/* the zero fill .balign leaves between the end of one table and the next label */
static bool zero_pad(const view_t *v, uint64_t from, uint64_t to) {
    if (to < from || !in_view(v, from, to - from)) return false;
    for (uint64_t va = from; va < to; va++)
        if (*at(v, va) != 0) return false;
    return true;
}

#define FAIL(...)                                                                                                      \
    do {                                                                                                               \
        if (err) snprintf(err, err_len, __VA_ARGS__);                                                                  \
        return false;                                                                                                  \
    } while (0)

/* ---- token table ---- */

typedef struct {
    uint64_t tt, ti;    /* token_table, token_index */
    uint16_t idx[256];
} tokens_t;

/* digit "0" is token 48 and sits at hit. checks that walking 198 more NULs
 * from "9" ends the table, that token_index follows at the next 8-byte
 * boundary, and that every index entry points at the start of the string
 * after the previous one's NUL. */
static bool find_tokens(const view_t *v, uint64_t hit, tokens_t *t, char *err, size_t err_len) {
    if (!in_view(v, hit - 1, 1) || *at(v, hit - 1) != 0) FAIL("byte before \"0\" isn't the end of token 47");

    uint64_t va = hit + DIGITS_LEN;
    for (int tok = 58; tok < 256; tok++) {
        uint64_t start = va;
        while (in_view(v, va, 1) && *at(v, va) != 0) {
            if (va - start > MAX_NAME) FAIL("token %d runs past %d bytes", tok, MAX_NAME);
            va++;
        }
        if (!in_view(v, va, 1)) FAIL("token %d runs off the end of the run", tok);
        va++;
    }
    uint64_t tt_end = va;

    t->ti = align8(tt_end);
    if (!zero_pad(v, tt_end, t->ti)) FAIL("no zero padding before token_index");
    for (int i = 0; i < 256; i++)
        if (!rd16(v, t->ti + 2 * i, &t->idx[i])) FAIL("token_index runs off the end of the run");

    if (t->idx[0] != 0) FAIL("token_index[0] = %u, want 0", t->idx[0]);
    if (t->idx[48] > hit - v->va) FAIL("token_index[48] points before the run");
    t->tt = hit - t->idx[48];
    if (t->tt & 7) FAIL("token_table at 0x%" PRIx64 " isn't 8-aligned", t->tt);

    for (int i = 0; i < 256; i++) {
        uint64_t s = t->tt + t->idx[i];
        uint64_t e = i < 255 ? t->tt + t->idx[i + 1] : tt_end;
        if (e <= s) FAIL("token_index[%d] isn't increasing", i);
        for (uint64_t p = s; p + 1 < e; p++) {
            unsigned char c = *at(v, p);
            if (c < 0x20 || c > 0x7e) FAIL("token %d has byte 0x%02x", i, c);
        }
        if (*at(v, e - 1) != 0) FAIL("token %d isn't NUL-terminated where token_index says", i);
    }
    return true;
}

/* ---- markers, num_syms, names ---- */

typedef struct {
    uint64_t markers;
    uint32_t n_markers;
    uint64_t num_syms; /* va of the count */
    uint64_t names;
    uint32_t n;
} names_t;

static bool check_markers(const view_t *v, uint64_t m, uint32_t n_markers) {
    uint32_t prev, cur;
    if (!rd32(v, m, &prev) || prev != 0) return false;
    for (uint32_t i = 1; i < n_markers; i++) {
        /* 256 entries of at least two bytes each */
        if (!rd32(v, m + 4ull * i, &cur) || cur < prev || cur - prev < 512) return false;
        prev = cur;
    }
    return true;
}

static bool entry_len(const view_t *v, uint64_t va, uint32_t *hdr, uint32_t *len) {
    if (!in_view(v, va, 1)) return false;
    unsigned char b0 = *at(v, va);
    if (b0 & 0x80) {
        if (!in_view(v, va + 1, 1)) return false;
        unsigned char b1 = *at(v, va + 1);
        if (b1 & 0x80) return false;
        *hdr = 2;
        *len = (b0 & 0x7fu) | ((uint32_t) b1 << 7);
    } else {
        *hdr = 1;
        *len = b0;
    }
    return *len != 0 && in_view(v, va + *hdr, *len);
}

/* walks all n entries from names and checks that each 256th one starts at
 * its marker and that the stream ends where the markers' padding begins */
static bool check_names(const view_t *v, uint64_t names, uint32_t n, uint64_t markers, uint32_t n_markers) {
    if ((n + 255) / 256 != n_markers) return false;
    uint64_t va = names;
    for (uint32_t i = 0; i < n; i++) {
        if ((i & 0xff) == 0) {
            uint32_t mk;
            if (!rd32(v, markers + 4ull * (i >> 8), &mk) || va - names != mk) return false;
        }
        uint32_t hdr, len;
        if (!entry_len(v, va, &hdr, &len)) return false;
        va += hdr + len;
        if (va > markers) return false;
    }
    return align8(va) == markers && zero_pad(v, va, markers);
}

/* markers sits at m (n_markers of them, already checked). num_syms is a .long
 * padded to 8 right before names, and names starts markers[last] before the
 * last block, so the count has to be in a window just below that block. */
static bool find_names(const view_t *v, uint64_t m, uint32_t n_markers, uint32_t want_n, names_t *out) {
    uint32_t last;
    if (!rd32(v, m + 4ull * (n_markers - 1), &last)) return false;
    if (m < v->va + last + 8 + 2) return false;

    uint32_t lo = want_n ? want_n : (n_markers - 1) * 256 + 1;
    uint32_t hi = want_n ? want_n : n_markers * 256;

    uint64_t top = (m - last - 8 - 2) & ~7ull;
    uint64_t span = 256ull * MAX_ENTRY + 8;
    uint64_t bottom = top - v->va > span ? top - span : v->va;
    for (uint64_t x = top; x >= bottom; x -= 8) {
        uint32_t n, pad;
        if (!rd32(v, x, &n) || !rd32(v, x + 4, &pad)) continue;
        if (n < lo || n > hi || pad != 0) continue;
        if (!check_names(v, x + 8, n, m, n_markers)) continue;
        *out = (names_t) {.markers = m, .n_markers = n_markers, .num_syms = x, .names = x + 8, .n = n};
        return true;
    }
    return false;
}

static bool check_seqs(const view_t *v, uint64_t va, uint32_t n) {
    if (!in_view(v, va, 3ull * n)) return false;
    const unsigned char *p = at(v, va);
    for (uint32_t i = 0; i < n; i++, p += 3)
        if (((uint32_t) p[0] << 16 | (uint32_t) p[1] << 8 | p[2]) >= n) return false;
    return true;
}

static bool locate_names(const view_t *v, ksym_layout_t layout, uint64_t tt, names_t *out, uint64_t *seqs) {
    *seqs = 0;
    if (layout == KSYM_LAYOUT_V6_2) {
        /* the seqs gap depends on the exact count, so walk counts */
        for (uint32_t n = 1; n <= MAX_SYMS; n++) {
            uint64_t gap = align8(3ull * n);
            uint32_t nm = (n + 255) / 256;
            uint64_t need = gap + align8(4ull * nm);
            if (tt - v->va < need) break;
            uint64_t s = tt - gap, m = s - align8(4ull * nm);
            if (!check_markers(v, m, nm) || !zero_pad(v, m + 4ull * nm, s)) continue;
            if (!check_seqs(v, s, n) || !zero_pad(v, s + 3ull * n, tt)) continue;
            if (find_names(v, m, nm, n, out)) {
                *seqs = s;
                return true;
            }
        }
        return false;
    }
    for (uint32_t nm = 1; nm <= MAX_MARKERS; nm++) {
        uint64_t mlen = align8(4ull * nm);
        if (tt - v->va < mlen) break;
        uint64_t m = tt - mlen;
        if (!check_markers(v, m, nm) || !zero_pad(v, m + 4ull * nm, tt)) continue;
        if (find_names(v, m, nm, 0, out)) return true;
    }
    return false;
}

/* ---- decode ---- */

static bool expand(const view_t *v, const tokens_t *t, uint64_t va, uint32_t len, char *out, size_t *out_len) {
    size_t o = 0;
    for (uint32_t i = 0; i < len; i++) {
        unsigned char b = *at(v, va + i);
        const unsigned char *tok = at(v, t->tt + t->idx[b]);
        for (; *tok; tok++) {
            if (o + 1 >= MAX_NAME) return false;
            out[o++] = (char) *tok;
        }
    }
    out[o] = '\0';
    *out_len = o;
    return true;
}

static uint32_t hash_name(const char *s) {
    uint32_t h = 2166136261u;
    for (; *s; s++) h = (h ^ (unsigned char) *s) * 16777619u;
    return h;
}

static bool build_hash(ksym_table_t *tab) {
    size_t cap = 1;
    while (cap < tab->n * 2) cap <<= 1;
    tab->hash = calloc(cap, sizeof(*tab->hash));
    if (!tab->hash) return false;
    tab->hash_cap = cap;
    for (size_t i = 0; i < tab->n; i++) {
        size_t h = hash_name(tab->syms[i].name) & (cap - 1);
        while (tab->hash[h]) h = (h + 1) & (cap - 1);
        tab->hash[h] = (uint32_t) i + 1;
    }
    return true;
}

static bool decode(const view_t *v, const pt_image_t *img, const ksym_cfg_t *cfg, const tokens_t *t, const names_t *nm,
                   uint64_t offsets, uint64_t relbase_va, ksym_table_t *tab, char *err, size_t err_len) {
    uint64_t base;
    if (!rd64(v, relbase_va, &base)) FAIL("kallsyms_relative_base at 0x%" PRIx64 " isn't loaded", relbase_va);
    if (base < img->start || base >= img->end)
        FAIL("kallsyms_relative_base 0x%" PRIx64 " is outside the image 0x%" PRIx64 "-0x%" PRIx64, base,
             img->start, img->end);
    if (!in_view(v, offsets, 4ull * nm->n)) FAIL("kallsyms_offsets at 0x%" PRIx64 " isn't loaded", offsets);

    /* sizing pass, so the names can live in one arena */
    char buf[MAX_NAME];
    size_t arena = 0, blen;
    uint64_t va = nm->names;
    for (uint32_t i = 0; i < nm->n; i++) {
        uint32_t hdr, len;
        entry_len(v, va, &hdr, &len); /* check_names already walked these */
        if (!expand(v, t, va + hdr, len, buf, &blen)) FAIL("symbol %u expands past %d bytes", i, MAX_NAME);
        if (blen < 2) FAIL("symbol %u has no name after its type", i);
        arena += blen; /* the type char's byte holds the NUL instead */
        va += hdr + len;
    }

    tab->syms = calloc(nm->n, sizeof(*tab->syms));
    tab->strs = malloc(arena);
    if (!tab->syms || !tab->strs) FAIL("out of memory for %u symbols", nm->n);
    tab->n = nm->n;

    size_t used = 0;
    uint64_t prev = 0;
    va = nm->names;
    for (uint32_t i = 0; i < nm->n; i++) {
        uint32_t hdr, len;
        entry_len(v, va, &hdr, &len);
        expand(v, t, va + hdr, len, buf, &blen);
        va += hdr + len;

        int32_t off;
        memcpy(&off, at(v, offsets + 4ull * i), 4);
        uint64_t addr;
        if (cfg->addr == KSYM_ADDR_RELATIVE) addr = base + (uint32_t) off;
        else addr = off >= 0 ? (uint64_t) off : base - 1 - (int64_t) off;
        if (addr < prev) FAIL("symbol %u (%.64s) at 0x%" PRIx64 " is below the one before it (0x%" PRIx64 ")", i, buf + 1,
                              addr, prev);
        prev = addr;

        memcpy(tab->strs + used, buf + 1, blen);
        tab->syms[i] = (ksym_t) {.addr = addr, .name = tab->strs + used, .type = buf[0]};
        used += blen;
    }

    if (!build_hash(tab)) FAIL("out of memory for the symbol hash");

    const ksym_t *text = ksym_by_name(tab, "_text");
    if (!text) FAIL("no _text symbol");
    if (text->addr != img->start)
        FAIL("_text decodes to 0x%" PRIx64 ", but the image starts at 0x%" PRIx64, text->addr, img->start);
    tab->relative_base = base;
    return true;
}

/* one candidate token table at hit, all the way through. *real is set once
 * the token table itself checks out, so the caller can report the error
 * from a real table over the ones from stray digit runs. */
static bool try_hit(const view_t *v, const pt_image_t *img, const ksym_cfg_t *cfg, uint64_t hit, ksym_table_t *tab,
                    bool *real, char *err, size_t err_len) {
    tokens_t t;
    *real = false;
    if (!find_tokens(v, hit, &t, err, err_len)) return false;
    *real = true;

    names_t nm;
    uint64_t seqs;
    if (!locate_names(v, cfg->layout, t.tt, &nm, &seqs))
        FAIL("token_table at 0x%" PRIx64 ", but no markers/names/num_syms fit the %s layout before it", t.tt,
             ksym_layout_name(cfg->layout));

    uint64_t offsets, relbase;
    uint64_t olen = align8(4ull * nm.n);
    if (cfg->layout == KSYM_LAYOUT_V6_4) {
        offsets = t.ti + 512;
        relbase = offsets + olen;
        seqs = relbase + 8;
        if (!zero_pad(v, offsets + 4ull * nm.n, relbase)) FAIL("no zero padding after kallsyms_offsets");
        if (!check_seqs(v, seqs, nm.n)) FAIL("kallsyms_seqs_of_names at 0x%" PRIx64 " doesn't check out", seqs);
    } else {
        if (nm.num_syms - v->va < 8 + olen) FAIL("no room for kallsyms_offsets before kallsyms_relative_base");
        relbase = nm.num_syms - 8;
        offsets = relbase - olen;
        if (!zero_pad(v, offsets + 4ull * nm.n, relbase)) FAIL("no zero padding after kallsyms_offsets");
    }

    ksym_table_t out = {0};
    if (!decode(v, img, cfg, &t, &nm, offsets, relbase, &out, err, err_len)) {
        ksym_free(&out);
        return false;
    }
    out.va_num_syms = nm.num_syms;
    out.va_names = nm.names;
    out.va_markers = nm.markers;
    out.va_token_table = t.tt;
    out.va_token_index = t.ti;
    out.va_offsets = offsets;
    out.va_seqs = seqs;
    *tab = out;
    return true;
}

int ksym_load(const pt_image_t *img, const ksym_cfg_t *cfg, ksym_table_t *tab, char *err, size_t err_len) {
    *tab = (ksym_table_t) {0};
    char last[512] = "";
    int candidates = 0;
    bool have_real = false;

    for (size_t r = 0; r < img->n_runs; r++) {
        const pt_run_t *run = &img->runs[r];
        if (!run->nx || !run->data || run->len < DIGITS_LEN) continue;
        view_t v = {.p = run->data, .va = run->va, .len = run->len};

        const unsigned char *p = run->data, *end = run->data + run->len;
        while ((p = memmem(p, (size_t) (end - p), DIGITS, DIGITS_LEN)) != NULL) {
            uint64_t hit = run->va + (uint64_t) (p - run->data);
            candidates++;
            char e[256] = "";
            bool real;
            if (try_hit(&v, img, cfg, hit, tab, &real, e, sizeof(e))) return 0;
            if (real || !have_real) snprintf(last, sizeof(last), "%s (\"0\" at 0x%" PRIx64 "): %s",
                                             real ? "real table" : "stray digits", hit, e);
            have_real |= real;
            p++;
        }
    }

    if (err) {
        if (!candidates) snprintf(err, err_len, "no token_table (\"0\" .. \"9\") in the image's NX pages");
        else snprintf(err, err_len, "%d token_table candidate(s) rejected for %s/%s; %s", candidates,
                      ksym_layout_name(cfg->layout), ksym_addr_name(cfg->addr), last);
    }
    return -1;
}

/* ---- lookups ---- */

const ksym_t *ksym_by_name(const ksym_table_t *tab, const char *name) {
    if (!tab->hash_cap) return NULL;
    size_t h = hash_name(name) & (tab->hash_cap - 1);
    for (; tab->hash[h]; h = (h + 1) & (tab->hash_cap - 1)) {
        const ksym_t *s = &tab->syms[tab->hash[h] - 1];
        if (strcmp(s->name, name) == 0) return s;
    }
    return NULL;
}

const ksym_t *ksym_by_addr(const ksym_table_t *tab, uint64_t addr, uint64_t *off) {
    size_t lo = 0, hi = tab->n; /* first index with syms[i].addr > addr */
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (tab->syms[mid].addr <= addr) lo = mid + 1;
        else hi = mid;
    }
    if (lo == 0) return NULL;
    const ksym_t *s = &tab->syms[lo - 1];
    if (off) *off = addr - s->addr;
    return s;
}

void ksym_free(ksym_table_t *tab) {
    free(tab->syms);
    free(tab->strs);
    free(tab->hash);
    *tab = (ksym_table_t) {0};
}

/* ---- switches and checks ---- */

const char *ksym_layout_name(ksym_layout_t layout) {
    switch (layout) {
    case KSYM_LAYOUT_V5: return "v5 (<= 6.1)";
    case KSYM_LAYOUT_V6_2: return "v6.2 (6.2-6.3)";
    case KSYM_LAYOUT_V6_4: return "v6.4 (>= 6.4)";
    }
    return "?";
}

const char *ksym_addr_name(ksym_addr_t addr) {
    return addr == KSYM_ADDR_ABS_PERCPU ? "absolute-percpu" : "relative";
}

int ksym_cfg_from_banner(const char *banner, ksym_cfg_t *cfg, char *err, size_t err_len) {
    unsigned maj, min;
    if (strncmp(banner, BANNER, strlen(BANNER)) != 0 || sscanf(banner + strlen(BANNER), "%u.%u", &maj, &min) != 2) {
        if (err) snprintf(err, err_len, "not a linux banner: '%.40s'", banner);
        return -1;
    }
    unsigned v = maj * 1000 + min;
    if (v < 4006) {
        /* kallsyms_offsets (base-relative) is x86_64's default from 4.6 */
        if (err) snprintf(err, err_len, "kernel %u.%u predates base-relative kallsyms", maj, min);
        return -1;
    }

    cfg->layout = v < 6002 ? KSYM_LAYOUT_V5 : v < 6004 ? KSYM_LAYOUT_V6_2 : KSYM_LAYOUT_V6_4;
    /* KALLSYMS_ABSOLUTE_PERCPU was x86_64 && SMP, and went away in 6.15 */
    bool smp = false;
    for (const char *p = banner; (p = strstr(p, " SMP")) != NULL; p++)
        smp |= p[4] == ' ' || p[4] == '\0' || p[4] == '\n';
    cfg->addr = v < 6015 && smp ? KSYM_ADDR_ABS_PERCPU : KSYM_ADDR_RELATIVE;
    return 0;
}

size_t ksym_banner_scan(const pt_image_t *img, uint64_t *hits, size_t max) {
    size_t n = 0, bl = strlen(BANNER);
    for (size_t r = 0; r < img->n_runs; r++) {
        const pt_run_t *run = &img->runs[r];
        if (!run->nx || !run->data) continue;
        const unsigned char *p = run->data, *end = run->data + run->len;
        while ((p = memmem(p, (size_t) (end - p), BANNER, bl)) != NULL) {
            if (n < max) hits[n] = run->va + (uint64_t) (p - run->data);
            n++;
            p++;
        }
    }
    return n;
}

int ksym_check_banner(const pt_image_t *img, const ksym_table_t *tab, char *banner, size_t banner_len, char *err,
                      size_t err_len) {
    const ksym_t *s = ksym_by_name(tab, "linux_banner");
    if (!s) {
        if (err) snprintf(err, err_len, "no linux_banner symbol");
        return -1;
    }

    const unsigned char *p = pt_image_ptr(img, s->addr, 1);
    if (!p) {
        if (err) snprintf(err, err_len, "linux_banner 0x%" PRIx64 " isn't in a loaded NX run", s->addr);
        return -1;
    }
    /* the string has to end inside the same run */
    size_t room = 0;
    while (pt_image_ptr(img, s->addr, room + 1) && room < 4096 && p[room]) room++;
    if (!pt_image_ptr(img, s->addr, room + 1) || p[room]) {
        if (err) snprintf(err, err_len, "linux_banner 0x%" PRIx64 " isn't NUL-terminated", s->addr);
        return -1;
    }
    if (strncmp((const char *) p, BANNER, strlen(BANNER)) != 0) {
        if (err) snprintf(err, err_len, "linux_banner 0x%" PRIx64 " reads '%.20s'", s->addr, p);
        return -1;
    }

    uint64_t hits[64];
    size_t n = ksym_banner_scan(img, hits, 64);
    bool found = false;
    for (size_t i = 0; i < n && i < 64; i++) found |= hits[i] == s->addr;
    if (!found) {
        if (err) snprintf(err, err_len, "linux_banner 0x%" PRIx64 " isn't among the %zu raw \"" BANNER "\" hits",
                          s->addr, n);
        return -1;
    }

    if (banner && banner_len) snprintf(banner, banner_len, "%s", (const char *) p);
    return 0;
}
