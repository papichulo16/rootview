#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "kscan_priv.h"

static uint64_t hash64(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    return x;
}

static uint64_t key(kscan_kind_t kind, uint64_t addr) {
    return hash64(addr ^ ((uint64_t) kind << 56));
}

int kscan_start(kscan_result_t *r, kscan_kind_t kind, char *err, size_t err_len) {
    *r = (kscan_result_t) {.kind = kind, .cap = 256, .hash_cap = 1024};
    r->objs = calloc(r->cap, sizeof(*r->objs));
    r->hash = calloc(r->hash_cap, sizeof(*r->hash));
    if (!r->objs || !r->hash) {
        kscan_free(r);
        FAIL("out of memory");
    }
    return 0;
}

void kscan_free(kscan_result_t *r) {
    free(r->objs);
    free(r->hash);
    r->objs = NULL;
    r->hash = NULL;
    r->n = r->cap = r->hash_cap = 0;
}

static size_t slot_of(const kscan_result_t *r, kscan_kind_t kind, uint64_t addr) {
    size_t i = key(kind, addr) & (r->hash_cap - 1);
    for (; r->hash[i]; i = (i + 1) & (r->hash_cap - 1)) {
        const kscan_object_t *o = &r->objs[r->hash[i] - 1];
        if (o->addr == addr && o->kind == kind) break;
    }
    return i;
}

const kscan_object_t *kscan_find(const kscan_result_t *r, kscan_kind_t kind, uint64_t addr) {
    if (!r->hash_cap) return NULL;
    size_t i = slot_of(r, kind, addr);
    return r->hash[i] ? &r->objs[r->hash[i] - 1] : NULL;
}

static int grow(kscan_result_t *r) {
    if (r->n == r->cap) {
        kscan_object_t *o = realloc(r->objs, 2 * r->cap * sizeof(*o));
        if (!o) return -1;
        r->objs = o;
        r->cap *= 2;
    }
    if ((r->n + 1) * 2 > r->hash_cap) {
        uint32_t *h = calloc(2 * r->hash_cap, sizeof(*h));
        if (!h) return -1;
        free(r->hash);
        r->hash = h;
        r->hash_cap *= 2;
        for (size_t i = 0; i < r->n; i++) r->hash[slot_of(r, r->objs[i].kind, r->objs[i].addr)] = (uint32_t) (i + 1);
    }
    return 0;
}

kscan_object_t *kscan_add(kscan_result_t *r, kscan_kind_t kind, uint64_t addr, unsigned src, bool *added) {
    size_t i = slot_of(r, kind, addr);
    kscan_object_t *o;
    if (r->hash[i]) {
        o = &r->objs[r->hash[i] - 1];
        if (added) *added = false;
    } else {
        if (r->n >= KSCAN_MAX_OBJECTS || grow(r) != 0) return NULL;
        i = slot_of(r, kind, addr); /* the table may have been rehashed */
        o = &r->objs[r->n];
        *o = (kscan_object_t) {.kind = kind, .addr = addr, .id = -1};
        r->hash[i] = (uint32_t) ++r->n;
        if (added) *added = true;
    }
    if (src < KSCAN_SOURCES) {
        o->source_mask |= 1u << src;
        r->source_count[src]++;
    }
    return o;
}

void kscan_source_failed(kscan_result_t *r, unsigned src, const char *err) {
    if (src >= KSCAN_SOURCES) return;
    r->ran_mask &= ~(1u << src);
    snprintf(r->source_err[src], sizeof(r->source_err[src]), "%s", err && *err ? err : "failed");
}

void kscan_source_ran(kscan_result_t *r, unsigned src) {
    if (src < KSCAN_SOURCES) r->ran_mask |= 1u << src;
}

int kscan_window_begin(kwalk_t *w, bool *own, char *err, size_t err_len) {
    *own = !w->in_window;
    return *own ? kwalk_begin(w, err, err_len) : 0;
}

int kscan_window_end(kwalk_t *w, bool own, int rc, char *err, size_t err_len) {
    char rerr[256];
    if (own && kwalk_end(w, rerr, sizeof(rerr)) != 0 && rc == 0) {
        if (err) snprintf(err, err_len, "%s", rerr);
        return -1;
    }
    return rc;
}

int kscan_off(const kwalk_t *w, const char *type, const char *path, uint64_t *off, char *err, size_t err_len) {
    kfield_t f;
    if (kfield_resolve(&w->kp->btf, type, path, &f, err, err_len) != 0) return -1;
    *off = f.offset;
    return 0;
}

void kscan_name(char *dst, size_t dst_len, const void *src, size_t src_len) {
    const unsigned char *s = src;
    size_t i = 0;
    for (; i + 1 < dst_len && i < src_len && s[i]; i++) dst[i] = s[i] >= 0x20 && s[i] < 0x7f ? (char) s[i] : '?';
    dst[i] = '\0';
}

void kscan_source_failf(kscan_result_t *r, unsigned src, const char *fmt, ...) {
    char e[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e, sizeof(e), fmt, ap);
    va_end(ap);
    kscan_source_failed(r, src, e);
}

int kscan_sym(const kwalk_t *w, const char *name, uint64_t *addr, char *err, size_t err_len) {
    const ksym_t *s = ksym_by_name(&w->kp->ksym, name);
    if (!s) FAIL("no %s symbol", name);
    *addr = s->addr;
    return 0;
}

int kscan_u64(kwalk_t *w, uint64_t va, uint64_t *v, char *err, size_t err_len) {
    return kwalk_read(w, va, v, sizeof(*v), err, err_len);
}

int kscan_u32(kwalk_t *w, uint64_t va, uint32_t *v, char *err, size_t err_len) {
    return kwalk_read(w, va, v, sizeof(*v), err, err_len);
}

bool kscan_set_add(kscan_set_t *s, uint64_t addr) {
    if (!addr) return false;
    if ((s->n + 1) * 2 > s->cap) {
        size_t cap = s->cap ? s->cap * 2 : 64;
        uint64_t *slots = calloc(cap, sizeof(*slots));
        if (!slots) return false;
        for (size_t i = 0; i < s->cap; i++) {
            if (!s->slots[i]) continue;
            size_t j = hash64(s->slots[i]) & (cap - 1);
            while (slots[j]) j = (j + 1) & (cap - 1);
            slots[j] = s->slots[i];
        }
        free(s->slots);
        s->slots = slots;
        s->cap = cap;
    }
    size_t i = hash64(addr) & (s->cap - 1);
    for (; s->slots[i]; i = (i + 1) & (s->cap - 1))
        if (s->slots[i] == addr) return false;
    s->slots[i] = addr;
    s->n++;
    return true;
}

void kscan_set_free(kscan_set_t *s) {
    free(s->slots);
    *s = (kscan_set_t) {0};
}

static const char *const NAMES[4][KSCAN_SOURCES] = {
    [KSCAN_TASK] = {"task_list", "pid_idr", "runqueue", "children", "threads"},
    [KSCAN_MODULE] = {"module_list", "mod_tree", "carve", "mod_tree[1]"},
    [KSCAN_BPF_PROG] = {"prog_idr", "bpf_kallsyms", "bpf_tree", "prog_func", "map_idr", "used_maps"},
    [KSCAN_BPF_MAP] = {"prog_idr", "bpf_kallsyms", "bpf_tree", "prog_func", "map_idr", "used_maps"},
};

const char *kscan_source_name(kscan_kind_t kind, unsigned src) {
    if ((unsigned) kind > KSCAN_BPF_MAP || src >= KSCAN_SOURCES || !NAMES[kind][src]) return "?";
    return NAMES[kind][src];
}
