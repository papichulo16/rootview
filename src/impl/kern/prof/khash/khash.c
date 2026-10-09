#include "kern/prof/khash.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"

#define FAIL(...)                                                                                                      \
    do {                                                                                                               \
        if (err) snprintf(err, err_len, __VA_ARGS__);                                                                  \
        return -1;                                                                                                     \
    } while (0)

#define PAGE_MASK ((uint64_t) KHASH_PAGE_SIZE - 1)

static const char *const BOUNDS[KHASH_REGIONS][2] = {
    [KHASH_TEXT] = {"_stext", "_etext"},
    [KHASH_RODATA] = {"__start_rodata", "__end_rodata"},
};

const char *khash_region_name(khash_region_id_t region) {
    return region == KHASH_TEXT ? "text" : region == KHASH_RODATA ? "rodata" : "?";
}

const char *khash_change_name(khash_change_kind_t kind) {
    switch (kind) {
    case KHASH_MODIFIED: return "modified";
    case KHASH_UNREADABLE: return "unreadable";
    case KHASH_READABLE: return "readable";
    }
    return "?";
}

/* both regions from kallsyms, checked to be inside the image, in order and
 * not absurdly long */
static int regions(const kprof_t *kp, khash_region_t reg[KHASH_REGIONS], size_t *total, char *err, size_t err_len) {
    *total = 0;
    for (int r = 0; r < KHASH_REGIONS; r++) {
        const ksym_t *s = ksym_by_name(&kp->ksym, BOUNDS[r][0]), *e = ksym_by_name(&kp->ksym, BOUNDS[r][1]);
        if (!s || !e) FAIL("no %s symbol", s ? BOUNDS[r][1] : BOUNDS[r][0]);
        if (s->addr >= e->addr) FAIL("%s 0x%016" PRIx64 " isn't below %s 0x%016" PRIx64, BOUNDS[r][0], s->addr,
                                     BOUNDS[r][1], e->addr);
        if (s->addr < kp->img.start || e->addr > kp->img.end)
            FAIL("%s [0x%016" PRIx64 ", 0x%016" PRIx64 ") is outside the image [0x%016" PRIx64 ", 0x%016" PRIx64 ")",
                 khash_region_name(r), s->addr, e->addr, kp->img.start, kp->img.end);
        if (r > 0 && s->addr < reg[r - 1].end) FAIL("%s overlaps %s", khash_region_name(r), khash_region_name(r - 1));
        uint64_t n = ((e->addr + PAGE_MASK) & ~PAGE_MASK) - (s->addr & ~PAGE_MASK);
        n /= KHASH_PAGE_SIZE;
        if (n > KHASH_MAX_REGION_PAGES) FAIL("%s is %" PRIu64 " pages", khash_region_name(r), n);
        reg[r] = (khash_region_t) {.start = s->addr, .end = e->addr, .first = *total, .n = n};
        *total += n;
    }
    return 0;
}

typedef struct {
    const kmem_t *mem;
    const khash_region_t *reg;
    khash_page_t *pages; /* the region's own */
    unsigned char buf[KHASH_PAGE_SIZE];
} pass_t;

/* one leaf mapping: hashes every page of the region it covers. pages no
 * leaf covers stay !ok. */
static int hash_leaf(uint64_t va, uint64_t pa, uint64_t size, bool nx, void *ctx) {
    (void) nx;
    pass_t *p = ctx;
    uint64_t lo = va > p->reg->start ? va : p->reg->start;
    uint64_t hi = va + size < p->reg->end ? va + size : p->reg->end;
    while (lo < hi) {
        uint64_t next = (lo & ~PAGE_MASK) + KHASH_PAGE_SIZE;
        uint32_t len = (uint32_t) ((next < hi ? next : hi) - lo);
        khash_page_t *pg = &p->pages[((lo & ~PAGE_MASK) - (p->reg->start & ~PAGE_MASK)) / KHASH_PAGE_SIZE];
        if (kmem_read_pa(p->mem, pa + (lo - va), p->buf, len, NULL, 0) == 0) {
            sha256(p->buf, len, pg->hash);
            pg->ok = true;
        }
        lo += len;
    }
    return 0;
}

static int hash_region(const kprof_t *kp, const khash_region_t *reg, khash_page_t *pages, char *err,
                       size_t err_len) {
    for (size_t i = 0; i < reg->n; i++) {
        uint64_t va = (reg->start & ~PAGE_MASK) + i * KHASH_PAGE_SIZE, end = va + KHASH_PAGE_SIZE;
        if (va < reg->start) va = reg->start;
        if (end > reg->end) end = reg->end;
        pages[i] = (khash_page_t) {.va = va, .len = (uint32_t) (end - va)};
    }
    pass_t *p = malloc(sizeof(*p)); /* the buffer's a page: keep it off the stack */
    if (!p) FAIL("out of memory");
    *p = (pass_t) {.mem = &kp->target.mem, .reg = reg, .pages = pages};
    /* a page is covered by one leaf, so there can't be more leaves than pages */
    int rc = pt_for_each_page(&kp->target.mem, &kp->root, reg->start, reg->end, reg->n, hash_leaf, p, err, err_len);
    free(p);
    return rc;
}

int khash_snapshot(const kprof_t *kp, khash_baseline_t **out, char *err, size_t err_len) {
    *out = NULL;
    khash_region_t reg[KHASH_REGIONS];
    size_t n;
    if (regions(kp, reg, &n, err, err_len) != 0) return -1;
    khash_baseline_t *b = calloc(1, sizeof(*b) + n * sizeof(b->pages[0]));
    if (!b) FAIL("out of memory");
    memcpy(b->region, reg, sizeof(reg));
    b->n = n;

    if (kprof_pause(kp, err, err_len) != 0) {
        free(b);
        return -1;
    }
    int rc = 0;
    for (int r = 0; r < KHASH_REGIONS && rc == 0; r++) {
        char e[256] = "";
        if (hash_region(kp, &reg[r], b->pages + reg[r].first, e, sizeof(e)) != 0) {
            if (err) snprintf(err, err_len, "%s: %s", khash_region_name(r), e);
            rc = -1;
        }
    }
    char rerr[256];
    if (kprof_resume(kp, rerr, sizeof(rerr)) != 0 && rc == 0) {
        if (err) snprintf(err, err_len, "resume: %s", rerr);
        rc = -1;
    }
    if (rc != 0) {
        free(b);
        return -1;
    }
    for (size_t i = 0; i < n; i++) b->unreadable += !b->pages[i].ok;
    *out = b;
    return 0;
}

int khash_baseline(kprof_t *kp, char *err, size_t err_len) {
    khash_baseline_t *b;
    if (khash_snapshot(kp, &b, err, err_len) != 0) return -1;
    free(kp->hash);
    kp->hash = b;
    return 0;
}

int khash_diff(kprof_t *kp, khash_diff_t *d, char *err, size_t err_len) {
    *d = (khash_diff_t) {0};
    if (!kp->hash) {
        if (khash_baseline(kp, err, err_len) != 0) return -1;
        *d = (khash_diff_t) {.baselined = true, .pages = kp->hash->n, .unreadable = kp->hash->unreadable};
        return 0;
    }
    const khash_baseline_t *old = kp->hash;
    khash_baseline_t *now;
    if (khash_snapshot(kp, &now, err, err_len) != 0) return -1;
    if (now->n != old->n || memcmp(now->region, old->region, sizeof(now->region)) != 0) {
        free(now);
        FAIL("the regions moved since the baseline: it was taken over another kernel");
    }
    d->pages = now->n;
    d->unreadable = now->unreadable;

    size_t cap = 0;
    for (size_t i = 0; i < now->n; i++) {
        const khash_page_t *a = &old->pages[i], *b = &now->pages[i];
        if (a->ok == b->ok && (!a->ok || memcmp(a->hash, b->hash, sizeof(a->hash)) == 0)) continue;
        if (d->n == cap) {
            cap = cap ? cap * 2 : 16;
            khash_change_t *c = realloc(d->changes, cap * sizeof(*c));
            if (!c) {
                free(now);
                khash_diff_free(d);
                FAIL("out of memory");
            }
            d->changes = c;
        }
        khash_change_t *c = &d->changes[d->n++];
        *c = (khash_change_t) {
            .kind = !b->ok ? KHASH_UNREADABLE : !a->ok ? KHASH_READABLE : KHASH_MODIFIED,
            .region = i >= now->region[KHASH_RODATA].first ? KHASH_RODATA : KHASH_TEXT,
            .index = i,
            .va = b->va,
            .len = b->len,
        };
        memcpy(c->before, a->hash, sizeof(c->before));
        memcpy(c->after, b->hash, sizeof(c->after));
        const ksym_t *s = ksym_by_addr(&kp->ksym, b->va, &c->sym_off);
        c->sym = s ? s->name : NULL;
    }
    free(now);
    return 0;
}

void khash_diff_free(khash_diff_t *d) {
    free(d->changes);
    d->changes = NULL;
    d->n = 0;
}
