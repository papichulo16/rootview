#include "kern/prof/kwalk.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "kern/prof/kfield.h"

#define FAIL(...)                                                                                                      \
    do {                                                                                                               \
        if (err) snprintf(err, err_len, __VA_ARGS__);                                                                  \
        return -1;                                                                                                     \
    } while (0)

#define PAGE 4096ull

/* ---- page cache ---- */

void kwalk_init(kwalk_t *w, const kprof_t *kp, size_t max_pages) {
    if (max_pages == 0) max_pages = KWALK_DEFAULT_CACHE_PAGES;
    if (max_pages > KWALK_MAX_CACHE_PAGES) max_pages = KWALK_MAX_CACHE_PAGES;
    *w = (kwalk_t) {.kp = kp, .budget_ms = KWALK_DEFAULT_BUDGET_MS, .max_pages = max_pages};
}

static void cache_drop(kwalk_t *w) {
    for (size_t i = 0; i < w->cap; i++) free(w->pages[i].data);
    free(w->pages);
    w->pages = NULL;
    w->cap = w->used = 0;
}

void kwalk_free(kwalk_t *w) {
    cache_drop(w);
    w->in_window = false;
}

int kwalk_begin(kwalk_t *w, char *err, size_t err_len) {
    if (w->in_window) FAIL("already in a snapshot window");
    if (kprof_pause(w->kp, err, err_len) != 0) return -1;
    cache_drop(w);
    w->hits = w->misses = 0;
    w->in_window = true;
    return 0;
}

int kwalk_end(kwalk_t *w, char *err, size_t err_len) {
    if (!w->in_window) FAIL("not in a snapshot window");
    cache_drop(w);
    w->in_window = false;
    return kprof_resume(w->kp, err, err_len);
}

static uint64_t hash64(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    return x;
}

/* the cached page holding va, reading it in on a miss; NULL when the cache
 * is full (the caller reads around it) or the page is unreadable (err set) */
static const unsigned char *cache_page(kwalk_t *w, uint64_t page, bool *full, char *err, size_t err_len) {
    *full = false;
    if (!w->pages) {
        size_t cap = 16;
        while (cap < w->max_pages * 2) cap <<= 1;
        if (!(w->pages = calloc(cap, sizeof(*w->pages)))) {
            *full = true;
            return NULL;
        }
        w->cap = cap;
    }
    size_t i = hash64(page) & (w->cap - 1);
    for (; w->pages[i].ok; i = (i + 1) & (w->cap - 1)) {
        if (w->pages[i].va == page) {
            w->hits++;
            return w->pages[i].data;
        }
    }
    w->misses++;
    unsigned char *data;
    if (w->used == w->max_pages || !(data = malloc(PAGE))) {
        *full = true;
        return NULL;
    }
    if (kprof_read(w->kp, page, data, PAGE, err, err_len) != 0) {
        free(data);
        return NULL;
    }
    w->pages[i] = (kwalk_page_t) {.va = page, .ok = true, .data = data};
    w->used++;
    return data;
}

int kwalk_read(kwalk_t *w, uint64_t va, void *buf, size_t len, char *err, size_t err_len) {
    if (!w->in_window) return kprof_read(w->kp, va, buf, len, err, err_len);
    if (va + len < va) FAIL("read of %zu bytes at 0x%016" PRIx64 " wraps", len, va);
    unsigned char *out = buf;
    while (len) {
        uint64_t page = va & ~(PAGE - 1), off = va - page;
        size_t chunk = PAGE - off < len ? (size_t) (PAGE - off) : len;
        bool full;
        const unsigned char *p = cache_page(w, page, &full, err, err_len);
        if (p) memcpy(out, p + off, chunk);
        else if (!full || kprof_read(w->kp, va, out, chunk, err, err_len) != 0) return -1;
        va += chunk, out += chunk, len -= chunk;
    }
    return 0;
}

size_t kwalk_read_many(kwalk_t *w, kwalk_iov_t *iov, size_t n, char *err, size_t err_len) {
    size_t failed = 0;
    char e[256];
    for (size_t i = 0; i < n; i++) {
        iov[i].rc = kwalk_read(w, iov[i].va, iov[i].buf, iov[i].len, e, sizeof(e));
        if (iov[i].rc != 0 && failed++ == 0 && err) snprintf(err, err_len, "%s", e);
    }
    return failed;
}

/* a struct or union by name, "struct " prefix and typedefs allowed */
static uint32_t find_struct(const btf_t *b, const char *type) {
    if (strncmp(type, "struct ", 7) == 0) type += 7;
    else if (strncmp(type, "union ", 6) == 0) type += 6;
    uint32_t id = btf_find(b, type, BTF_KIND_STRUCT);
    if (!id) id = btf_find(b, type, BTF_KIND_UNION);
    if (!id) id = btf_resolve(b, btf_find(b, type, BTF_KIND_TYPEDEF));
    return id;
}

int kwalk_read_struct(kwalk_t *w, const char *type, uint64_t va, void *buf, size_t buf_len, size_t *size, char *err,
                      size_t err_len) {
    uint32_t id = find_struct(&w->kp->btf, type);
    int64_t sz = id ? btf_size(&w->kp->btf, id) : -1;
    if (sz <= 0) FAIL("no struct %s", type);
    if ((uint64_t) sz > KWALK_MAX_STRUCT || (size_t) sz > buf_len)
        FAIL("struct %s is %" PRId64 " bytes, more than %zu", type, sz,
             buf_len < KWALK_MAX_STRUCT ? buf_len : (size_t) KWALK_MAX_STRUCT);
    if (size) *size = (size_t) sz;
    return kwalk_read(w, va, buf, (size_t) sz, err, err_len);
}

static int read_u64(kwalk_t *w, uint64_t va, uint64_t *v, char *err, size_t err_len) {
    return kwalk_read(w, va, v, sizeof(*v), err, err_len);
}

/* ---- walk limits: visited set, node cap, time budget ---- */

typedef struct {
    uint64_t *slots; /* open addressing, 0 is empty (0 is never a kernel va) */
    size_t cap;
    struct timespec start;
    uint32_t budget_ms;
    size_t steps;
} walk_t;

static int walk_start(walk_t *s, const kwalk_t *w, size_t max, char *err, size_t err_len) {
    size_t cap = 16;
    while (cap < (max + 1) * 2) cap <<= 1;
    *s = (walk_t) {.cap = cap, .budget_ms = w->budget_ms};
    if (!(s->slots = calloc(cap, sizeof(*s->slots)))) FAIL("out of memory for a %zu-node visited set", max);
    clock_gettime(CLOCK_MONOTONIC, &s->start);
    return 0;
}

static void walk_end(walk_t *s) {
    free(s->slots);
}

/* false if va was already visited */
static bool walk_visit(walk_t *s, uint64_t va) {
    size_t i = hash64(va) & (s->cap - 1);
    for (; s->slots[i]; i = (i + 1) & (s->cap - 1))
        if (s->slots[i] == va) return false;
    s->slots[i] = va;
    return true;
}

static bool walk_over_budget(walk_t *s) {
    if (!s->budget_ms || ++s->steps % 16) return false;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    uint64_t ms = (uint64_t) (now.tv_sec - s->start.tv_sec) * 1000 + (uint64_t) (now.tv_nsec / 1000000) -
                  (uint64_t) (s->start.tv_nsec / 1000000);
    return ms > s->budget_ms;
}

static size_t clamp_max(size_t max) {
    return max > KWALK_MAX_NODES ? KWALK_MAX_NODES : max;
}

/* ---- list_head and hlist ---- */

/* member's offset in type, checking it's a want (list_head, hlist_node) */
static int link_member(kwalk_t *w, const char *type, const char *member, const char *want, uint64_t *off, char *err,
                       size_t err_len) {
    const btf_t *b = &w->kp->btf;
    kfield_t f;
    btf_type_t t;
    if (kfield_resolve(b, type, member, &f, err, err_len) != 0) return -1;
    if (btf_type(b, btf_resolve(b, f.type), &t) != 0 || strcmp(t.name, want) != 0)
        FAIL("%s.%s is a %s, not a struct %s", type, member, t.name[0] ? t.name : "<anon>", want);
    *off = f.offset;
    return 0;
}

/* first: the first node, end: the value that ends the list (head for a
 * list_head list, 0 for an hlist). next is the first word of both node
 * types, so a node's next is read at the node itself. */
static int walk_links(kwalk_t *w, uint64_t head, uint64_t first, uint64_t end, uint64_t off, uint64_t *out,
                      size_t max, size_t *n, char *err, size_t err_len) {
    *n = 0;
    max = clamp_max(max);
    walk_t s;
    if (walk_start(&s, w, max, err, err_len) != 0) return -1;
    int rc = -1;
    uint64_t node = first;
    for (; node != end; (*n)++) {
        if (!kwalk_kernel_va(node)) {
            if (err) snprintf(err, err_len, "list 0x%016" PRIx64 ": node %zu is 0x%016" PRIx64 ", not a kernel address",
                              head, *n, node);
            goto out;
        }
        if (!walk_visit(&s, node)) {
            if (err) snprintf(err, err_len, "list 0x%016" PRIx64 ": node 0x%016" PRIx64 " seen twice (a cycle after %zu nodes)",
                              head, node, *n);
            goto out;
        }
        if (*n == max) {
            if (err) snprintf(err, err_len, "list 0x%016" PRIx64 ": more than %zu nodes", head, max);
            goto out;
        }
        if (walk_over_budget(&s)) {
            if (err) snprintf(err, err_len, "list 0x%016" PRIx64 ": %u ms budget ran out after %zu nodes", head,
                              s.budget_ms, *n);
            goto out;
        }
        out[*n] = node - off;
        char e[200];
        if (read_u64(w, node, &node, e, sizeof(e)) != 0) {
            if (err) snprintf(err, err_len, "list 0x%016" PRIx64 ": node %zu: %s", head, *n, e);
            goto out;
        }
    }
    rc = 0;
out:
    walk_end(&s);
    return rc;
}

int kwalk_list_off(kwalk_t *w, uint64_t head, uint64_t off, uint64_t *out, size_t max, size_t *n, char *err,
                   size_t err_len) {
    *n = 0;
    uint64_t first;
    if (!kwalk_kernel_va(head)) FAIL("list head 0x%016" PRIx64 " is not a kernel address", head);
    if (read_u64(w, head, &first, err, err_len) != 0) return -1;
    return walk_links(w, head, first, head, off, out, max, n, err, err_len);
}

int kwalk_hlist_off(kwalk_t *w, uint64_t head, uint64_t off, uint64_t *out, size_t max, size_t *n, char *err,
                    size_t err_len) {
    *n = 0;
    uint64_t first;
    if (!kwalk_kernel_va(head)) FAIL("hlist head 0x%016" PRIx64 " is not a kernel address", head);
    if (read_u64(w, head, &first, err, err_len) != 0) return -1;
    return walk_links(w, head, first, 0, off, out, max, n, err, err_len);
}

int kwalk_list(kwalk_t *w, uint64_t head, const char *type, const char *member, uint64_t *out, size_t max, size_t *n,
               char *err, size_t err_len) {
    *n = 0;
    uint64_t off;
    if (link_member(w, type, member, "list_head", &off, err, err_len) != 0) return -1;
    return kwalk_list_off(w, head, off, out, max, n, err, err_len);
}

int kwalk_hlist(kwalk_t *w, uint64_t head, const char *type, const char *member, uint64_t *out, size_t max, size_t *n,
                char *err, size_t err_len) {
    *n = 0;
    uint64_t off;
    if (link_member(w, type, member, "hlist_node", &off, err, err_len) != 0) return -1;
    return kwalk_hlist_off(w, head, off, out, max, n, err, err_len);
}

/* ---- rb-tree ---- */

/* struct rb_node: __rb_parent_color, rb_right, rb_left. the layout hasn't
 * moved since 2.6.x, but it's checked against BTF anyway. */
typedef struct {
    uint64_t parent_color, right, left;
} rb_raw_t;

static int rb_layout(kwalk_t *w, char *err, size_t err_len) {
    const btf_t *b = &w->kp->btf;
    kfield_t pc, r, l;
    if (kfield_resolve(b, "rb_node", "__rb_parent_color", &pc, err, err_len) != 0 ||
        kfield_resolve(b, "rb_node", "rb_right", &r, err, err_len) != 0 ||
        kfield_resolve(b, "rb_node", "rb_left", &l, err, err_len) != 0)
        return -1;
    if (pc.offset != 0 || r.offset != 8 || l.offset != 16) FAIL("struct rb_node isn't {parent_color, right, left}");
    return 0;
}

int kwalk_rbtree(kwalk_t *w, uint64_t root, uint64_t *out, size_t max, size_t *n, char *err, size_t err_len) {
    *n = 0;
    max = clamp_max(max);
    if (rb_layout(w, err, err_len) != 0) return -1;
    if (!kwalk_kernel_va(root)) FAIL("rb_root 0x%016" PRIx64 " is not a kernel address", root);
    uint64_t top;
    if (read_u64(w, root, &top, err, err_len) != 0) return -1;
    if (!top) return 0;

    walk_t s;
    if (walk_start(&s, w, max, err, err_len) != 0) return -1;
    /* iterative in-order: stack[i] is a node whose left subtree is being
     * walked, and parent[] what each must name as its parent */
    struct {
        uint64_t node;
        rb_raw_t raw;
    } stack[KWALK_RB_MAX_DEPTH];
    int depth = 0, rc = -1;
    uint64_t node = top, parent = 0;
    char e[200];
    for (;;) {
        while (node) {
            if (!kwalk_kernel_va(node)) {
                if (err) snprintf(err, err_len, "rb_root 0x%016" PRIx64 ": node 0x%016" PRIx64
                                  " is not a kernel address", root, node);
                goto out;
            }
            if (!walk_visit(&s, node)) {
                if (err) snprintf(err, err_len, "rb_root 0x%016" PRIx64 ": node 0x%016" PRIx64 " reached twice",
                                  root, node);
                goto out;
            }
            if (depth == KWALK_RB_MAX_DEPTH) {
                if (err) snprintf(err, err_len, "rb_root 0x%016" PRIx64 ": deeper than %d", root,
                                  KWALK_RB_MAX_DEPTH);
                goto out;
            }
            if (walk_over_budget(&s)) {
                if (err) snprintf(err, err_len, "rb_root 0x%016" PRIx64 ": %u ms budget ran out after %zu nodes",
                                  root, s.budget_ms, *n);
                goto out;
            }
            rb_raw_t raw;
            if (kwalk_read(w, node, &raw, sizeof(raw), e, sizeof(e)) != 0) {
                if (err) snprintf(err, err_len, "rb_root 0x%016" PRIx64 ": node 0x%016" PRIx64 ": %s", root, node, e);
                goto out;
            }
            if ((raw.parent_color & ~3ull) != parent) {
                if (err) snprintf(err, err_len, "rb_root 0x%016" PRIx64 ": node 0x%016" PRIx64 " names parent 0x%016"
                                  PRIx64 ", reached from 0x%016" PRIx64, root, node, (uint64_t) (raw.parent_color & ~3ull), parent);
                goto out;
            }
            stack[depth].node = node;
            stack[depth++].raw = raw;
            parent = node;
            node = raw.left;
        }
        if (!depth) break;
        depth--;
        if (*n == max) {
            if (err) snprintf(err, err_len, "rb_root 0x%016" PRIx64 ": more than %zu nodes", root, max);
            goto out;
        }
        out[(*n)++] = stack[depth].node;
        parent = stack[depth].node;
        node = stack[depth].raw.right;
    }
    rc = 0;
out:
    walk_end(&s);
    return rc;
}

/* ---- per-cpu ---- */

int kwalk_nr_cpus(kwalk_t *w, unsigned *n, char *err, size_t err_len) {
    const ksym_t *s = ksym_by_name(&w->kp->ksym, "nr_cpu_ids");
    if (!s) FAIL("no nr_cpu_ids symbol");
    uint32_t v;
    if (kwalk_read(w, s->addr, &v, sizeof(v), err, err_len) != 0) return -1;
    if (v == 0 || v > 8192) FAIL("nr_cpu_ids is %u", v);
    *n = v;
    return 0;
}

int kwalk_percpu_addr(kwalk_t *w, const char *sym, unsigned cpu, uint64_t *addr, char *err, size_t err_len) {
    const ksym_t *s = ksym_by_name(&w->kp->ksym, sym);
    const ksym_t *offs = ksym_by_name(&w->kp->ksym, "__per_cpu_offset");
    if (!s) FAIL("no %s symbol", sym);
    if (!offs) FAIL("no __per_cpu_offset symbol");
    unsigned nr;
    if (kwalk_nr_cpus(w, &nr, err, err_len) != 0) return -1;
    if (cpu >= nr) FAIL("cpu %u, but nr_cpu_ids is %u", cpu, nr);
    uint64_t off;
    if (read_u64(w, offs->addr + 8ull * cpu, &off, err, err_len) != 0) return -1;
    *addr = s->addr + off;
    if (!kwalk_kernel_va(*addr))
        FAIL("%s on cpu %u is 0x%016" PRIx64 " (offset 0x%016" PRIx64 "), not a kernel address", sym, cpu, *addr, off);
    return 0;
}

/* ---- idr / xarray ---- */

/* xarray entry encoding (include/linux/xarray.h): internal entries have
 * the low two bits 10; above 4096 they're nodes (node + 2), below the chunk
 * size siblings, and 256/257 retry and zero entries. a low bit of 1 is a
 * value entry, which an idr never stores. */
#define XA_INTERNAL(e) (((e) & 3) == 2)
#define XA_IS_NODE(e) (XA_INTERNAL(e) && (e) > 4096)
#define XA_IS_VALUE(e) ((e) & 1)

/* the visited set is sized for this many nodes: a full 64-ary tree under
 * it holds 4M ids, far past any real idr */
#define XA_MAX_NODES (KWALK_MAX_NODES / 16)

typedef struct {
    kwalk_t *w;
    walk_t s;
    kfield_t shift, offset, parent, slots;
    unsigned chunk_shift, chunk;
    unsigned char *buf; /* one xa_node */
    size_t node_size;
    uint64_t base; /* idr_base */
    kwalk_idr_entry_t *out;
    size_t max, n, nodes;
} xa_walk_t;

static int xa_field_u(xa_walk_t *x, const kfield_t *f, uint64_t *v) {
    kval_t kv;
    if (kfield_decode(&x->w->kp->btf, f, x->buf, x->node_size, &kv, NULL, 0) != 0) return -1;
    *v = kv.u;
    kval_free(&kv);
    return 0;
}

static int xa_node(xa_walk_t *x, uint64_t node, uint64_t parent, unsigned slot, int want_shift, uint64_t index,
                   char *err, size_t err_len) {
    if (!kwalk_kernel_va(node)) FAIL("xa_node 0x%016" PRIx64 " is not a kernel address", node);
    if (++x->nodes > XA_MAX_NODES) FAIL("more than %u xa_nodes", XA_MAX_NODES);
    if (!walk_visit(&x->s, node)) FAIL("xa_node 0x%016" PRIx64 " reached twice", node);
    if (walk_over_budget(&x->s)) FAIL("%u ms budget ran out after %zu xa_nodes", x->s.budget_ms, x->nodes);

    char e[200];
    if (kwalk_read(x->w, node, x->buf, x->node_size, e, sizeof(e)) != 0) FAIL("xa_node 0x%016" PRIx64 ": %s", node, e);
    uint64_t shift, offset, up;
    if (xa_field_u(x, &x->shift, &shift) || xa_field_u(x, &x->offset, &offset) || xa_field_u(x, &x->parent, &up))
        FAIL("xa_node 0x%016" PRIx64 ": undecodable", node);
    if (shift % x->chunk_shift || shift >= 64) FAIL("xa_node 0x%016" PRIx64 ": shift %" PRIu64, node, shift);
    if (want_shift >= 0 && shift != (uint64_t) want_shift)
        FAIL("xa_node 0x%016" PRIx64 ": shift %" PRIu64 " under a parent that wants %d", node, shift, want_shift);
    if (up != parent || (parent && offset != slot))
        FAIL("xa_node 0x%016" PRIx64 ": parent 0x%016" PRIx64 " slot %" PRIu64 ", reached from 0x%016" PRIx64
             " slot %u",
             node, up, offset, parent, slot);

    /* copy the slots out: the recursion reuses buf */
    uint64_t slots[256];
    memcpy(slots, x->buf + x->slots.offset, x->chunk * 8);
    for (unsigned i = 0; i < x->chunk; i++) {
        uint64_t e = slots[i], idx = index + ((uint64_t) i << shift);
        if (!e) continue;
        if (XA_IS_NODE(e)) {
            if (shift == 0) FAIL("xa_node 0x%016" PRIx64 ": a node in leaf slot %u", node, i);
            if (xa_node(x, e - 2, node, i, (int) (shift - x->chunk_shift), idx, err, err_len) != 0) return -1;
            continue;
        }
        if (XA_INTERNAL(e) || XA_IS_VALUE(e)) continue; /* sibling, retry, zero, value */
        if (x->n == x->max) FAIL("more than %zu idr entries", x->max);
        x->out[x->n++] = (kwalk_idr_entry_t) {.id = idx + x->base, .ptr = e};
    }
    return 0;
}

int kwalk_idr(kwalk_t *w, uint64_t idr, kwalk_idr_entry_t *out, size_t max, size_t *n, char *err, size_t err_len) {
    *n = 0;
    const btf_t *b = &w->kp->btf;
    xa_walk_t x = {.w = w, .out = out, .max = clamp_max(max)};
    kfield_t f_head, f_base;
    if (kfield_resolve(b, "idr", "idr_rt.xa_head", &f_head, err, err_len) != 0 ||
        kfield_resolve(b, "idr", "idr_base", &f_base, err, err_len) != 0 ||
        kfield_resolve(b, "xa_node", "shift", &x.shift, err, err_len) != 0 ||
        kfield_resolve(b, "xa_node", "offset", &x.offset, err, err_len) != 0 ||
        kfield_resolve(b, "xa_node", "parent", &x.parent, err, err_len) != 0 ||
        kfield_resolve(b, "xa_node", "slots", &x.slots, err, err_len) != 0)
        return -1;
    x.chunk = x.slots.size / 8;
    for (x.chunk_shift = 0; (1u << x.chunk_shift) < x.chunk; x.chunk_shift++);
    if (x.chunk < 2 || x.chunk > 256 || (1u << x.chunk_shift) != x.chunk)
        FAIL("xa_node.slots has %u entries, not a power of two up to 256", x.chunk);
    int64_t ns = btf_size(b, find_struct(b, "xa_node"));
    if (ns <= 0 || ns > KWALK_MAX_STRUCT) FAIL("xa_node is %" PRId64 " bytes", ns);
    x.node_size = (size_t) ns;
    if (x.slots.offset + x.chunk * 8ull > x.node_size) FAIL("xa_node.slots runs past the node");

    if (!kwalk_kernel_va(idr)) FAIL("idr 0x%016" PRIx64 " is not a kernel address", idr);
    uint64_t head;
    uint32_t base;
    if (read_u64(w, idr + f_head.offset, &head, err, err_len) != 0 ||
        kwalk_read(w, idr + f_base.offset, &base, sizeof(base), err, err_len) != 0)
        return -1;
    x.base = base;
    if (!head) return 0;
    if (!XA_IS_NODE(head)) {
        /* a lone entry at index 0 sits in the head itself */
        if (!XA_INTERNAL(head) && !XA_IS_VALUE(head)) {
            if (x.max == 0) FAIL("more than 0 idr entries");
            out[(*n)++] = (kwalk_idr_entry_t) {.id = base, .ptr = head};
        }
        return 0;
    }

    if (!(x.buf = malloc(x.node_size))) FAIL("out of memory");
    int rc = walk_start(&x.s, w, XA_MAX_NODES, err, err_len);
    if (rc == 0) {
        rc = xa_node(&x, head - 2, 0, 0, -1, 0, err, err_len);
        walk_end(&x.s);
    }
    free(x.buf);
    *n = x.n;
    return rc;
}
