#ifndef ROOTVIEW_KWALK_H
#define ROOTVIEW_KWALK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "kern/prof/kprof.h"

/* reading many kernel objects at once: a page cache scoped to one pause
 * window, scatter-gather and whole-struct reads, and walkers for the
 * kernel's linked structures - list_head, hlist, per-cpu, idr/xarray.
 *
 * every walker treats guest memory as hostile. a node pointer has to be a
 * canonical upper-half address, a node seen twice is a cycle, and a walk
 * stops at its node cap or its time budget, so a corrupted or malicious
 * structure ends a walk with an error rather than a hang. */

/* hard ceilings: a caller's max is clamped to these */
#define KWALK_MAX_NODES (1u << 20)
#define KWALK_MAX_CACHE_PAGES (1u << 16) /* 256MiB */
#define KWALK_MAX_STRUCT (1u << 16)

#define KWALK_DEFAULT_CACHE_PAGES 4096 /* 16MiB */
#define KWALK_DEFAULT_BUDGET_MS 2000

typedef struct {
    uint64_t va;  /* page-aligned */
    bool ok;      /* false: slot empty */
    unsigned char *data;
} kwalk_page_t;

typedef struct {
    const kprof_t *kp;   /* borrowed */
    uint32_t budget_ms;  /* per walk; 0 means no limit */

    /* the page cache: only live between kwalk_begin and kwalk_end, since
     * pages read while the guest runs go stale the moment they're read */
    bool in_window;
    kwalk_page_t *pages; /* open addressing on va */
    size_t cap, used, max_pages;
    uint64_t hits, misses;
} kwalk_t;

/* max_pages 0 takes the default; the cache is allocated on first use */
void kwalk_init(kwalk_t *w, const kprof_t *kp, size_t max_pages);
void kwalk_free(kwalk_t *w);

/* the snapshot window: begin pauses the guest and starts an empty cache,
 * end drops the cache and resumes. reads outside a window go straight to
 * the guest. a failed end still drops the cache. */
int kwalk_begin(kwalk_t *w, char *err, size_t err_len);
int kwalk_end(kwalk_t *w, char *err, size_t err_len);

/* kprof_read through the cache when in a window */
int kwalk_read(kwalk_t *w, uint64_t va, void *buf, size_t len, char *err, size_t err_len);

typedef struct {
    uint64_t va;
    void *buf;
    size_t len;
    int rc; /* out: 0 or -1 */
} kwalk_iov_t;

/* reads each iov independently, so one bad pointer doesn't sink the rest.
 * returns how many failed; err holds the first failure. */
size_t kwalk_read_many(kwalk_t *w, kwalk_iov_t *iov, size_t n, char *err, size_t err_len);

/* reads a whole struct named by type (as kfield_resolve takes it) into buf.
 * *size gets its btf size, which must fit buf_len and KWALK_MAX_STRUCT. */
int kwalk_read_struct(kwalk_t *w, const char *type, uint64_t va, void *buf, size_t buf_len, size_t *size, char *err,
                      size_t err_len);

/* a canonical upper-half (kernel) address under 4-level paging */
static inline bool kwalk_kernel_va(uint64_t va) {
    return (va >> 47) == 0x1ffff;
}

/* the containers on a list_head list, head excluded: head is the address of
 * the list_head that anchors the list (e.g. &init_task.tasks), and member
 * the list_head's path inside type ("tasks"). out gets each container's
 * address, in list order. fails on a non-canonical or unreadable node, a
 * cycle that doesn't come back to head, more than max nodes, or the budget. */
int kwalk_list(kwalk_t *w, uint64_t head, const char *type, const char *member, uint64_t *out, size_t max, size_t *n,
               char *err, size_t err_len);

/* the same for an hlist: head is an hlist_head, member an hlist_node, and
 * the list ends at a NULL next */
int kwalk_hlist(kwalk_t *w, uint64_t head, const char *type, const char *member, uint64_t *out, size_t max, size_t *n,
                char *err, size_t err_len);

/* kwalk_list and kwalk_hlist with the link's offset in its container given
 * directly, for links BTF can't name as a plain member (pid_links[0]) */
int kwalk_list_off(kwalk_t *w, uint64_t head, uint64_t off, uint64_t *out, size_t max, size_t *n, char *err,
                   size_t err_len);
int kwalk_hlist_off(kwalk_t *w, uint64_t head, uint64_t off, uint64_t *out, size_t max, size_t *n, char *err,
                    size_t err_len);

/* the rb_nodes of the rb_root at root, in order (leftmost first): out gets
 * each struct rb_node's own address, and the caller subtracts the node's
 * offset in its container. every child has to name its parent in
 * __rb_parent_color, and the tree can be no deeper than an rb-tree of max
 * nodes could be, so a cycle or a hand-built list can't pass as a tree. */
#define KWALK_RB_MAX_DEPTH 96
int kwalk_rbtree(kwalk_t *w, uint64_t root, uint64_t *out, size_t max, size_t *n, char *err, size_t err_len);

/* cpu's copy of the per-cpu variable sym: sym's address plus
 * __per_cpu_offset[cpu]. cpu has to be below nr_cpu_ids. */
int kwalk_percpu_addr(kwalk_t *w, const char *sym, unsigned cpu, uint64_t *addr, char *err, size_t err_len);
int kwalk_nr_cpus(kwalk_t *w, unsigned *n, char *err, size_t err_len);

typedef struct {
    uint64_t id;
    uint64_t ptr;
} kwalk_idr_entry_t;

/* the (id, pointer) pairs of the struct idr at idr, in id order: decodes the
 * xarray under it, skipping the zero entries that reserve an id. every node
 * has to name the node it was reached from as its parent, at a shift one
 * level down, or the walk fails. */
int kwalk_idr(kwalk_t *w, uint64_t idr, kwalk_idr_entry_t *out, size_t max, size_t *n, char *err, size_t err_len);

#endif
