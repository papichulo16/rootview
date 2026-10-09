/* kscan tests: the object table on its own (dedup by address, bits from
 * several sources, rehashing), then kscan_tasks over each fixture with a
 * mem.raw - every source runs, agrees with ps and with each other - and
 * again with one task hidden the way a rootkit does it: unlinked from
 * init_task.tasks, from its struct pid, and from both. then kscan_modules,
 * against kallsyms.gz, and one module unlinked from the list (poisoned, as
 * list_del leaves it), erased from one and both latch trees by rebuilding
 * them without it, from all three so only carving finds it, and with its
 * kallsyms emptied. each time exactly that address loses exactly those
 * bits (or gains that flag), and every other object is as it was. */
#include <inttypes.h>

#include "../../src/impl/kern/prof/scan/kscan_priv.h"
#include "fixture.h"
#include "kern/prof/kwalk.h"

/* ---- a kmem_t that patches 8-byte words over the dump ---- */

typedef struct {
    kmem_t base;
    struct {
        uint64_t pa, val;
    } patch[4096];
    int n;
} overlay_t;

static int overlay_read(void *ctx, uint64_t pa, void *buf, size_t len, char *err, size_t err_len) {
    overlay_t *o = ctx;
    if (kmem_read_pa(&o->base, pa, buf, len, err, err_len) != 0) return -1;
    for (int i = 0; i < o->n; i++)
        for (unsigned b = 0; b < 8; b++) {
            uint64_t at = o->patch[i].pa + b;
            if (at >= pa && at < pa + len) ((unsigned char *) buf)[at - pa] = (unsigned char) (o->patch[i].val >> (8 * b));
        }
    return 0;
}

/* ---- the table ---- */

static void test_table(void) {
    printf("table\n");
    char err[256];
    kscan_result_t r;
    if (kscan_start(&r, KSCAN_TASK, err, sizeof(err)) != 0) {
        CHECK(0, "kscan_start: %s", err);
        return;
    }
    /* enough to rehash several times; source 0 adds all, source 1 the odd ones */
    const size_t N = 5000;
    bool added;
    for (size_t i = 0; i < N; i++) {
        kscan_object_t *o = kscan_add(&r, KSCAN_TASK, 0xffff888000000000ull + i * 0x1000, 0, &added);
        CHECK(o && added, "add %zu", i);
    }
    for (size_t i = 1; i < N; i += 2) {
        kscan_object_t *o = kscan_add(&r, KSCAN_TASK, 0xffff888000000000ull + i * 0x1000, 1, &added);
        CHECK(o && !added, "re-add %zu made a new object", i);
    }
    CHECK(r.n == N, "%zu objects, want %zu", r.n, N);
    CHECK(r.source_count[0] == N && r.source_count[1] == N / 2, "counts %zu %zu", r.source_count[0],
          r.source_count[1]);
    size_t bad = 0;
    for (size_t i = 0; i < N; i++) {
        const kscan_object_t *o = kscan_find(&r, KSCAN_TASK, 0xffff888000000000ull + i * 0x1000);
        uint32_t want = (i & 1) ? 3u : 1u;
        bad += !o || o->source_mask != want || o->id != -1;
    }
    CHECK(!bad, "%zu objects with the wrong mask after rehashing", bad);
    CHECK(!kscan_find(&r, KSCAN_TASK, 0xdead), "found an address never added");
    CHECK(!kscan_find(&r, KSCAN_MODULE, 0xffff888000000000ull), "same address, other kind, found");
    /* the same address under another kind is a different object */
    CHECK(kscan_add(&r, KSCAN_MODULE, 0xffff888000000000ull, 0, &added) && added, "kind isn't part of the key");

    kscan_source_ran(&r, 0);
    kscan_source_ran(&r, 2);
    kscan_source_failed(&r, 2, "boom");
    CHECK(r.ran_mask == 1u && !strcmp(r.source_err[2], "boom"), "ran_mask %#x, err '%s'", r.ran_mask,
          r.source_err[2]);
    kscan_free(&r);
    CHECK(!kscan_find(&r, KSCAN_TASK, 0xffff888000000000ull), "found after free");
    CHECK(!strcmp(kscan_source_name(KSCAN_TASK, KSCAN_SRC_RUNQUEUE), "runqueue") &&
              !strcmp(kscan_source_name(KSCAN_TASK, 7), "?"),
          "source names");
}

/* ---- tasks over a fixture ---- */

static int ps_pids(const char *ps, int *pids, int max) {
    int n = 0;
    for (const char *l = ps; l && *l && n < max; l = strchr(l, '\n') ? strchr(l, '\n') + 1 : NULL)
        if (*l >= '0' && *l <= '9') pids[n++] = atoi(l);
    return n;
}

static const kscan_object_t *by_pid(const kscan_result_t *r, int64_t pid) {
    for (size_t i = 0; i < r->n; i++)
        if (r->objs[i].id == pid && !(r->objs[i].flags & KSCAN_UNREADABLE)) return &r->objs[i];
    return NULL;
}

#define BIT(s) (1u << (s))
#define TASK_ALL (BIT(KSCAN_SRC_TASK_LIST) | BIT(KSCAN_SRC_PID_IDR) | BIT(KSCAN_SRC_RUNQUEUE) | \
                  BIT(KSCAN_SRC_CHILDREN) | BIT(KSCAN_SRC_THREADS))
#define MOD_ALL (BIT(KSCAN_SRC_MOD_LIST) | BIT(KSCAN_SRC_MOD_TREE) | BIT(KSCAN_SRC_MOD_TREE_1) | \
                 BIT(KSCAN_SRC_MOD_CARVE))

static void print_sources(const kscan_result_t *r, uint32_t all) {
    for (unsigned s = 0; s < KSCAN_SOURCES; s++)
        if (all & BIT(s))
            printf("  %-12s %4zu%s%s\n", kscan_source_name(r->kind, s), r->source_count[s],
                   r->ran_mask & BIT(s) ? "" : "  FAILED: ", r->ran_mask & BIT(s) ? "" : r->source_err[s]);
}

static void test_clean(kwalk_t *w, const int *pids, int npids, kscan_result_t *r) {
    char err[512];
    if (kscan_tasks(w, r, err, sizeof(err)) != 0) {
        CHECK(0, "kscan_tasks: %s", err);
        return;
    }
    print_sources(r, TASK_ALL);
    CHECK(r->ran_mask == TASK_ALL, "ran_mask %#x", r->ran_mask);

    int missing = 0;
    for (int i = 0; i < npids; i++) {
        const kscan_object_t *o = by_pid(r, pids[i]);
        if (!o || !(o->source_mask & BIT(KSCAN_SRC_PID_IDR))) missing++;
    }
    CHECK(!missing, "%d ps pids not seen through the pid idr", missing);

    /* a clean guest: every leader on the list has a pid, everything with a
     * pid is in its thread group, and nothing is only on a runqueue */
    size_t unreadable = 0, list_no_idr = 0, idr_no_threads = 0, rq_only = 0;
    for (size_t i = 0; i < r->n; i++) {
        const kscan_object_t *o = &r->objs[i];
        uint32_t m = o->source_mask;
        unreadable += !!(o->flags & KSCAN_UNREADABLE);
        if (o->flags & KSCAN_TASK_IDLE) continue;
        list_no_idr += (m & BIT(KSCAN_SRC_TASK_LIST)) && !(m & BIT(KSCAN_SRC_PID_IDR));
        idr_no_threads += (m & BIT(KSCAN_SRC_PID_IDR)) && !(m & BIT(KSCAN_SRC_THREADS));
        rq_only += m == BIT(KSCAN_SRC_RUNQUEUE);
    }
    CHECK(!unreadable && !list_no_idr && !idr_no_threads && !rq_only,
          "unreadable %zu, list-not-idr %zu, idr-not-threads %zu, runqueue-only %zu", unreadable, list_no_idr,
          idr_no_threads, rq_only);
    const kscan_object_t *init = kscan_find(r, KSCAN_TASK, w->kp->init_task);
    CHECK(init && (init->flags & KSCAN_TASK_IDLE) && !strcmp(init->name, "swapper/0"), "init_task: %s",
          init ? init->name : "missing");
    printf("  %zu tasks\n", r->n);
}

/* ---- hiding a task, the way a rootkit does it, by patching the dump ---- */

/* a thread group leader other than init and swapper, found by every source
 * but the runqueue, or NULL */
static const kscan_object_t *pick_victim(const kscan_result_t *clean) {
    uint32_t want = TASK_ALL & ~BIT(KSCAN_SRC_RUNQUEUE);
    for (size_t i = 0; i < clean->n; i++) {
        const kscan_object_t *o = &clean->objs[i];
        if ((o->flags & KSCAN_TASK_LEADER) && !(o->flags & KSCAN_TASK_IDLE) && o->id > 1 &&
            (o->source_mask & want) == want)
            return o;
    }
    return NULL;
}

/* queues an 8-byte patch at va */
static int patch(kprof_t *kp, overlay_t *o, uint64_t va, uint64_t val, char *err, size_t err_len) {
    uint64_t pa;
    if (o->n == (int) (sizeof(o->patch) / sizeof(o->patch[0]))) {
        snprintf(err, err_len, "more than %d patches", o->n);
        return -1;
    }
    if (pt_translate(&kp->target.mem, &kp->root, va, &pa, NULL, err, err_len) != 0) return -1;
    o->patch[o->n].pa = pa;
    o->patch[o->n++].val = val;
    return 0;
}

static int off_of(kprof_t *kp, const char *type, const char *path, uint64_t *off, char *err, size_t err_len) {
    kfield_t f;
    if (kfield_resolve(&kp->btf, type, path, &f, err, err_len) != 0) return -1;
    *off = f.offset;
    return 0;
}

/* unlinks the list_head at link: prev->next = next, next->prev = prev, and
 * with poison the link's own pointers set the way list_del leaves them */
static int unlink_at(kprof_t *kp, kwalk_t *w, uint64_t link, bool poison, overlay_t *o, char *err, size_t err_len) {
    uint64_t next, prev;
    if (kwalk_read(w, link, &next, 8, err, err_len) != 0 || kwalk_read(w, link + 8, &prev, 8, err, err_len) != 0 ||
        patch(kp, o, prev, next, err, err_len) != 0 || patch(kp, o, next + 8, prev, err, err_len) != 0)
        return -1;
    if (poison && (patch(kp, o, link, 0xdead000000000100ull, err, err_len) != 0 ||
                   patch(kp, o, link + 8, 0xdead000000000122ull, err, err_len) != 0))
        return -1;
    return 0;
}

/* list_del(&task->tasks), the way most task-hiding rootkits leave it: the
 * task's own pointers untouched */
static int hide_from_list(kprof_t *kp, kwalk_t *w, uint64_t task, overlay_t *o, char *err, size_t err_len) {
    uint64_t off;
    if (off_of(kp, "task_struct", "tasks", &off, err, err_len) != 0) return -1;
    return unlink_at(kp, w, task + off, false, o, err, err_len);
}

/* hlist_del(&task->pid_links[PIDTYPE_PID]) out of its struct pid's
 * tasks[PIDTYPE_PID]: the pid stays in the idr, but no task hangs off it.
 * a leader is the first (only) entry, so the head takes the link's next. */
static int hide_from_idr(kprof_t *kp, kwalk_t *w, uint64_t task, overlay_t *o, char *err, size_t err_len) {
    uint64_t off_tpid, off_links, off_ptasks, pid, first, next;
    if (off_of(kp, "task_struct", "thread_pid", &off_tpid, err, err_len) != 0 ||
        off_of(kp, "task_struct", "pid_links", &off_links, err, err_len) != 0 ||
        off_of(kp, "pid", "tasks", &off_ptasks, err, err_len) != 0 ||
        kwalk_read(w, task + off_tpid, &pid, 8, err, err_len) != 0 ||
        kwalk_read(w, pid + off_ptasks, &first, 8, err, err_len) != 0 ||
        kwalk_read(w, task + off_links, &next, 8, err, err_len) != 0)
        return -1;
    if (first != task + off_links) {
        snprintf(err, err_len, "pid's first task is 0x%016" PRIx64 ", not this one", first);
        return -1;
    }
    return patch(kp, o, pid + off_ptasks, next, err, err_len);
}

typedef int (*scan_fn)(kwalk_t *w, kscan_result_t *r, char *err, size_t err_len);

/* scans with o over the dump and checks that exactly the victim changed:
 * it lost the bits in drop and nothing else, gained the flags in flags, and
 * every other object kept the mask and flags it had in the clean scan */
static void check_hidden(kprof_t *kp, kwalk_t *w, scan_fn scan, uint32_t all, const kscan_result_t *clean,
                         const kscan_object_t *victim, overlay_t *o, uint32_t drop, uint32_t flags, const char *what) {
    char err[512];
    kmem_t base = kp->target.mem;
    o->base = base;
    kp->target.mem = (kmem_t) {.read_pa = overlay_read, .ctx = o};
    kscan_result_t r;
    int rc = scan(w, &r, err, sizeof(err));
    kp->target.mem = base;
    if (rc != 0) {
        CHECK(0, "%s: scan: %s", what, err);
        return;
    }
    if (r.ran_mask != all) print_sources(&r, all);
    CHECK(r.ran_mask == all, "%s: ran_mask %#x", what, r.ran_mask);
    CHECK(r.n == clean->n, "%s: %zu objects, clean had %zu", what, r.n, clean->n);
    const kscan_object_t *t = kscan_find(&r, victim->kind, victim->addr);
    uint32_t want = victim->source_mask & ~drop, want_flags = victim->flags | flags;
    CHECK(t && t->source_mask == want && t->flags == want_flags && t->id == victim->id,
          "%s: %s %s, mask %#x want %#x, flags %#x want %#x", what, victim->name, t ? "found" : "lost",
          t ? t->source_mask : 0, want, t ? t->flags : 0, want_flags);
    size_t changed = 0;
    for (size_t i = 0; i < clean->n; i++) {
        const kscan_object_t *c = &clean->objs[i], *h = kscan_find(&r, c->kind, c->addr);
        if (c->addr != victim->addr && (!h || h->source_mask != c->source_mask || h->flags != c->flags)) changed++;
    }
    CHECK(!changed, "%s: %zu other objects changed", what, changed);
    printf("  %s: %" PRId64 " (%s) mask %#x -> %#x, flags %#x -> %#x, %zu others unchanged\n", what, victim->id,
           victim->name, victim->source_mask, t ? t->source_mask : 0, victim->flags, t ? t->flags : 0,
           clean->n - 1 - changed);
    kscan_free(&r);
}

static void test_hidden(kprof_t *kp, kwalk_t *w, const kscan_result_t *clean) {
    const kscan_object_t *v = pick_victim(clean);
    if (!v) {
        printf("  hide: SKIP (no task on every source)\n");
        return;
    }
    char err[512];
    overlay_t list = {0}, idr = {0}, both = {0};
    if (hide_from_list(kp, w, v->addr, &list, err, sizeof(err)) != 0 ||
        hide_from_idr(kp, w, v->addr, &idr, err, sizeof(err)) != 0 ||
        hide_from_list(kp, w, v->addr, &both, err, sizeof(err)) != 0 ||
        hide_from_idr(kp, w, v->addr, &both, err, sizeof(err)) != 0) {
        CHECK(0, "hide: %s", err);
        return;
    }
    check_hidden(kp, w, kscan_tasks, TASK_ALL, clean, v, &list, BIT(KSCAN_SRC_TASK_LIST), 0, "off the task list");
    check_hidden(kp, w, kscan_tasks, TASK_ALL, clean, v, &idr, BIT(KSCAN_SRC_PID_IDR), 0, "out of the pid idr");
    /* off both, it's still reached through its parent and its thread group */
    check_hidden(kp, w, kscan_tasks, TASK_ALL, clean, v, &both, BIT(KSCAN_SRC_TASK_LIST) | BIT(KSCAN_SRC_PID_IDR), 0,
                 "off both");
}

/* ---- modules ---- */

static unsigned char *gunzip(const char *dir, const char *name, const char *file, size_t *len) {
    char cmd[4200];
    snprintf(cmd, sizeof(cmd), "gzip -dc '%s/%s/%s' 2>/dev/null", dir, name, file);
    FILE *f = popen(cmd, "r");
    if (!f) return NULL;
    size_t cap = 1 << 23, n = 0, got;
    unsigned char *buf = malloc(cap + 1);
    while ((got = fread(buf + n, 1, cap - n, f)) > 0)
        if ((n += got) == cap) buf = realloc(buf, (cap *= 2) + 1);
    if (pclose(f) != 0 || n == 0) {
        free(buf);
        return NULL;
    }
    buf[n] = '\0';
    *len = n;
    return buf;
}

/* the distinct [module] names in kallsyms text, into names[], NUL-separated */
static int kallsyms_modules(const char *ks, char names[][KSCAN_NAME_MAX], int max) {
    int n = 0;
    for (const char *l = ks; l && *l; l = strchr(l, '\n') ? strchr(l, '\n') + 1 : NULL) {
        const char *end = strchr(l, '\n'), *open = memchr(l, '[', end ? (size_t) (end - l) : strlen(l));
        if (!open) continue;
        const char *close = strchr(open, ']');
        if (!close || (end && close > end) || close - open - 1 >= KSCAN_NAME_MAX) continue;
        char nm[KSCAN_NAME_MAX];
        memcpy(nm, open + 1, (size_t) (close - open - 1));
        nm[close - open - 1] = '\0';
        int i = 0;
        while (i < n && strcmp(names[i], nm)) i++;
        if (i == n && n < max) strcpy(names[n++], nm);
    }
    return n;
}

static const kscan_object_t *by_name(const kscan_result_t *r, const char *name) {
    for (size_t i = 0; i < r->n; i++)
        if (!strcmp(r->objs[i].name, name)) return &r->objs[i];
    return NULL;
}

static void test_modules_clean(kwalk_t *w, const char *dir, const char *name, kscan_result_t *r) {
    char err[512];
    if (kscan_modules(w, r, err, sizeof(err)) != 0) {
        CHECK(0, "kscan_modules: %s", err);
        return;
    }
    print_sources(r, MOD_ALL);
    CHECK(r->ran_mask == MOD_ALL, "ran_mask %#x", r->ran_mask);
    size_t len;
    char *ks = (char *) gunzip(dir, name, "kallsyms.gz", &len);
    static char names[512][KSCAN_NAME_MAX];
    int nnames = ks ? kallsyms_modules(ks, names, 512) : 0;
    free(ks);
    CHECK(nnames > 0, "no modules in kallsyms.gz");
    int missing = 0;
    for (int i = 0; i < nnames; i++) {
        const kscan_object_t *o = by_name(r, names[i]);
        if (!o) {
            printf("  %s: in kallsyms, not found\n", names[i]);
            missing++;
        }
    }
    /* collect.py loads msr for LSTAR after it saves kallsyms, so msr is the
     * one module the dump may have that kallsyms.gz doesn't */
    size_t extra = r->n - (size_t) (nnames - missing);
    CHECK(!missing && (extra == 0 || (extra == 1 && by_name(r, "msr"))),
          "%zu modules, kallsyms has %d, %d of those missing", r->n, nnames, missing);
    /* a clean guest: every module on every source, its text covered by its
     * own symbols */
    size_t partial = 0, odd = 0;
    for (size_t i = 0; i < r->n; i++) {
        const kscan_object_t *o = &r->objs[i];
        partial += o->source_mask != MOD_ALL;
        odd += o->flags != 0 || !o->u.module.text_size || !o->u.module.nsyms_in_text;
        int k = 0;
        while (k < nnames && strcmp(names[k], o->name)) k++;
        if (o->source_mask != MOD_ALL || o->flags || k == nnames)
            printf("  %s%s: mask %#x flags %#x state %u text %" PRIu64 " syms %u/%u\n", o->name,
                   k == nnames ? " (not in kallsyms)" : "", o->source_mask, o->flags, o->u.module.state,
                   o->u.module.text_size, o->u.module.nsyms_in_text, o->u.module.nsyms);
    }
    CHECK(!partial && !odd, "%zu modules not on every source, %zu with flags or no text symbols", partial, odd);
    printf("  %zu modules\n", r->n);
}

/* rebuilds mod_tree.root.tree[idx] as a balanced tree over every node but
 * the victim's: what a rootkit erasing itself from the latch tree leaves */
typedef struct {
    kprof_t *kp;
    overlay_t *o;
    const uint64_t *nodes;
    char *err;
    size_t err_len;
} rebuild_t;

static uint64_t build(rebuild_t *b, size_t lo, size_t hi, uint64_t parent, int *rc) {
    if (lo >= hi || *rc) return 0;
    size_t mid = lo + (hi - lo) / 2;
    uint64_t node = b->nodes[mid];
    uint64_t left = build(b, lo, mid, node, rc), right = build(b, mid + 1, hi, node, rc);
    /* rb_node: __rb_parent_color (black), rb_right, rb_left */
    if (!*rc && (patch(b->kp, b->o, node, parent | 1, b->err, b->err_len) != 0 ||
                 patch(b->kp, b->o, node + 8, right, b->err, b->err_len) != 0 ||
                 patch(b->kp, b->o, node + 16, left, b->err, b->err_len) != 0))
        *rc = -1;
    return node;
}

static int hide_from_tree(kprof_t *kp, kwalk_t *w, uint64_t mod, unsigned idx, overlay_t *o, char *err,
                          size_t err_len) {
    uint64_t sym, tree, mtn_mod, mtn_node;
    if (!ksym_by_name(&kp->ksym, "mod_tree")) {
        snprintf(err, err_len, "no mod_tree");
        return -1;
    }
    sym = ksym_by_name(&kp->ksym, "mod_tree")->addr;
    if (off_of(kp, "mod_tree_root", "root.tree", &tree, err, err_len) != 0 ||
        off_of(kp, "mod_tree_node", "mod", &mtn_mod, err, err_len) != 0 ||
        off_of(kp, "mod_tree_node", "node", &mtn_node, err, err_len) != 0)
        return -1;
    uint64_t root = sym + tree + idx * 8ull;
    static uint64_t all[4096], keep[4096];
    size_t n, k = 0;
    if (kwalk_rbtree(w, root, all, 4096, &n, err, err_len) != 0) return -1;
    for (size_t i = 0; i < n; i++) {
        uint64_t m;
        if (kwalk_read(w, all[i] - idx * 24ull - (mtn_node - mtn_mod), &m, 8, err, err_len) != 0) return -1;
        if (m != mod) keep[k++] = all[i];
    }
    if (k == n) {
        snprintf(err, err_len, "module 0x%016" PRIx64 " isn't in tree[%u]", mod, idx);
        return -1;
    }
    rebuild_t b = {kp, o, keep, err, err_len};
    int rc = 0;
    uint64_t top = build(&b, 0, k, 0, &rc);
    return rc != 0 ? -1 : patch(kp, o, root, top, err, err_len);
}

/* list_del(&mod->list), poisoned: what most module-hiding rootkits do */
static int hide_mod_from_list(kprof_t *kp, kwalk_t *w, uint64_t mod, overlay_t *o, char *err, size_t err_len) {
    uint64_t off;
    if (off_of(kp, "module", "list", &off, err, err_len) != 0) return -1;
    return unlink_at(kp, w, mod + off, true, o, err, err_len);
}

/* mod->kallsyms->num_symtab = 0: its symbols gone from /proc/kallsyms */
static int strip_kallsyms(kprof_t *kp, kwalk_t *w, uint64_t mod, overlay_t *o, char *err, size_t err_len) {
    uint64_t off_ks, off_num, ks, num;
    if (off_of(kp, "module", "kallsyms", &off_ks, err, err_len) != 0 ||
        off_of(kp, "mod_kallsyms", "num_symtab", &off_num, err, err_len) != 0 ||
        kwalk_read(w, mod + off_ks, &ks, 8, err, err_len) != 0 ||
        kwalk_read(w, ks + off_num, &num, 8, err, err_len) != 0)
        return -1;
    /* num_symtab is a u32: keep whatever shares its qword */
    return patch(kp, o, ks + off_num, num & ~0xffffffffull, err, err_len);
}

static void test_modules_hidden(kprof_t *kp, kwalk_t *w, const kscan_result_t *clean) {
    /* the last module found: on 5.15's fixture the only one */
    const kscan_object_t *v = NULL;
    for (size_t i = 0; i < clean->n; i++)
        if (clean->objs[i].source_mask == MOD_ALL && !clean->objs[i].flags) v = &clean->objs[i];
    if (!v) {
        printf("  hide module: SKIP (none on every source)\n");
        return;
    }
    char err[512];
    static overlay_t list, tree0, trees, all, syms;
    list.n = tree0.n = trees.n = all.n = syms.n = 0;
    if (hide_mod_from_list(kp, w, v->addr, &list, err, sizeof(err)) != 0 ||
        hide_from_tree(kp, w, v->addr, 0, &tree0, err, sizeof(err)) != 0 ||
        hide_from_tree(kp, w, v->addr, 0, &trees, err, sizeof(err)) != 0 ||
        hide_from_tree(kp, w, v->addr, 1, &trees, err, sizeof(err)) != 0 ||
        hide_mod_from_list(kp, w, v->addr, &all, err, sizeof(err)) != 0 ||
        hide_from_tree(kp, w, v->addr, 0, &all, err, sizeof(err)) != 0 ||
        hide_from_tree(kp, w, v->addr, 1, &all, err, sizeof(err)) != 0 ||
        strip_kallsyms(kp, w, v->addr, &syms, err, sizeof(err)) != 0) {
        CHECK(0, "hide module: %s", err);
        return;
    }
    check_hidden(kp, w, kscan_modules, MOD_ALL, clean, v, &list, BIT(KSCAN_SRC_MOD_LIST), 0, "off the module list");
    check_hidden(kp, w, kscan_modules, MOD_ALL, clean, v, &tree0, BIT(KSCAN_SRC_MOD_TREE), 0, "out of tree[0]");
    check_hidden(kp, w, kscan_modules, MOD_ALL, clean, v, &trees,
                 BIT(KSCAN_SRC_MOD_TREE) | BIT(KSCAN_SRC_MOD_TREE_1), 0, "out of both trees");
    /* off the list and out of the tree, only carving still finds it */
    check_hidden(kp, w, kscan_modules, MOD_ALL, clean, v, &all,
                 BIT(KSCAN_SRC_MOD_LIST) | BIT(KSCAN_SRC_MOD_TREE) | BIT(KSCAN_SRC_MOD_TREE_1), 0, "off all three");
    check_hidden(kp, w, kscan_modules, MOD_ALL, clean, v, &syms, 0, KSCAN_MOD_NO_TEXT_SYMS, "kallsyms stripped");
}

static void test_fixture(const char *dir, const char *name) {
    if (fixture_has_dump(dir, name) <= 0) return;
    printf("fixture %s: kscan\n", name);
    dump_ctx_t ctx;
    kprof_target_t target;
    kprof_t kp;
    if (fixture_kprof(dir, name, &ctx, &target, &kp) != 0) return;
    char *ps = fixture_file(dir, name, "ps", NULL);
    static int pids[8192];
    int npids = ps ? ps_pids(ps, pids, 8192) : 0;
    CHECK(npids > 0, "no ps");

    kwalk_t w;
    kwalk_init(&w, &kp, 0);
    kscan_result_t r = {0};
    test_clean(&w, pids, npids, &r);
    if (r.n) test_hidden(&kp, &w, &r);
    kscan_free(&r);
    test_modules_clean(&w, dir, name, &r);
    if (r.n) test_modules_hidden(&kp, &w, &r);
    kscan_free(&r);
    CHECK(ctx.pauses == ctx.resumes && ctx.pauses > 0, "%d pauses, %d resumes", ctx.pauses, ctx.resumes);

    kwalk_free(&w);
    kprof_free(&kp);
    kmem_close(&target.mem);
    free(ps);
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "tests/fixtures";
    test_table();
    for_each_fixture(dir, test_fixture);
    printf(failures ? "\n%d FAILED\n" : "\nall passed\n", failures);
    return failures ? 1 : 0;
}
