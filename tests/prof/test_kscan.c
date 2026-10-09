/* kscan tests: the object table on its own (dedup by address, bits from
 * several sources, rehashing), then kscan_tasks over each fixture with a
 * mem.raw - every source runs, agrees with ps and with each other - and
 * again with one task hidden the way a rootkit does it: unlinked from
 * init_task.tasks, from its struct pid, and from both. each time exactly
 * that address loses exactly those bits, and every other task is as it was. */
#include <inttypes.h>

#include "../../src/impl/kern/prof/scan/kscan_priv.h"
#include "fixture.h"
#include "kern/prof/kwalk.h"

/* ---- a kmem_t that patches 8-byte words over the dump ---- */

typedef struct {
    kmem_t base;
    struct {
        uint64_t pa, val;
    } patch[4];
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

static void print_sources(const kscan_result_t *r) {
    for (unsigned s = 0; s < 5; s++)
        printf("  %-10s %4zu%s%s\n", kscan_source_name(KSCAN_TASK, s), r->source_count[s],
               r->ran_mask & BIT(s) ? "" : "  FAILED: ", r->ran_mask & BIT(s) ? "" : r->source_err[s]);
}

static void test_clean(kwalk_t *w, const int *pids, int npids, kscan_result_t *r) {
    char err[512];
    if (kscan_tasks(w, r, err, sizeof(err)) != 0) {
        CHECK(0, "kscan_tasks: %s", err);
        return;
    }
    print_sources(r);
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

/* list_del(&task->tasks): prev->next = next, next->prev = prev */
static int hide_from_list(kprof_t *kp, kwalk_t *w, uint64_t task, overlay_t *o, char *err, size_t err_len) {
    uint64_t off, next, prev;
    if (off_of(kp, "task_struct", "tasks", &off, err, err_len) != 0 ||
        kwalk_read(w, task + off, &next, 8, err, err_len) != 0 ||
        kwalk_read(w, task + off + 8, &prev, 8, err, err_len) != 0)
        return -1;
    return patch(kp, o, prev, next, err, err_len) != 0 || patch(kp, o, next + 8, prev, err, err_len) != 0 ? -1 : 0;
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

/* scans with o over the dump and checks that exactly the victim changed:
 * it lost the bits in drop and nothing else, and every other object kept
 * the mask it had in the clean scan */
static void check_hidden(kprof_t *kp, kwalk_t *w, const kscan_result_t *clean, const kscan_object_t *victim,
                         overlay_t *o, uint32_t drop, const char *what) {
    char err[512];
    kmem_t base = kp->target.mem;
    o->base = base;
    kp->target.mem = (kmem_t) {.read_pa = overlay_read, .ctx = o};
    kscan_result_t r;
    int rc = kscan_tasks(w, &r, err, sizeof(err));
    kp->target.mem = base;
    if (rc != 0) {
        CHECK(0, "%s: kscan_tasks: %s", what, err);
        return;
    }
    CHECK(r.ran_mask == TASK_ALL, "%s: ran_mask %#x", what, r.ran_mask);
    CHECK(r.n == clean->n, "%s: %zu tasks, clean had %zu", what, r.n, clean->n);
    const kscan_object_t *t = kscan_find(&r, KSCAN_TASK, victim->addr);
    uint32_t want = victim->source_mask & ~drop;
    CHECK(t && t->source_mask == want && t->id == victim->id, "%s: pid %" PRId64 " %s, mask %#x, want %#x", what,
          victim->id, t ? "found" : "lost", t ? t->source_mask : 0, want);
    size_t changed = 0;
    for (size_t i = 0; i < clean->n; i++) {
        const kscan_object_t *c = &clean->objs[i], *h = kscan_find(&r, KSCAN_TASK, c->addr);
        if (c->addr != victim->addr && (!h || h->source_mask != c->source_mask)) changed++;
    }
    CHECK(!changed, "%s: %zu other tasks changed", what, changed);
    printf("  %s: pid %" PRId64 " (%s) mask %#x -> %#x, %zu others unchanged\n", what, victim->id, victim->name,
           victim->source_mask, t ? t->source_mask : 0, clean->n - 1 - changed);
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
    check_hidden(kp, w, clean, v, &list, BIT(KSCAN_SRC_TASK_LIST), "off the task list");
    check_hidden(kp, w, clean, v, &idr, BIT(KSCAN_SRC_PID_IDR), "out of the pid idr");
    /* off both, it's still reached through its parent and its thread group */
    check_hidden(kp, w, clean, v, &both, BIT(KSCAN_SRC_TASK_LIST) | BIT(KSCAN_SRC_PID_IDR), "off both");
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
