/* kscan tests: the object table on its own (dedup by address, bits from
 * several sources, rehashing), then kscan_tasks over each fixture with a
 * mem.raw - every source runs, agrees with ps and with each other - and
 * again with one task unlinked from init_task.tasks the way a rootkit does
 * it, which has to leave the same address found by every other source. */
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

/* list_del(&victim->tasks) by patching prev->next and next->prev */
static void test_hidden(kprof_t *kp, kwalk_t *w, const kscan_result_t *clean) {
    char err[512];
    kfield_t f;
    if (kfield_resolve(&kp->btf, "task_struct", "tasks", &f, err, sizeof(err)) != 0) {
        CHECK(0, "%s", err);
        return;
    }
    /* a thread group leader other than init and swapper, found by every
     * source but the runqueue */
    const kscan_object_t *victim = NULL;
    uint32_t want = TASK_ALL & ~BIT(KSCAN_SRC_RUNQUEUE);
    for (size_t i = 0; i < clean->n && !victim; i++) {
        const kscan_object_t *o = &clean->objs[i];
        if ((o->flags & KSCAN_TASK_LEADER) && !(o->flags & KSCAN_TASK_IDLE) && o->id > 1 &&
            (o->source_mask & want) == want)
            victim = o;
    }
    if (!victim) {
        printf("  hide: SKIP (no task on every source)\n");
        return;
    }
    uint64_t link = victim->addr + f.offset, next, prev, pa_prev_next, pa_next_prev;
    if (kwalk_read(w, link, &next, 8, err, sizeof(err)) != 0 || kwalk_read(w, link + 8, &prev, 8, err, sizeof(err)) ||
        pt_translate(&kp->target.mem, &kp->root, prev, &pa_prev_next, NULL, err, sizeof(err)) != 0 ||
        pt_translate(&kp->target.mem, &kp->root, next + 8, &pa_next_prev, NULL, err, sizeof(err)) != 0) {
        CHECK(0, "hide: %s", err);
        return;
    }
    uint64_t addr = victim->addr;
    int64_t pid = victim->id;
    char name[KSCAN_NAME_MAX];
    snprintf(name, sizeof(name), "%s", victim->name);

    overlay_t o = {.base = kp->target.mem, .patch = {{pa_prev_next, next}, {pa_next_prev, prev}}, .n = 2};
    kp->target.mem = (kmem_t) {.read_pa = overlay_read, .ctx = &o};
    kscan_result_t r;
    if (kscan_tasks(w, &r, err, sizeof(err)) != 0) {
        CHECK(0, "kscan_tasks (hidden): %s", err);
    } else {
        const kscan_object_t *t = kscan_find(&r, KSCAN_TASK, addr);
        CHECK(r.ran_mask == TASK_ALL, "hidden: ran_mask %#x", r.ran_mask);
        CHECK(r.n == clean->n, "hidden: %zu tasks, clean had %zu", r.n, clean->n);
        CHECK(t && !(t->source_mask & BIT(KSCAN_SRC_TASK_LIST)) && (t->source_mask & BIT(KSCAN_SRC_PID_IDR)) &&
                  (t->source_mask & BIT(KSCAN_SRC_CHILDREN)) && t->id == pid,
              "hidden pid %" PRId64 ": %s, mask %#x", pid, t ? "found" : "lost", t ? t->source_mask : 0);
        printf("  hid pid %" PRId64 " (%s) from the task list: mask %#x\n", pid, name, t ? t->source_mask : 0);
        kscan_free(&r);
    }
    kp->target.mem = o.base;
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
