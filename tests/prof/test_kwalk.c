/* kwalk tests, over each fixture with a mem.raw: init_task.tasks through
 * kwalk_list against ps, the same walk cached in a snapshot window, the
 * list made hostile (a cycle, a wild pointer, a self-loop, too many nodes,
 * too slow) by patching the dump, an hlist, per-cpu runqueues, and the pid
 * idr against ps plus the bpf idrs against the ids their objects carry. */
#include <inttypes.h>
#include <unistd.h>

#include "fixture.h"
#include "kern/prof/kfield.h"
#include "kern/prof/kwalk.h"

/* ---- a kmem_t that patches 8-byte words over the dump, and can be slow ---- */

typedef struct {
    kmem_t base;
    struct {
        uint64_t pa, val;
    } patch[4];
    int n;
    unsigned delay_us;
} overlay_t;

static int overlay_read(void *ctx, uint64_t pa, void *buf, size_t len, char *err, size_t err_len) {
    overlay_t *o = ctx;
    if (o->delay_us) usleep(o->delay_us);
    if (kmem_read_pa(&o->base, pa, buf, len, err, err_len) != 0) return -1;
    for (int i = 0; i < o->n; i++)
        for (unsigned b = 0; b < 8; b++) {
            uint64_t at = o->patch[i].pa + b;
            if (at >= pa && at < pa + len) ((unsigned char *) buf)[at - pa] = (unsigned char) (o->patch[i].val >> (8 * b));
        }
    return 0;
}

/* ---- tasks ---- */

static uint64_t field_off(const kprof_t *kp, const char *type, const char *path) {
    kfield_t f;
    char err[256];
    if (kfield_resolve(&kp->btf, type, path, &f, err, sizeof(err)) != 0) {
        CHECK(0, "%s", err);
        return 0;
    }
    return f.offset;
}

static int64_t read_s32(kwalk_t *w, uint64_t va) {
    int32_t v = 0;
    kwalk_read(w, va, &v, sizeof(v), NULL, 0);
    return v;
}

static int ps_pids(const char *ps, int *pids, int max) {
    int n = 0;
    for (const char *l = ps; l && *l && n < max; l = strchr(l, '\n') ? strchr(l, '\n') + 1 : NULL)
        if (*l >= '0' && *l <= '9') pids[n++] = atoi(l);
    return n;
}

static bool has_pid(const int *pids, int n, int64_t pid) {
    for (int i = 0; i < n; i++)
        if (pids[i] == pid) return true;
    return false;
}

static void test_tasks(kwalk_t *w, const kprof_t *kp, const int *pids, int npids, uint64_t *tasks, size_t *ntasks) {
    char err[512];
    uint64_t off_tasks = field_off(kp, "task_struct", "tasks"), off_pid = field_off(kp, "task_struct", "pid");
    uint64_t head = kp->init_task + off_tasks;
    size_t n;
    if (kwalk_list(w, head, "task_struct", "tasks", tasks, 8192, &n, err, sizeof(err)) != 0) {
        CHECK(0, "kwalk_list: %s", err);
        *ntasks = 0;
        return;
    }
    *ntasks = n;
    size_t matched = 0;
    for (size_t i = 0; i < n; i++) matched += has_pid(pids, npids, read_s32(w, tasks[i] + off_pid));
    CHECK(n == (size_t) npids && matched == n, "%zu tasks, %zu in ps, ps has %d", n, matched, npids);
    printf("  kwalk_list init_task.tasks: %zu tasks, all in ps\n", n);

    /* the same walk in a snapshot window: equal, and the second pass is all hits */
    uint64_t again[8192];
    size_t n2;
    CHECK(kwalk_begin(w, err, sizeof(err)) == 0, "begin: %s", err);
    CHECK(kwalk_list(w, head, "task_struct", "tasks", again, 8192, &n2, err, sizeof(err)) == 0 && n2 == n &&
              !memcmp(again, tasks, n * 8),
          "cached walk differs: %s", err);
    uint64_t misses = w->misses;
    CHECK(kwalk_list(w, head, "task_struct", "tasks", again, 8192, &n2, err, sizeof(err)) == 0 && w->misses == misses,
          "second cached walk missed %" PRIu64 " times", w->misses - misses);
    printf("  in a window: %zu pages cached, second walk all hits\n", w->used);
    CHECK(kwalk_end(w, err, sizeof(err)) == 0 && w->used == 0 && !w->in_window, "end");
    CHECK(kwalk_end(w, err, sizeof(err)) != 0, "end outside a window accepted");

    /* read_struct and read_many */
    unsigned char buf[KWALK_MAX_STRUCT];
    size_t size;
    uint64_t off_comm = field_off(kp, "task_struct", "comm");
    CHECK(kwalk_read_struct(w, "task_struct", kp->init_task, buf, sizeof(buf), &size, err, sizeof(err)) == 0 &&
              !strcmp((char *) buf + off_comm, "swapper/0"),
          "read_struct init_task: %s", err);
    CHECK(kwalk_read_struct(w, "task_struct", kp->init_task, buf, 64, &size, err, sizeof(err)) != 0,
          "read_struct into 64 bytes accepted");
    char c1[16], c2[16];
    kwalk_iov_t iov[3] = {{kp->init_task + off_comm, c1, 16, 0},
                          {0x10, c2, 16, 0},
                          {n ? tasks[0] + off_comm : 0, c2, 16, 0}};
    CHECK(kwalk_read_many(w, iov, 3, err, sizeof(err)) == 1 && iov[0].rc == 0 && iov[1].rc != 0 && iov[2].rc == 0 &&
              !strcmp(c1, "swapper/0"),
          "read_many: %d %d %d", iov[0].rc, iov[1].rc, iov[2].rc);
}

/* ---- the same list, made hostile ---- */

static void test_corrupt(kprof_t *kp, kwalk_t *w, const uint64_t *tasks, size_t ntasks) {
    if (ntasks < 8) return;
    char err[512];
    uint64_t off = field_off(kp, "task_struct", "tasks"), head = kp->init_task + off;
    uint64_t victim = tasks[5] + off, pa;
    if (pt_translate(&kp->target.mem, &kp->root, victim, &pa, NULL, err, sizeof(err)) != 0) {
        CHECK(0, "translate: %s", err);
        return;
    }
    overlay_t o = {.base = kp->target.mem};
    kp->target.mem = (kmem_t) {.read_pa = overlay_read, .ctx = &o};
    static uint64_t out[8192];
    size_t n;

    static const struct {
        const char *what, *want;
    } cases[] = {
        {"cycle back to node 2", "seen twice"},
        {"self-loop", "seen twice"},
        {"wild pointer", "not a kernel address"},
        {"null next", "not a kernel address"},
    };
    uint64_t vals[] = {tasks[2] + off, victim, 0x4141414141414141ull, 0};
    for (size_t i = 0; i < 4; i++) {
        o.patch[0] = (typeof(o.patch[0])) {pa, vals[i]};
        o.n = 1;
        int rc = kwalk_list(w, head, "task_struct", "tasks", out, 8192, &n, err, sizeof(err));
        CHECK(rc != 0 && strstr(err, cases[i].want), "%s: rc %d, '%s'", cases[i].what, rc, err);
        printf("  %s: %s\n", cases[i].what, err);
    }
    o.n = 0;

    CHECK(kwalk_list(w, head, "task_struct", "tasks", out, 10, &n, err, sizeof(err)) != 0 &&
              strstr(err, "more than 10"),
          "node cap: '%s'", err);
    printf("  max 10: %s\n", err);

    /* every read 2ms with a 20ms budget: the walk gives up long before the end */
    o.delay_us = 2000;
    w->budget_ms = 20;
    CHECK(kwalk_list(w, head, "task_struct", "tasks", out, 8192, &n, err, sizeof(err)) != 0 && strstr(err, "budget"),
          "budget: '%s'", err);
    printf("  20ms budget: %s\n", err);
    w->budget_ms = KWALK_DEFAULT_BUDGET_MS;

    CHECK(kwalk_list(w, head, "task_struct", "comm", out, 8192, &n, err, sizeof(err)) != 0 && strstr(err, "list_head"),
          "comm as a list_head: '%s'", err);
    CHECK(kwalk_list(w, 0x1000, "task_struct", "tasks", out, 8192, &n, err, sizeof(err)) != 0, "user head accepted");
    kp->target.mem = o.base;
}

/* ---- hlist: every bucket of ucounts_hashtable, which holds init_ucounts ---- */

static void test_hlist(const kprof_t *kp, kwalk_t *w) {
    const ksym_t *tab = ksym_by_name(&kp->ksym, "ucounts_hashtable");
    const ksym_t *init = ksym_by_name(&kp->ksym, "init_ucounts");
    kfield_t f;
    btf_type_t t;
    if (!tab || !init || kfield_resolve(&kp->btf, "ucounts", "node", &f, NULL, 0) != 0 ||
        btf_type(&kp->btf, btf_resolve(&kp->btf, f.type), &t) != 0 || strcmp(t.name, "hlist_node") != 0) {
        printf("  hlist: SKIP (no ucounts_hashtable of hlist_nodes)\n");
        return;
    }
    /* the table runs to the next symbol */
    size_t idx = (size_t) (tab - kp->ksym.syms);
    uint64_t end = idx + 1 < kp->ksym.n ? kp->ksym.syms[idx + 1].addr : tab->addr + 8;
    size_t buckets = (size_t) (end - tab->addr) / 8, total = 0;
    if (buckets > 65536) buckets = 65536;
    bool found = false;
    char err[512];
    uint64_t out[1024];
    for (size_t b = 0; b < buckets; b++) {
        size_t n;
        if (kwalk_hlist(w, tab->addr + 8 * b, "ucounts", "node", out, 1024, &n, err, sizeof(err)) != 0) {
            CHECK(0, "bucket %zu: %s", b, err);
            return;
        }
        for (size_t i = 0; i < n; i++) found |= out[i] == init->addr;
        total += n;
    }
    CHECK(found, "init_ucounts not in ucounts_hashtable");
    printf("  kwalk_hlist ucounts_hashtable: %zu buckets, %zu entries, init_ucounts among them\n", buckets, total);
}

/* ---- per-cpu ---- */

static void test_percpu(const kprof_t *kp, kwalk_t *w, const char *dir, const char *name, const uint64_t *tasks,
                        size_t ntasks) {
    char err[512];
    unsigned nr;
    if (kwalk_nr_cpus(w, &nr, err, sizeof(err)) != 0) {
        CHECK(0, "nr_cpus: %s", err);
        return;
    }
    uint64_t off_curr = field_off(kp, "rq", "curr"), off_comm = field_off(kp, "task_struct", "comm");
    for (unsigned cpu = 0; cpu < nr; cpu++) {
        uint64_t rq, curr;
        char comm[17] = "";
        if (kwalk_percpu_addr(w, "runqueues", cpu, &rq, err, sizeof(err)) != 0 ||
            kwalk_read(w, rq + off_curr, &curr, 8, err, sizeof(err)) != 0 ||
            kwalk_read(w, curr + off_comm, comm, 16, err, sizeof(err)) != 0) {
            CHECK(0, "cpu %u: %s", cpu, err);
            continue;
        }
        /* curr is a task on the list, or an idle task (init_task on cpu 0) */
        bool known = curr == kp->init_task || !strncmp(comm, "swapper/", 8);
        for (size_t i = 0; i < ntasks && !known; i++) known = tasks[i] == curr;
        CHECK(known, "cpu %u: rq->curr 0x%016" PRIx64 " (%s) isn't a known task", cpu, curr, comm);
        printf("  cpu %u: runqueues 0x%016" PRIx64 ", curr %s\n", cpu, rq, comm);
    }
    uint64_t a;
    CHECK(kwalk_percpu_addr(w, "runqueues", nr, &a, err, sizeof(err)) != 0, "cpu %u accepted", nr);

    /* in kernel mode, GS base is cpu 0's __per_cpu_offset */
    char *regs = fixture_file(dir, name, "regs", NULL), *txt = fixture_file(dir, name, "regs.txt", NULL);
    uint64_t cpl = 3, off;
    const ksym_t *offs = ksym_by_name(&kp->ksym, "__per_cpu_offset");
    const char *gs = txt ? strstr(txt, "\nGS =") : NULL;
    if (regs && !regs_get(regs, "cpl", &cpl) && cpl == 0 && gs && offs &&
        kwalk_read(w, offs->addr, &off, 8, NULL, 0) == 0) {
        uint64_t base = strtoull(gs + 10, NULL, 16);
        CHECK(off == base, "__per_cpu_offset[0] 0x%016" PRIx64 ", GS base 0x%016" PRIx64, off, base);
        printf("  __per_cpu_offset[0] == GS base 0x%016" PRIx64 "\n", base);
    }
    free(regs);
    free(txt);
}

/* ---- idr ---- */

static void test_idr(kprof_t *kp, kwalk_t *w, const int *pids, int npids) {
    char err[512];
    static kwalk_idr_entry_t e[65536];
    size_t n;

    /* init_pid_ns.idr: id -> struct pid, whose numbers[0].nr is the id */
    const ksym_t *ns = ksym_by_name(&kp->ksym, "init_pid_ns");
    uint64_t off_idr = field_off(kp, "pid_namespace", "idr");
    uint64_t off_nr = field_off(kp, "pid", "numbers") + field_off(kp, "upid", "nr");
    if (!ns || kwalk_idr(w, ns->addr + off_idr, e, 65536, &n, err, sizeof(err)) != 0) {
        CHECK(0, "init_pid_ns.idr: %s", ns ? err : "no init_pid_ns");
        return;
    }
    size_t bad = 0, found = 0;
    for (size_t i = 0; i < n; i++) {
        bad += read_s32(w, e[i].ptr + off_nr) != (int64_t) e[i].id;
        if (i) bad += e[i].id <= e[i - 1].id;
    }
    for (int i = 0; i < npids; i++)
        for (size_t j = 0; j < n; j++)
            if (e[j].id == (uint64_t) pids[i]) {
                found++;
                break;
            }
    CHECK(n && !bad && found == (size_t) npids, "pid idr: %zu entries, %zu bad, %zu of %d ps pids", n, bad, found,
          npids);
    printf("  kwalk_idr init_pid_ns.idr: %zu pids (ids %" PRIu64 "..%" PRIu64 "), every ps pid among them\n", n,
           n ? e[0].id : 0, n ? e[n - 1].id : 0);

    /* the root node's first slot pointed back at the root itself */
    uint64_t head, pa;
    uint64_t idr = ns->addr + off_idr, off_slots = field_off(kp, "xa_node", "slots");
    kwalk_read(w, idr + field_off(kp, "idr", "idr_rt.xa_head"), &head, 8, NULL, 0);
    if ((head & 3) == 2 && head > 4096 &&
        pt_translate(&kp->target.mem, &kp->root, head - 2 + off_slots, &pa, NULL, NULL, 0) == 0) {
        overlay_t o = {.base = kp->target.mem, .patch = {{pa, head}}, .n = 1};
        kp->target.mem = (kmem_t) {.read_pa = overlay_read, .ctx = &o};
        int rc = kwalk_idr(w, idr, e, 65536, &n, err, sizeof(err));
        CHECK(rc != 0 && (strstr(err, "twice") || strstr(err, "parent")), "self-referencing xa_node: '%s'", err);
        printf("  xa_node slot 0 -> itself: %s\n", err);
        kp->target.mem = o.base;
    }

    /* prog_idr and map_idr: each object's own id agrees with its slot */
    static const struct {
        const char *sym, *type, *path;
    } bpf[] = {{"prog_idr", "bpf_prog_aux", "id"}, {"map_idr", "bpf_map", "id"}};
    for (size_t k = 0; k < 2; k++) {
        const ksym_t *s = ksym_by_name(&kp->ksym, bpf[k].sym);
        if (!s) {
            printf("  %s: SKIP (no symbol)\n", bpf[k].sym);
            continue;
        }
        if (kwalk_idr(w, s->addr, e, 65536, &n, err, sizeof(err)) != 0) {
            CHECK(0, "%s: %s", bpf[k].sym, err);
            continue;
        }
        uint64_t off_id = field_off(kp, bpf[k].type, bpf[k].path), off_aux = field_off(kp, "bpf_prog", "aux");
        bad = 0;
        for (size_t i = 0; i < n; i++) {
            uint64_t obj = e[i].ptr;
            if (k == 0 && kwalk_read(w, obj + off_aux, &obj, 8, NULL, 0) != 0) {
                bad++;
                continue;
            }
            bad += (uint64_t) read_s32(w, obj + off_id) != e[i].id;
        }
        CHECK(!bad, "%s: %zu of %zu ids disagree with their objects", bpf[k].sym, bad, n);
        printf("  kwalk_idr %s: %zu entries%s\n", bpf[k].sym, n, n ? ", ids match their objects" : "");
    }
}

static void test_fixture(const char *dir, const char *name) {
    if (fixture_has_dump(dir, name) <= 0) return;
    printf("fixture %s: kwalk\n", name);
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
    static uint64_t tasks[8192];
    size_t ntasks;
    test_tasks(&w, &kp, pids, npids, tasks, &ntasks);
    test_corrupt(&kp, &w, tasks, ntasks);
    test_hlist(&kp, &w);
    test_percpu(&kp, &w, dir, name, tasks, ntasks);
    test_idr(&kp, &w, pids, npids);
    CHECK(ctx.pauses == ctx.resumes, "%d pauses, %d resumes", ctx.pauses, ctx.resumes);

    kwalk_free(&w);
    kprof_free(&kp);
    kmem_close(&target.mem);
    free(ps);
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "tests/fixtures";
    for_each_fixture(dir, test_fixture);
    printf(failures ? "\n%d FAILED\n" : "\nall passed\n", failures);
    return failures ? 1 : 0;
}
