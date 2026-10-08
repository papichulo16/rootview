/* M4 tests: kfield and kprof_init. kfield resolution and decoding against
 * each fixture's vmlinux.btf.gz (always run); then for each fixture with a
 * mem.raw, the whole init sequence over the dump, and a walk of
 * init_task.tasks diffed against what ps saw in the guest at the pause. */
#include <inttypes.h>

#include "fixture.h"
#include "kern/prof/kfield.h"
#include "kern/prof/kprof.h"

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

/* ---- decoding hand-made fields: widths, signs, straddling bitfields ---- */

static void test_decode(void) {
    printf("decoding\n");
    btf_t none = {0};
    unsigned char buf[32] = {0};
    kval_t v;
    char err[256];

    /* -5 as an s32 at +4 */
    int32_t neg = -5;
    memcpy(buf + 4, &neg, 4);
    kfield_t f = {.offset = 4, .size = 4, .kind = KF_S, .is_signed = true};
    CHECK(kfield_decode(&none, &f, buf, sizeof(buf), &v, err, sizeof(err)) == 0 && v.s == -5 && v.u == 0xfffffffbu,
          "s32 -5: s %" PRId64 " u 0x%" PRIx64, v.s, v.u);
    f.kind = KF_U, f.is_signed = false;
    CHECK(kfield_decode(&none, &f, buf, sizeof(buf), &v, err, sizeof(err)) == 0 && v.s == 0xfffffffbll, "u32");

    /* a signed 3-bit field at bit 7 of byte 8: straddles two bytes, value -3 (0b101) */
    memset(buf, 0, sizeof(buf));
    buf[8] = 0x80, buf[9] = 0x02;
    f = (kfield_t) {.offset = 8, .size = 2, .bit_off = 7, .bit_size = 3, .kind = KF_S, .is_signed = true};
    CHECK(kfield_decode(&none, &f, buf, sizeof(buf), &v, err, sizeof(err)) == 0 && v.s == -3 && v.u == 5,
          "s:3 straddling: s %" PRId64 " u %" PRIu64, v.s, v.u);

    /* a 64-bit bitfield at bit 4: nine bytes */
    uint64_t val = 0xfedcba9876543210ull;
    memset(buf, 0, sizeof(buf));
    for (int i = 0; i < 64; i++)
        if (val >> i & 1) buf[(4 + i) / 8] |= (unsigned char) (1u << ((4 + i) % 8));
    f = (kfield_t) {.offset = 0, .size = 9, .bit_off = 4, .bit_size = 64, .kind = KF_U};
    CHECK(kfield_decode(&none, &f, buf, sizeof(buf), &v, err, sizeof(err)) == 0 && v.u == val, "u:64 over 9 bytes");

    /* bounds */
    f = (kfield_t) {.offset = 30, .size = 4, .kind = KF_U};
    CHECK(kfield_decode(&none, &f, buf, sizeof(buf), &v, err, sizeof(err)) != 0, "read past the buffer accepted");
    f = (kfield_t) {.offset = UINT64_MAX - 1, .size = 4, .kind = KF_U};
    CHECK(kfield_decode(&none, &f, buf, sizeof(buf), &v, err, sizeof(err)) != 0, "offset overflow accepted");

    /* a string that fills its array keeps its NUL past len */
    memcpy(buf, "0123456789abcdef", 16);
    f = (kfield_t) {.offset = 0, .size = 16, .kind = KF_CSTR};
    CHECK(kfield_decode(&none, &f, buf, sizeof(buf), &v, err, sizeof(err)) == 0 && v.len == 16 &&
              !strcmp((char *) v.bytes, "0123456789abcdef"),
          "full comm");
    kval_free(&v);
}

/* ---- kfield over each fixture's BTF ---- */

static void test_fixture_kfield(const char *dir, const char *name) {
    size_t len;
    unsigned char *raw = gunzip(dir, name, "vmlinux.btf.gz", &len);
    if (!raw) return;
    printf("fixture %s: kfield\n", name);
    btf_t b;
    char err[256];
    if (btf_parse(raw, len, &b, err, sizeof(err)) != 0) {
        CHECK(0, "parse: %s", err);
        free(raw);
        return;
    }

    uint32_t task = btf_find(&b, "task_struct", BTF_KIND_STRUCT);
    static const struct {
        const char *type, *path;
        kfield_kind_t kind;
        uint32_t size;
        const char *ref; /* pointee or enum name */
    } cases[] = {
        {"task_struct", "comm", KF_CSTR, 16, NULL},
        {"task_struct", "pid", KF_S, 4, NULL},
        {"task_struct", "flags", KF_U, 4, NULL},
        {"task_struct", "mm", KF_PTR, 8, "mm_struct"},
        {"task_struct", "real_cred", KF_PTR, 8, "cred"},
        {"task_struct", "tasks", KF_BYTES, 16, NULL},
        {"task_struct", "tasks.next", KF_PTR, 8, "list_head"},
        {"task_struct", "se.vruntime", KF_U, 8, NULL},
        {"task_struct", "in_execve", KF_U, 1, NULL},
        {"struct task_struct", "start_time", KF_U, 8, NULL},
        {"bpf_prog", "type", KF_ENUM, 4, "bpf_prog_type"},
        {"bpf_prog", "jited", KF_U, 1, NULL},
        {"bpf_prog", "insnsi", KF_BYTES, 0, NULL},
        {"bpf_prog", "tag", KF_BYTES, 8, NULL},
        {"bpf_prog", "bpf_func", KF_PTR, 8, NULL},
        {"cred", "uid", KF_BYTES, 4, NULL}, /* kuid_t is a struct */
        {"cred", "uid.val", KF_U, 4, NULL},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        kfield_t f;
        if (kfield_resolve(&b, cases[i].type, cases[i].path, &f, err, sizeof(err)) != 0) {
            CHECK(0, "%s.%s: %s", cases[i].type, cases[i].path, err);
            continue;
        }
        CHECK(f.kind == cases[i].kind && f.size == cases[i].size, "%s.%s: %s/%u, want %s/%u", cases[i].type,
              cases[i].path, kfield_kind_name(f.kind), f.size, kfield_kind_name(cases[i].kind), cases[i].size);
        if (cases[i].ref) {
            btf_type_t t;
            CHECK(btf_type(&b, f.ref, &t) == 0 && !strcmp(t.name, cases[i].ref), "%s.%s: ref '%s', want '%s'",
                  cases[i].type, cases[i].path, t.name, cases[i].ref);
        }
    }

    /* offsets agree with btf_member, bitfields split into byte + bit */
    kfield_t f;
    btf_member_t m;
    CHECK(kfield_resolve(&b, "task_struct", "in_execve", &f, err, sizeof(err)) == 0 &&
              btf_member(&b, task, "in_execve", &m) == 0 && f.offset * 8 + f.bit_off == m.bit_off && f.bit_size == 1,
          "in_execve bit position");
    CHECK(kfield_resolve(&b, "task_struct", "se.vruntime", &f, err, sizeof(err)) == 0 &&
              btf_member(&b, task, "se.vruntime", &m) == 0 && f.offset * 8 == m.bit_off,
          "se.vruntime offset");

    /* no -> in v1, and the error says why */
    CHECK(kfield_resolve(&b, "task_struct", "mm.pgd", &f, err, sizeof(err)) != 0 && strstr(err, "pointer") &&
              strstr(err, "mm_struct"),
          "mm.pgd: '%s'", err);
    printf("  mm.pgd: %s\n", err);
    CHECK(kfield_resolve(&b, "task_struct", "nope", &f, err, sizeof(err)) != 0, "nope accepted");
    CHECK(kfield_resolve(&b, "no_such_struct", "x", &f, err, sizeof(err)) != 0, "no_such_struct accepted");

    /* decode a fake task_struct: pid, a bitfield set beside its neighbours,
     * a string, and an enum */
    int64_t tsize = btf_size(&b, task);
    unsigned char *buf = calloc(1, (size_t) tsize);
    kfield_t pid, comm, exec;
    kfield_resolve(&b, "task_struct", "pid", &pid, NULL, 0);
    kfield_resolve(&b, "task_struct", "comm", &comm, NULL, 0);
    kfield_resolve(&b, "task_struct", "in_execve", &exec, NULL, 0);
    int32_t p = 4242;
    memcpy(buf + pid.offset, &p, 4);
    memcpy(buf + comm.offset, "swapper/0", 10);
    memset(buf + exec.offset, 0xff, exec.size);
    buf[exec.offset] &= (unsigned char) ~(1u << exec.bit_off);
    kval_t v;
    CHECK(kfield_decode(&b, &pid, buf, (size_t) tsize, &v, err, sizeof(err)) == 0 && v.s == 4242, "pid");
    CHECK(kfield_decode(&b, &exec, buf, (size_t) tsize, &v, err, sizeof(err)) == 0 && v.u == 0, "in_execve clear");
    buf[exec.offset] |= (unsigned char) (1u << exec.bit_off);
    CHECK(kfield_decode(&b, &exec, buf, (size_t) tsize, &v, err, sizeof(err)) == 0 && v.u == 1, "in_execve set");
    CHECK(kfield_decode(&b, &comm, buf, (size_t) tsize, &v, err, sizeof(err)) == 0 && v.len == 9 &&
              !strcmp((char *) v.bytes, "swapper/0"),
          "comm");
    kval_free(&v);
    free(buf);

    kfield_t type;
    unsigned char pbuf[256] = {0};
    kfield_resolve(&b, "bpf_prog", "type", &type, NULL, 0);
    pbuf[type.offset] = 2;
    CHECK(kfield_decode(&b, &type, pbuf, sizeof(pbuf), &v, err, sizeof(err)) == 0 && v.u == 2 && v.enum_name &&
              !strcmp(v.enum_name, "BPF_PROG_TYPE_KPROBE"),
          "bpf_prog.type 2");
    pbuf[type.offset] = 250;
    CHECK(kfield_decode(&b, &type, pbuf, sizeof(pbuf), &v, err, sizeof(err)) == 0 && !v.enum_name, "unknown type");

    btf_free(&b);
    free(raw);
}

/* ---- the init sequence over a dump ---- */

typedef struct {
    kprof_regs_t regs;
    int pauses, resumes;
} dump_ctx_t;

static int dump_pause(void *ctx, char *err, size_t err_len) {
    (void) err, (void) err_len;
    ((dump_ctx_t *) ctx)->pauses++;
    return 0;
}

static int dump_resume(void *ctx, char *err, size_t err_len) {
    (void) err, (void) err_len;
    ((dump_ctx_t *) ctx)->resumes++;
    return 0;
}

static int dump_regs(void *ctx, kprof_regs_t *regs, char *err, size_t err_len) {
    (void) err, (void) err_len;
    *regs = ((dump_ctx_t *) ctx)->regs;
    return 0;
}

typedef struct {
    int pid;
    char comm[64];
} task_t;

static int cmp_task(const void *a, const void *b) {
    return ((const task_t *) a)->pid - ((const task_t *) b)->pid;
}

/* task->comm is what /proc/<pid>/comm starts from, but /proc prints a
 * kthread's full name where comm cut it at 15 (6.2+), and appends
 * "-<workqueue>" to a busy kworker's. anything else has to be equal. */
static bool comm_matches(const char *walk, const char *proc) {
    size_t n = strlen(walk);
    if (strncmp(walk, proc, n) != 0) return false;
    return proc[n] == '\0' || n == 15 || proc[n] == '-';
}

/* init_task.tasks round to itself, one kprof_read per task_struct and every
 * field decoded out of that buffer */
static size_t walk_tasks(const kprof_t *kp, task_t *out, size_t max, char *err, size_t err_len) {
    kfield_t f_next, f_pid, f_comm;
    if (kfield_resolve(&kp->btf, "task_struct", "tasks.next", &f_next, err, err_len) != 0 ||
        kfield_resolve(&kp->btf, "task_struct", "pid", &f_pid, err, err_len) != 0 ||
        kfield_resolve(&kp->btf, "task_struct", "comm", &f_comm, err, err_len) != 0)
        return 0;
    int64_t size = btf_size(&kp->btf, btf_find(&kp->btf, "task_struct", BTF_KIND_STRUCT));
    unsigned char *buf = malloc((size_t) size);
    size_t n = 0;
    uint64_t task = kp->init_task;
    for (;;) {
        if (kprof_read(kp, task, buf, (size_t) size, err, err_len) != 0) break;
        kval_t next, pid, comm;
        kfield_decode(&kp->btf, &f_next, buf, (size_t) size, &next, NULL, 0);
        if (task != kp->init_task) {
            if (n == max) {
                snprintf(err, err_len, "more than %zu tasks", max);
                break;
            }
            kfield_decode(&kp->btf, &f_pid, buf, (size_t) size, &pid, NULL, 0);
            kfield_decode(&kp->btf, &f_comm, buf, (size_t) size, &comm, NULL, 0);
            out[n].pid = (int) pid.s;
            snprintf(out[n].comm, sizeof(out[n].comm), "%s", comm.bytes);
            kval_free(&comm);
            n++;
        }
        task = next.u - f_next.offset; /* container_of: next is the first word of tasks */
        if (task == kp->init_task) {
            free(buf);
            return n;
        }
    }
    free(buf);
    return SIZE_MAX;
}

static void test_fixture_kprof(const char *dir, const char *name) {
    if (fixture_has_dump(dir, name) <= 0) return;
    printf("fixture %s: kprof_init\n", name);

    char *regs = fixture_file(dir, name, "regs", NULL);
    char *uname = fixture_file(dir, name, "uname", NULL);
    char *ps = fixture_file(dir, name, "ps", NULL);
    CHECK(regs && uname && ps, "missing regs, uname or ps");
    dump_ctx_t ctx = {0};
    if (!regs || !uname || !ps || regs_get(regs, "cr3", &ctx.regs.cr3) || regs_get(regs, "cr4", &ctx.regs.cr4) ||
        regs_get(regs, "lstar", &ctx.regs.lstar) || regs_get(regs, "idtr", &ctx.regs.idtr_base)) {
        CHECK(0, "bad fixture files");
        goto out;
    }

    char path[4096], err[512];
    kprof_target_t target = {.pause = dump_pause, .resume = dump_resume, .read_regs = dump_regs, .ctx = &ctx};
    snprintf(path, sizeof(path), "%s/%s/mem.raw", dir, name);
    if (kmem_dump_open(path, &target.mem, err, sizeof(err)) != 0) {
        CHECK(0, "%s", err);
        goto out;
    }

    /* LA57 is rejected at step 3, and the vm is still resumed */
    kprof_t kp;
    dump_ctx_t saved = ctx;
    ctx.regs.cr4 |= PT_CR4_LA57;
    CHECK(kprof_init(&kp, &target, err, sizeof(err)) != 0 && strstr(err, "step 3 (root)") && ctx.pauses == 1 &&
              ctx.resumes == 1,
          "LA57: '%s', %d pauses, %d resumes", err, ctx.pauses, ctx.resumes);
    printf("  LA57: %s\n", err);
    ctx = saved;

    /* done-when: all ten steps, step 9 included */
    if (kprof_init(&kp, &target, err, sizeof(err)) != 0) {
        CHECK(0, "%s", err);
        kmem_close(&target.mem);
        goto out;
    }
    CHECK(ctx.pauses == 1 && ctx.resumes == 1, "%d pauses, %d resumes", ctx.pauses, ctx.resumes);
    uname[strcspn(uname, "\n")] = '\0';
    CHECK(!strcmp(kp.release, uname), "release '%s', uname '%s'", kp.release, uname);
    printf("  %s (%u.%u.%u); vcpu root 0x%" PRIx64 ", init_top_pgt 0x%" PRIx64 "; init_task 0x%" PRIx64
           " comm swapper/0\n",
           kp.release, kp.major, kp.minor, kp.patch, kp.vcpu_root.pgd, kp.root.pgd, kp.init_task);
    const ksym_t *pgt = ksym_by_name(&kp.ksym, "init_top_pgt");
    uint64_t pgt_pa;
    CHECK(pgt && pt_translate(&target.mem, &kp.root, pgt->addr, &pgt_pa, NULL, NULL, 0) == 0 && pgt_pa == kp.root.pgd,
          "init_top_pgt maps itself");

    /* done-when: init_task.tasks against ps */
    task_t tasks[4096], want[4096];
    size_t n = walk_tasks(&kp, tasks, 4096, err, sizeof(err));
    CHECK(n != SIZE_MAX && n > 0, "walk: %s", err);
    size_t nw = 0;
    for (char *l = ps; *l && nw < 4096;) {
        char *eol = strchr(l, '\n');
        if (eol) *eol = '\0';
        char *sp = strchr(l, ' ');
        if (sp) {
            want[nw].pid = atoi(l);
            snprintf(want[nw].comm, sizeof(want[nw].comm), "%s", sp + 1);
            nw++;
        }
        if (!eol) break;
        l = eol + 1;
    }
    if (n != SIZE_MAX) {
        qsort(tasks, n, sizeof(*tasks), cmp_task);
        size_t i = 0, j = 0, diff = 0;
        while (i < n || j < nw) {
            int c = i == n ? 1 : j == nw ? -1 : cmp_task(&tasks[i], &want[j]);
            if (c == 0 && comm_matches(tasks[i].comm, want[j].comm)) {
                i++, j++;
                continue;
            }
            diff++;
            if (c <= 0) printf("  walk only: %d %s\n", tasks[i].pid, tasks[i].comm), i++;
            if (c >= 0) printf("  ps only:   %d %s\n", want[j].pid, want[j].comm), j++;
        }
        CHECK(diff == 0, "%zu task(s) differ between the walk and ps", diff);
        if (!diff) printf("  init_task.tasks: %zu tasks, all match ps\n", n);
    }

    kprof_free(&kp);
    kmem_close(&target.mem);
out:
    free(regs);
    free(uname);
    free(ps);
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "tests/fixtures";
    test_decode();
    for_each_fixture(dir, test_fixture_kfield);
    for_each_fixture(dir, test_fixture_kprof);

    printf(failures ? "\n%d FAILED\n" : "\nall passed\n", failures);
    return failures ? 1 : 0;
}
