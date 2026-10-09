/* khash tests: SHA-256 against the FIPS 180-4 vectors, one-shot and fed in
 * odd-sized pieces. then, over each fixture with a mem.raw, the regions
 * against kallsyms.gz, a page's hash against its bytes read directly, the
 * first khash_diff taking the baseline and the second finding nothing. then
 * the dump is patched the way a rootkit patches a kernel - an inline hook
 * on a syscall, a sys_call_table entry swapped, a write across a page
 * boundary, a rodata frame made unreadable - and each diff has to name
 * exactly those pages, while a byte past _etext in its last page changes
 * nothing. last, the patched state is accepted as the baseline, and going
 * back to the clean dump reports the same pages the other way round. */
#include <inttypes.h>

#include "../../src/impl/kern/prof/khash/sha256.h"
#include "fixture.h"
#include "kern/prof/khash.h"

/* ---- a kmem_t that patches bytes over the dump and can fail one frame ---- */

typedef struct {
    kmem_t base;
    struct {
        uint64_t pa;
        unsigned char val;
    } patch[64];
    int n;
    uint64_t fail_pa; /* a frame whose reads fail; 0 for none */
} overlay_t;

static int overlay_read(void *ctx, uint64_t pa, void *buf, size_t len, char *err, size_t err_len) {
    overlay_t *o = ctx;
    if (o->fail_pa && pa < o->fail_pa + 4096 && pa + len > o->fail_pa) {
        if (err) snprintf(err, err_len, "frame 0x%" PRIx64 " fails", o->fail_pa);
        return -1;
    }
    if (kmem_read_pa(&o->base, pa, buf, len, err, err_len) != 0) return -1;
    for (int i = 0; i < o->n; i++)
        if (o->patch[i].pa >= pa && o->patch[i].pa < pa + len) ((unsigned char *) buf)[o->patch[i].pa - pa] = o->patch[i].val;
    return 0;
}

/* writes bytes at a kernel va into the overlay, through the canonical root */
static int poke(const kprof_t *kp, overlay_t *o, uint64_t va, const void *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint64_t pa;
        char err[256];
        if (pt_translate(&kp->target.mem, &kp->root, va + i, &pa, NULL, err, sizeof(err)) != 0) {
            CHECK(0, "poke 0x%016" PRIx64 ": %s", va + i, err);
            return -1;
        }
        o->patch[o->n].pa = pa;
        o->patch[o->n++].val = ((const unsigned char *) bytes)[i];
    }
    return 0;
}

/* ---- sha256 ---- */

static void hex(const uint8_t *h, char out[65]) {
    for (int i = 0; i < 32; i++) sprintf(out + 2 * i, "%02x", h[i]);
}

static void test_sha256(void) {
    printf("sha256\n");
    static const struct {
        const char *msg, *want;
    } V[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
        {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrst"
         "nopqrstu",
         "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"},
    };
    uint8_t h[32];
    char got[65];
    for (size_t i = 0; i < sizeof(V) / sizeof(V[0]); i++) {
        sha256(V[i].msg, strlen(V[i].msg), h);
        hex(h, got);
        CHECK(!strcmp(got, V[i].want), "sha256(\"%.20s...\") = %s", V[i].msg, got);
    }

    /* a million 'a's, fed in pieces that straddle every block offset */
    static char a[1000000];
    memset(a, 'a', sizeof(a));
    sha256_t s;
    sha256_init(&s);
    for (size_t off = 0, step = 1; off < sizeof(a); off += step, step = step % 131 + 1)
        sha256_update(&s, a + off, off + step > sizeof(a) ? sizeof(a) - off : step);
    sha256_final(&s, h);
    hex(h, got);
    CHECK(!strcmp(got, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"), "a million a's: %s", got);
}

/* ---- the fixtures ---- */

static unsigned char *gunzip(const char *dir, const char *name, const char *file) {
    char cmd[4200];
    snprintf(cmd, sizeof(cmd), "gzip -dc '%s/%s/%s' 2>/dev/null", dir, name, file);
    FILE *f = popen(cmd, "r");
    if (!f) return NULL;
    size_t cap = 1 << 20, len = 0;
    unsigned char *out = malloc(cap);
    for (size_t r; (r = fread(out + len, 1, cap - len - 1, f)) > 0;)
        if ((len += r) + 1 == cap) out = realloc(out, cap *= 2);
    out[len] = '\0';
    pclose(f);
    return out;
}

static uint64_t sym(const kprof_t *kp, const char *name) {
    const ksym_t *s = ksym_by_name(&kp->ksym, name);
    CHECK(s, "no %s", name);
    return s ? s->addr : 0;
}

static size_t page_of(const khash_baseline_t *b, uint64_t va) {
    for (size_t i = 0; i < b->n; i++)
        if (va >= b->pages[i].va && va < b->pages[i].va + b->pages[i].len) return i;
    return (size_t) -1;
}

static void test_regions(const kprof_t *kp, const char *dir, const char *name) {
    char *ks = (char *) gunzip(dir, name, "kallsyms.gz");
    const khash_baseline_t *b = kp->hash;
    static const char *const names[KHASH_REGIONS][2] = {{"_stext", "_etext"}, {"__start_rodata", "__end_rodata"}};
    for (int r = 0; r < KHASH_REGIONS; r++) {
        const khash_region_t *g = &b->region[r];
        uint64_t s = 0, e = 0;
        CHECK(ks && !sym_get(ks, names[r][0], &s) && !sym_get(ks, names[r][1], &e), "kallsyms.gz bounds");
        CHECK(g->start == s && g->end == e, "%s [0x%016" PRIx64 ", 0x%016" PRIx64 "), kallsyms.gz says [0x%016" PRIx64
              ", 0x%016" PRIx64 ")", khash_region_name(r), g->start, g->end, s, e);
        CHECK(g->n == ((e + 4095) / 4096 - s / 4096), "%s: %zu pages", khash_region_name(r), g->n);
        /* the pages tile the region exactly */
        uint64_t at = g->start;
        size_t gaps = 0;
        for (size_t i = g->first; i < g->first + g->n; i++) {
            gaps += b->pages[i].va != at || !b->pages[i].len || b->pages[i].len > 4096;
            at = b->pages[i].va + b->pages[i].len;
        }
        CHECK(!gaps && at == g->end, "%s: %zu pages don't tile it", khash_region_name(r), gaps);
        printf("  %-6s [0x%016" PRIx64 ", 0x%016" PRIx64 ") %5zu pages, last %u bytes\n", khash_region_name(r),
               g->start, g->end, g->n, b->pages[g->first + g->n - 1].len);
    }
    CHECK(b->region[KHASH_RODATA].first == b->region[KHASH_TEXT].n, "rodata doesn't follow text in the vector");
    CHECK(b->unreadable == 0, "%zu unreadable pages on a clean dump", b->unreadable);

    /* a page's hash is the hash of its bytes */
    static unsigned char buf[4096];
    uint8_t h[32];
    char err[256];
    for (size_t i = 0; i < b->n; i += b->n / 7) {
        const khash_page_t *p = &b->pages[i];
        CHECK(kprof_read(kp, p->va, buf, p->len, err, sizeof(err)) == 0, "read page %zu: %s", i, err);
        sha256(buf, p->len, h);
        CHECK(!memcmp(h, p->hash, 32), "page %zu at 0x%016" PRIx64 ": hash isn't its bytes'", i, p->va);
    }
    free(ks);
}

/* diffs with o over the dump: the changes must be exactly the pages in
 * want (ascending), each of kind */
static void check_diff(kprof_t *kp, overlay_t *o, const size_t *want, size_t nwant, khash_change_kind_t kind,
                       const char *what) {
    char err[512];
    kmem_t base = kp->target.mem;
    o->base = base;
    kp->target.mem = (kmem_t) {.read_pa = overlay_read, .ctx = o};
    khash_diff_t d;
    int rc = khash_diff(kp, &d, err, sizeof(err));
    kp->target.mem = base;
    if (rc != 0) {
        CHECK(0, "%s: khash_diff: %s", what, err);
        return;
    }
    const khash_baseline_t *b = kp->hash;
    CHECK(!d.baselined && d.pages == b->n, "%s: baselined %d, %zu pages", what, d.baselined, d.pages);
    CHECK(d.n == nwant, "%s: %zu changes, want %zu", what, d.n, nwant);
    for (size_t i = 0; i < d.n && i < nwant; i++) {
        const khash_change_t *c = &d.changes[i];
        const khash_page_t *p = &b->pages[want[i]];
        khash_region_id_t r = want[i] >= b->region[KHASH_RODATA].first ? KHASH_RODATA : KHASH_TEXT;
        CHECK(c->index == want[i] && c->va == p->va && c->len == p->len && c->kind == kind && c->region == r,
              "%s: change %zu is page %zu (%s, %s), want %zu (%s, %s)", what, i, c->index, khash_change_name(c->kind),
              khash_region_name(c->region), want[i], khash_change_name(kind), khash_region_name(r));
        CHECK(!memcmp(c->before, p->hash, 32), "%s: change %zu's before isn't the baseline", what, i);
        CHECK(kind == KHASH_UNREADABLE ? !memcmp(c->after, (uint8_t[32]) {0}, 32) : !!memcmp(c->after, c->before, 32),
              "%s: change %zu's after", what, i);
        CHECK(c->sym && c->sym_off < 0x100000, "%s: change %zu has no symbol", what, i);
    }
    printf("  %s:", what);
    for (size_t i = 0; i < d.n; i++)
        printf(" %s 0x%016" PRIx64 " (%s+0x%" PRIx64 ")", khash_change_name(d.changes[i].kind), d.changes[i].va,
               d.changes[i].sym ? d.changes[i].sym : "?", d.changes[i].sym_off);
    printf(d.n ? "\n" : " none\n");
    khash_diff_free(&d);
}

static void test_patched(kprof_t *kp) {
    const khash_baseline_t *b = kp->hash;
    uint64_t getdents = sym(kp, "__x64_sys_getdents64"), sct = sym(kp, "sys_call_table");
    uint64_t etext = sym(kp, "_etext");
    if (!getdents || !sct) return;

    /* jmp rel32 over the syscall's entry */
    static const unsigned char jmp[5] = {0xe9, 0x10, 0x32, 0x54, 0x76};
    static overlay_t hook, table, straddle, tail, gone, all;
    hook = table = straddle = tail = gone = all = (overlay_t) {0};
    poke(kp, &hook, getdents, jmp, sizeof(jmp));
    size_t p_hook = page_of(b, getdents);
    check_diff(kp, &hook, &p_hook, 1, KHASH_MODIFIED, "inline hook");

    /* sys_call_table[__NR_getdents64] pointed somewhere else */
    uint64_t evil = 0xffffffffc0de0000ull, slot = sct + 217 * 8;
    poke(kp, &table, slot, &evil, 8);
    size_t p_table = page_of(b, slot);
    check_diff(kp, &table, &p_table, 1, KHASH_MODIFIED, "sys_call_table entry");

    /* four bytes over a page boundary inside text: both pages */
    uint64_t edge = (getdents & ~4095ull) + 4096 - 2;
    poke(kp, &straddle, edge, "\xcc\xcc\xcc\xcc", 4);
    size_t p_edge[2] = {page_of(b, edge), page_of(b, edge) + 1};
    check_diff(kp, &straddle, p_edge, 2, KHASH_MODIFIED, "across a page boundary");

    /* _etext's page: a byte past it is outside the region, the one before isn't */
    if (etext & 4095) {
        poke(kp, &tail, etext, "\x90", 1);
        check_diff(kp, &tail, NULL, 0, KHASH_MODIFIED, "byte at _etext");
        poke(kp, &tail, etext - 1, "\x90", 1);
        size_t p_tail = page_of(b, etext - 1);
        check_diff(kp, &tail, &p_tail, 1, KHASH_MODIFIED, "byte before _etext");
    } else {
        printf("  _etext page-aligned: SKIP the tail\n");
    }

    /* the sys_call_table frame unreadable */
    uint64_t pa;
    CHECK(pt_translate(&kp->target.mem, &kp->root, slot, &pa, NULL, NULL, 0) == 0, "translate sys_call_table");
    gone.fail_pa = pa & ~4095ull;
    check_diff(kp, &gone, &p_table, 1, KHASH_UNREADABLE, "sys_call_table frame unreadable");

    /* accepting the hooked state: diffing it again finds nothing, and the
     * clean dump then shows the same pages changed back */
    poke(kp, &all, getdents, jmp, sizeof(jmp));
    poke(kp, &all, slot, &evil, 8);
    char err[512];
    kmem_t base = kp->target.mem;
    all.base = base;
    kp->target.mem = (kmem_t) {.read_pa = overlay_read, .ctx = &all};
    int rc = khash_baseline(kp, err, sizeof(err));
    kp->target.mem = base;
    CHECK(rc == 0, "rebaseline: %s", err);
    size_t both[2] = {p_hook, p_table};
    check_diff(kp, &all, NULL, 0, KHASH_MODIFIED, "hooked, after accepting it");
    overlay_t none = {0};
    check_diff(kp, &none, both, 2, KHASH_MODIFIED, "clean, against the hooked baseline");
}

static void test_fixture(const char *dir, const char *name) {
    if (fixture_has_dump(dir, name) <= 0) return;
    printf("fixture %s: khash\n", name);
    dump_ctx_t ctx;
    kprof_target_t target;
    kprof_t kp;
    if (fixture_kprof(dir, name, &ctx, &target, &kp) != 0) return;
    CHECK(!kp.hash, "kprof_init left a baseline");

    char err[512];
    khash_diff_t d;
    int pauses = ctx.pauses;
    CHECK(khash_diff(&kp, &d, err, sizeof(err)) == 0, "first diff: %s", err);
    CHECK(d.baselined && !d.n && kp.hash && d.pages == kp.hash->n, "first diff didn't take the baseline");
    CHECK(ctx.pauses == pauses + 1 && ctx.resumes == ctx.pauses, "%d pauses, %d resumes", ctx.pauses, ctx.resumes);
    khash_diff_free(&d);
    if (!kp.hash) goto out;
    test_regions(&kp, dir, name);

    CHECK(khash_diff(&kp, &d, err, sizeof(err)) == 0, "second diff: %s", err);
    CHECK(!d.baselined && d.n == 0, "%zu changes on an unchanged dump", d.n);
    khash_diff_free(&d);

    test_patched(&kp);
    CHECK(ctx.pauses == ctx.resumes, "%d pauses, %d resumes", ctx.pauses, ctx.resumes);

out:
    kprof_free(&kp);
    CHECK(!kp.hash, "kprof_free left the baseline");
    kmem_close(&target.mem);
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : "tests/fixtures";
    test_sha256();
    for_each_fixture(dir, test_fixture);
    printf(failures ? "\n%d FAILED\n" : "\nall passed\n", failures);
    return failures ? 1 : 0;
}
