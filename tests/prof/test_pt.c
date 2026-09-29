/* M1 tests: pt_root/pt_walk against synthetic page tables (always run) and
 * against the ram-dump fixtures under tests/fixtures (skipped per fixture
 * when its mem.raw isn't present - see tests/fixtures/README.md). */
#include <dirent.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "kern/prof/kmem.h"
#include "kern/prof/pt.h"

static int failures;

#define CHECK(cond, ...)                                                                                               \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            failures++;                                                                                                \
            printf("  FAIL %s:%d: ", __FILE__, __LINE__);                                                              \
            printf(__VA_ARGS__);                                                                                       \
            putchar('\n');                                                                                             \
        }                                                                                                              \
    } while (0)

/* ---- synthetic guest memory ---- */

#define SYN_SIZE (16u << 20)
#define PTE_P 0x063ull /* present|rw|accessed|dirty */
#define P PTE_P
#define PTE_PS 0x080ull
#define NX (1ull << 63)

typedef struct {
    unsigned char *ram;
} syn_t;

static int syn_read_pa(void *ctx, uint64_t pa, void *buf, size_t len, char *err, size_t err_len) {
    syn_t *s = ctx;
    if (pa > SYN_SIZE || len > SYN_SIZE - pa) {
        if (err) snprintf(err, err_len, "pa 0x%" PRIx64 " out of range", pa);
        return -1;
    }
    memcpy(buf, s->ram + pa, len);
    return 0;
}

static void set_ent(syn_t *s, uint64_t table, int idx, uint64_t val) {
    memcpy(s->ram + table + idx * 8, &val, 8);
}

static int idx(uint64_t va, int level) {
    return (int) ((va >> (12 + 9 * (level - 1))) & 0x1ff);
}

/* fills a page with junk that looks like entries pointing all over the place,
 * standing in for whatever sits on the even page below an odd non-KPTI root */
static void junk_page(syn_t *s, uint64_t pa) {
    uint64_t x = 0x9e3779b97f4a7c15ull;
    for (int i = 0; i < 512; i++) {
        x ^= x << 13, x ^= x >> 7, x ^= x << 17;
        memcpy(s->ram + pa + i * 8, &x, 8);
    }
}

/* kernel image: 2MiB pages starting at KTEXT, n_pmd of them, backed by
 * physical 0x400000.. (only the first few actually fit in SYN_SIZE, which is
 * fine - translation doesn't read the target) */
#define KTEXT 0xffffffff90000000ull
#define ANCHOR (KTEXT + 0x80)

static void map_image(syn_t *s, uint64_t pgd, uint64_t pdpt, uint64_t pd, int n_pmd) {
    set_ent(s, pgd, idx(KTEXT, 4), pdpt | P);
    set_ent(s, pdpt, idx(KTEXT, 3), pd | P);
    for (int i = 0; i < n_pmd; i++) set_ent(s, pd, idx(KTEXT, 2) + i, (0x400000ull + (uint64_t) i * 0x200000) | P | PTE_PS);
}

static kmem_t syn_mem(syn_t *s) {
    s->ram = calloc(1, SYN_SIZE);
    return (kmem_t) {.read_pa = syn_read_pa, .close = NULL, .ctx = s};
}

static void test_pcid_bits(void) {
    printf("synthetic: PCID bits in CR3\n");
    syn_t s;
    kmem_t m = syn_mem(&s);
    map_image(&s, 0x2000, 0x10000, 0x11000, 12);

    pt_root_t r;
    char err[256];
    uint64_t cr3 = 0x2000 | 0x5a5; /* PCID 0x5a5, bit 12 clear */
    CHECK(pt_root_from_cr3(&m, cr3, 0, ANCHOR, &r, err, sizeof(err)) == 0, "%s", err);
    CHECK(r.pgd == 0x2000, "pgd 0x%" PRIx64, r.pgd);

    /* PCID 0x802 (bit 11 is KPTI's user-ASID bit) and the no-flush bit */
    cr3 = (1ull << 63) | 0x2000 | 0x802;
    CHECK(pt_root_from_cr3(&m, cr3, 0, ANCHOR, &r, err, sizeof(err)) == 0, "%s", err);
    CHECK(r.pgd == 0x2000, "pgd 0x%" PRIx64, r.pgd);
    free(s.ram);
}

static void test_nopti_odd_root(void) {
    printf("synthetic: KPTI off, root on an odd page\n");
    syn_t s;
    kmem_t m = syn_mem(&s);
    junk_page(&s, 0x2000);
    map_image(&s, 0x3000, 0x10000, 0x11000, 12);

    pt_root_t r;
    char err[256];
    CHECK(pt_root_from_cr3(&m, 0x3000 | 0x002, 0, ANCHOR, &r, err, sizeof(err)) == 0, "%s", err);
    CHECK(r.pgd == 0x3000, "picked 0x%" PRIx64 ", want the odd page 0x3000", r.pgd);

    /* without KPTI, PGDs are single pages, so the even page can be another
     * process's PGD sharing the same kernel half - a tie that must keep CR3 */
    map_image(&s, 0x2000, 0x10000, 0x11000, 12);
    CHECK(pt_root_from_cr3(&m, 0x3000 | 0x002, 0, ANCHOR, &r, err, sizeof(err)) == 0, "%s", err);
    CHECK(r.pgd == 0x3000, "tie went to 0x%" PRIx64 ", want CR3 as-is 0x3000", r.pgd);
    free(s.ram);
}

static void test_pti_user_root(void) {
    printf("synthetic: KPTI on, vcpu on the user PGD\n");
    syn_t s;
    kmem_t m = syn_mem(&s);
    /* kernel PGD maps the whole image; user PGD only the entry-text PMD */
    map_image(&s, 0x4000, 0x10000, 0x11000, 12);
    map_image(&s, 0x5000, 0x12000, 0x13000, 1);

    pt_root_t r;
    char err[256];
    uint64_t user_cr3 = 0x5000 | (1ull << 11) | 0x1;
    CHECK(pt_root_from_cr3(&m, user_cr3, 0, ANCHOR, &r, err, sizeof(err)) == 0, "%s", err);
    CHECK(r.pgd == 0x4000, "picked 0x%" PRIx64 ", want kernel PGD 0x4000", r.pgd);

    uint64_t kern_cr3 = 0x4000 | 0x1;
    CHECK(pt_root_from_cr3(&m, kern_cr3, 0, ANCHOR, &r, err, sizeof(err)) == 0, "%s", err);
    CHECK(r.pgd == 0x4000, "picked 0x%" PRIx64, r.pgd);

    /* no-PCID KPTI clones all of .text into the user PGD; kernel PGD still
     * wins on rodata/data */
    map_image(&s, 0x5000, 0x12000, 0x13000, 8);
    CHECK(pt_root_from_cr3(&m, user_cr3, 0, ANCHOR, &r, err, sizeof(err)) == 0, "%s", err);
    CHECK(r.pgd == 0x4000, "picked 0x%" PRIx64 " with text cloned", r.pgd);
    free(s.ram);
}

static void test_no_root(void) {
    printf("synthetic: nothing maps the anchor\n");
    syn_t s;
    kmem_t m = syn_mem(&s);
    pt_root_t r;
    char err[256] = "";
    CHECK(pt_root_from_cr3(&m, 0x3000, 0, ANCHOR, &r, err, sizeof(err)) != 0, "expected failure");
    CHECK(err[0] != '\0', "no error message");
    free(s.ram);
}

static void test_walk_sizes(void) {
    printf("synthetic: 4K/2M/1G pages, NX bits, non-present, cross-page reads\n");
    syn_t s;
    kmem_t m = syn_mem(&s);
    uint64_t pgd = 0x1000, pdpt = 0x2000, pd = 0x3000, pt = 0x4000;
    pt_root_t r = {.pgd = pgd, .la57 = false};
    char err[256];
    uint64_t pa, size;

    /* 1GiB page at 0xffff888000000000 -> pa 0 */
    uint64_t dmap = 0xffff888000000000ull;
    set_ent(&s, pgd, idx(dmap, 4), pdpt | P);
    set_ent(&s, pdpt, idx(dmap, 3), 0x0 | P | PTE_PS | NX);
    CHECK(pt_translate(&m, &r, dmap + 0x123456, &pa, &size, err, sizeof(err)) == 0, "%s", err);
    CHECK(pa == 0x123456 && size == 1ull << 30, "1G: pa 0x%" PRIx64 " size 0x%" PRIx64, pa, size);

    /* 2MiB page */
    uint64_t kva = 0xffffffff81000000ull;
    uint64_t kpdpt = 0x5000;
    set_ent(&s, pgd, idx(kva, 4), kpdpt | P);
    set_ent(&s, kpdpt, idx(kva, 3), pd | P);
    set_ent(&s, pd, idx(kva, 2), 0x200000 | P | PTE_PS | NX);
    CHECK(pt_translate(&m, &r, kva + 0x1abcd, &pa, &size, err, sizeof(err)) == 0, "%s", err);
    CHECK(pa == 0x21abcd && size == 2ull << 20, "2M: pa 0x%" PRIx64, pa);

    /* two 4KiB pages that are virtually adjacent but physically apart */
    uint64_t uva = 0xffffffff81200000ull;
    set_ent(&s, pd, idx(uva, 2), pt | P);
    set_ent(&s, pt, idx(uva, 1), 0x9000 | P | NX);
    set_ent(&s, pt, idx(uva, 1) + 1, 0x7000 | P);
    memcpy(s.ram + 0x9ffe, "AB", 2);
    memcpy(s.ram + 0x7000, "CD", 2);
    char buf[4];
    CHECK(pt_read(&m, &r, uva + 0xffe, buf, 4, err, sizeof(err)) == 0, "%s", err);
    CHECK(memcmp(buf, "ABCD", 4) == 0, "cross-page read got %.4s", buf);

    /* not present, and non-canonical */
    CHECK(pt_translate(&m, &r, uva + 0x2000, &pa, NULL, err, sizeof(err)) != 0, "expected not-present");
    CHECK(pt_translate(&m, &r, 0x0000900000000000ull, &pa, NULL, err, sizeof(err)) != 0, "expected non-canonical");
    free(s.ram);
}

static void test_la57(void) {
    printf("synthetic: 5-level walk\n");
    syn_t s;
    kmem_t m = syn_mem(&s);
    uint64_t va = 0xff11000000001000ull; /* canonical only with 57 bits */
    uint64_t t5 = 0x1000, t4 = 0x2000, t3 = 0x3000, t2 = 0x4000, t1 = 0x5000;
    set_ent(&s, t5, idx(va, 5), t4 | P);
    set_ent(&s, t4, idx(va, 4), t3 | P);
    set_ent(&s, t3, idx(va, 3), t2 | P);
    set_ent(&s, t2, idx(va, 2), t1 | P);
    set_ent(&s, t1, idx(va, 1), 0x8000 | P);

    pt_root_t r = {.pgd = t5, .la57 = true};
    uint64_t pa;
    char err[256];
    CHECK(pt_translate(&m, &r, va + 0x42, &pa, NULL, err, sizeof(err)) == 0, "%s", err);
    CHECK(pa == 0x8042, "pa 0x%" PRIx64, pa);

    r.la57 = false;
    CHECK(pt_translate(&m, &r, va, &pa, NULL, err, sizeof(err)) != 0, "4-level should reject a 57-bit address");
    free(s.ram);
}

/* ---- ram-dump fixtures ---- */

static int read_file(const char *path, unsigned char **out, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    rewind(f);
    *out = malloc((size_t) n + 1);
    *len = fread(*out, 1, (size_t) n, f);
    (*out)[*len] = '\0';
    fclose(f);
    return 0;
}

static int regs_get(const char *regs, const char *key, uint64_t *val) {
    size_t kl = strlen(key);
    for (const char *p = regs; p && *p; p = strchr(p, '\n') ? strchr(p, '\n') + 1 : NULL) {
        if (strncmp(p, key, kl) == 0 && p[kl] == '=') {
            *val = strtoull(p + kl + 1, NULL, 0);
            return 0;
        }
    }
    return -1;
}

static int sym_get(const char *kallsyms, const char *name, uint64_t *addr) {
    size_t nl = strlen(name);
    for (const char *p = kallsyms; p && *p; p = strchr(p, '\n') ? strchr(p, '\n') + 1 : NULL) {
        const char *end = strchr(p, '\n');
        size_t ll = end ? (size_t) (end - p) : strlen(p);
        if (ll > nl + 1 && strncmp(p + ll - nl, name, nl) == 0 && p[ll - nl - 1] == ' ') {
            *addr = strtoull(p, NULL, 16);
            return 0;
        }
    }
    return -1;
}

static void test_fixture(const char *dir, const char *name) {
    char path[4096];
    struct stat st;
    snprintf(path, sizeof(path), "%s/%s/regs", dir, name);
    if (stat(path, &st) != 0) return; /* not a fixture */
    snprintf(path, sizeof(path), "%s/%s/mem.raw", dir, name);
    if (stat(path, &st) != 0) {
        printf("fixture %s: SKIP (no mem.raw)\n", name);
        return;
    }
    printf("fixture %s\n", name);
    int before = failures;

    unsigned char *regs = NULL, *syms = NULL, *live = NULL;
    size_t regs_len, syms_len, live_len;
    char p2[4096];
    snprintf(p2, sizeof(p2), "%s/%s/regs", dir, name);
    CHECK(read_file(p2, &regs, &regs_len) == 0, "missing %s", p2);
    snprintf(p2, sizeof(p2), "%s/%s/symcheck", dir, name);
    CHECK(read_file(p2, &syms, &syms_len) == 0, "missing %s", p2);
    snprintf(p2, sizeof(p2), "%s/%s/live_banner.bin", dir, name);
    CHECK(read_file(p2, &live, &live_len) == 0, "missing %s", p2);
    if (!regs || !syms || !live) goto out;

    uint64_t cr3, cr4, lstar, banner, init_top_pgt;
    CHECK(regs_get((char *) regs, "cr3", &cr3) == 0, "no cr3");
    CHECK(regs_get((char *) regs, "cr4", &cr4) == 0, "no cr4");
    CHECK(regs_get((char *) regs, "lstar", &lstar) == 0, "no lstar");
    CHECK(sym_get((char *) syms, "linux_banner", &banner) == 0, "no linux_banner");
    CHECK(sym_get((char *) syms, "init_top_pgt", &init_top_pgt) == 0, "no init_top_pgt");
    if (failures != before) goto out;

    kmem_t m;
    char err[256];
    CHECK(kmem_dump_open(path, &m, err, sizeof(err)) == 0, "%s", err);

    pt_root_t r;
    if (pt_root_from_cr3(&m, cr3, cr4, lstar, &r, err, sizeof(err)) != 0) {
        CHECK(0, "pt_root: %s", err);
        kmem_close(&m);
        goto out;
    }
    bool flipped = (r.pgd ^ (cr3 & PT_PA_MASK)) != 0;
    printf("  cr3 0x%" PRIx64 " -> root 0x%" PRIx64 " (%s)\n", cr3, r.pgd,
           flipped ? "bit 12 cleared: KPTI user PGD" : "cr3 as-is");

    /* done-when: linux_banner through the dump == the live read */
    unsigned char *got = malloc(live_len);
    CHECK(pt_read(&m, &r, banner, got, live_len, err, sizeof(err)) == 0, "%s", err);
    CHECK(memcmp(got, live, live_len) == 0, "linux_banner bytes differ from the live read");
    printf("  linux_banner: %.*s", (int) strcspn((char *) got, "\n"), got);
    putchar('\n');
    free(got);

    /* the kernel half is shared: init_top_pgt must translate, and its last
     * top-level entry must equal the chosen root's */
    uint64_t itp_pa, a, b;
    CHECK(pt_translate(&m, &r, init_top_pgt, &itp_pa, NULL, err, sizeof(err)) == 0, "%s", err);
    kmem_read_pa(&m, itp_pa + 511 * 8, &a, 8, NULL, 0);
    kmem_read_pa(&m, r.pgd + 511 * 8, &b, 8, NULL, 0);
    CHECK(a == b, "PML4[511] differs: init_top_pgt 0x%" PRIx64 " root 0x%" PRIx64, a, b);

    kmem_close(&m);
out:
    free(regs);
    free(syms);
    free(live);
}

int main(int argc, char **argv) {
    test_pcid_bits();
    test_nopti_odd_root();
    test_pti_user_root();
    test_no_root();
    test_walk_sizes();
    test_la57();

    const char *dir = argc > 1 ? argv[1] : "tests/fixtures";
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *e;
        char *names[64];
        int n = 0;
        while ((e = readdir(d)) && n < 64) {
            char p[4096];
            struct stat st;
            snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
            if (e->d_name[0] != '.' && stat(p, &st) == 0 && S_ISDIR(st.st_mode)) names[n++] = strdup(e->d_name);
        }
        closedir(d);
        for (int i = 0; i < n; i++) {
            int before = failures;
            test_fixture(dir, names[i]);
            if (failures != before) printf("  (fixture %s failed)\n", names[i]);
            free(names[i]);
        }
    }

    printf(failures ? "\n%d FAILED\n" : "\nall passed\n", failures);
    return failures ? 1 : 0;
}
