/* M1/M2 tests: pt_root/pt_walk/pt_image against synthetic page tables
 * (always run) and against the ram-dump fixtures under tests/fixtures (skipped per fixture
 * when its mem.raw isn't present - see tests/fixtures/README.md). */
#include <inttypes.h>

#include "fixture.h"

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

/* PD index -> its 2MiB slot under PT_KIMG_BASE */
#define KIMG(i) (PT_KIMG_BASE + ((uint64_t) (i) << 21))

static void test_image_synthetic(void) {
    printf("synthetic: pt_image extent, runs, NX, holes, 5-level\n");
    syn_t s;
    kmem_t m = syn_mem(&s);
    uint64_t pml5 = 0x1000, pgd = 0x2000, pdpt = 0x3000, pd = 0x4000, pt = 0x5000, mod_pd = 0x6000;
    char err[256];

    set_ent(&s, pml5, 511, pgd | P);
    set_ent(&s, pgd, 511, pdpt | P);
    set_ent(&s, pdpt, 510, pd | P);
    set_ent(&s, pdpt, 511, mod_pd | P); /* modules, never part of the image */
    set_ent(&s, mod_pd, 0, 0xe00000 | P | PTE_PS);

    /* 128-129 text (X), 130 rodata (NX), 131 a table split by a hole whose
     * PTEs don't carry NX but the PDE does, 132 NX again, 133 a gap, 140 a
     * stray mapping past the gap (nokaslr modules) that must not count */
    set_ent(&s, pd, 128, 0x200000 | P | PTE_PS);
    set_ent(&s, pd, 129, 0x400000 | P | PTE_PS);
    set_ent(&s, pd, 130, 0x600000 | P | PTE_PS | NX);
    set_ent(&s, pd, 131, pt | P | NX);
    for (int j = 0; j < 512; j++)
        if (j != 10) set_ent(&s, pt, j, (0xa00000 + (uint64_t) j * 4096) | P);
    set_ent(&s, pd, 132, 0x800000 | P | PTE_PS | NX);
    set_ent(&s, pd, 140, 0xc00000 | P | PTE_PS | NX);
    memcpy(s.ram + 0x600000 + 0x1ffffe, "RO", 2); /* last bytes of 130 */
    memcpy(s.ram + 0xa00000, "PT", 2);           /* first bytes of 131 */

    pt_root_t r = {.pgd = pgd, .la57 = false};
    pt_image_t img;
    CHECK(pt_image(&m, &r, &img, err, sizeof(err)) == 0, "%s", err);
    CHECK(img.start == KIMG(128) && img.end == KIMG(133), "extent 0x%" PRIx64 "-0x%" PRIx64, img.start, img.end);
    CHECK(img.n_runs == 3, "%zu runs, want 3", img.n_runs);
    if (img.n_runs == 3) {
        CHECK(img.runs[0].va == KIMG(128) && img.runs[0].len == 4ull << 20 && !img.runs[0].nx, "run 0 wrong");
        CHECK(img.runs[1].va == KIMG(130) && img.runs[1].len == (2ull << 20) + 10 * 4096 && img.runs[1].nx,
              "run 1 0x%" PRIx64 "+0x%" PRIx64, img.runs[1].va, img.runs[1].len);
        CHECK(img.runs[2].va == KIMG(131) + 11 * 4096 && img.runs[2].len == 501 * 4096ull + (2ull << 20) &&
                  img.runs[2].nx,
              "run 2 0x%" PRIx64 "+0x%" PRIx64, img.runs[2].va, img.runs[2].len);
    }

    CHECK(pt_image_read_nx(&m, &r, &img, err, sizeof(err)) == 0, "%s", err);
    CHECK(img.runs[0].data == NULL, "X run was loaded");
    const unsigned char *p = pt_image_ptr(&img, KIMG(131) - 2, 4);
    CHECK(p && memcmp(p, "ROPT", 4) == 0, "read across the 2M page / table seam");
    CHECK(pt_image_ptr(&img, KIMG(131) + 10 * 4096 - 2, 4) == NULL, "read across the hole should fail");
    CHECK(pt_image_ptr(&img, KIMG(128), 1) == NULL, "X pages aren't loaded");
    pt_image_free(&img);

    /* the same tables one level down under LA57 */
    r = (pt_root_t) {.pgd = pml5, .la57 = true};
    CHECK(pt_image(&m, &r, &img, err, sizeof(err)) == 0, "%s", err);
    CHECK(img.start == KIMG(128) && img.n_runs == 3, "5-level: start 0x%" PRIx64 ", %zu runs", img.start,
          img.n_runs);
    pt_image_free(&img);

    /* nothing under PDPT[510] */
    r = (pt_root_t) {.pgd = pgd, .la57 = false};
    memset(s.ram + pd, 0, 4096);
    CHECK(pt_image(&m, &r, &img, err, sizeof(err)) != 0, "empty PD should fail");
    set_ent(&s, pdpt, 510, 0);
    CHECK(pt_image(&m, &r, &img, err, sizeof(err)) != 0, "missing PDPT[510] should fail");
    free(s.ram);
}

/* ---- ram-dump fixtures ---- */

static void test_fixture(const char *dir, const char *name) {
    if (fixture_has_dump(dir, name) <= 0) return;
    printf("fixture %s\n", name);
    int before = failures;

    char *regs = NULL, *syms = NULL, *live = NULL;
    size_t live_len = 0;
    syms = fixture_file(dir, name, "symcheck", NULL);
    live = fixture_file(dir, name, "live_banner.bin", &live_len);
    CHECK(syms && live, "missing symcheck or live_banner.bin");
    if (!syms || !live) goto out;

    uint64_t cr3, banner, init_top_pgt;
    CHECK(sym_get(syms, "linux_banner", &banner) == 0, "no linux_banner");
    CHECK(sym_get(syms, "init_top_pgt", &init_top_pgt) == 0, "no init_top_pgt");
    if (failures != before) goto out;

    kmem_t m;
    pt_root_t r;
    char err[256];
    if (fixture_open(dir, name, &m, &r, &regs) != 0) goto out;
    regs_get(regs, "cr3", &cr3);
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

    /* the image extent holds the syscall entry and the banner, and LSTAR is
     * executable while the banner isn't */
    uint64_t lstar;
    regs_get(regs, "lstar", &lstar);
    pt_image_t img;
    if (pt_image(&m, &r, &img, err, sizeof(err)) == 0) {
        printf("  image 0x%" PRIx64 "-0x%" PRIx64 ", %zu runs\n", img.start, img.end, img.n_runs);
        CHECK(img.start <= lstar && lstar < img.end, "lstar outside the image");
        CHECK(img.start <= banner && banner < img.end, "linux_banner outside the image");
        for (size_t i = 0; i < img.n_runs; i++) {
            const pt_run_t *run = &img.runs[i];
            if (lstar - run->va < run->len) CHECK(!run->nx, "lstar's page is NX");
            if (banner - run->va < run->len) CHECK(run->nx, "linux_banner's page is executable");
        }
        pt_image_free(&img);
    } else {
        CHECK(0, "pt_image: %s", err);
    }

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

    test_image_synthetic();

    for_each_fixture(argc > 1 ? argv[1] : "tests/fixtures", test_fixture);

    printf(failures ? "\n%d FAILED\n" : "\nall passed\n", failures);
    return failures ? 1 : 0;
}
