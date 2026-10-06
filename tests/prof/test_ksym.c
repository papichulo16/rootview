/* M2 tests: kallsyms decoding. synthetic tables in all three layouts (always
 * run), then each ram-dump fixture decoded and diffed against its
 * /proc/kallsyms, with every wrong switch combination rejected. */
#define _GNU_SOURCE /* qsort_r */
#include <inttypes.h>
#include <stddef.h>

#include "fixture.h"
#include "kern/prof/ksym.h"

static const ksym_cfg_t ALL_CFGS[] = {
    {KSYM_LAYOUT_V5, KSYM_ADDR_RELATIVE},   {KSYM_LAYOUT_V5, KSYM_ADDR_ABS_PERCPU},
    {KSYM_LAYOUT_V6_2, KSYM_ADDR_RELATIVE}, {KSYM_LAYOUT_V6_2, KSYM_ADDR_ABS_PERCPU},
    {KSYM_LAYOUT_V6_4, KSYM_ADDR_RELATIVE}, {KSYM_LAYOUT_V6_4, KSYM_ADDR_ABS_PERCPU},
};
#define N_CFGS (sizeof(ALL_CFGS) / sizeof(ALL_CFGS[0]))

static bool cfg_eq(ksym_cfg_t a, ksym_cfg_t b) {
    return a.layout == b.layout && a.addr == b.addr;
}

static void test_cfg_from_banner(void) {
    printf("switches from the banner\n");
    static const struct {
        const char *banner;
        int ok;
        ksym_cfg_t want;
    } cases[] = {
        {"Linux version 5.15.0-198-generic (buildd@x) (gcc 11.4.0) #208-Ubuntu SMP Fri Sep 4", 1,
         {KSYM_LAYOUT_V5, KSYM_ADDR_ABS_PERCPU}},
        {"Linux version 6.1.0 (a@b) #1 SMP PREEMPT", 1, {KSYM_LAYOUT_V5, KSYM_ADDR_ABS_PERCPU}},
        {"Linux version 6.2.16 (a@b) #1 SMP", 1, {KSYM_LAYOUT_V6_2, KSYM_ADDR_ABS_PERCPU}},
        {"Linux version 6.3.0 (a@b) #1 SMP", 1, {KSYM_LAYOUT_V6_2, KSYM_ADDR_ABS_PERCPU}},
        {"Linux version 6.8.0-45-generic (a@b) #45-Ubuntu SMP PREEMPT_DYNAMIC", 1,
         {KSYM_LAYOUT_V6_4, KSYM_ADDR_ABS_PERCPU}},
        {"Linux version 6.14.11 (a@b) #1 SMP", 1, {KSYM_LAYOUT_V6_4, KSYM_ADDR_ABS_PERCPU}},
        {"Linux version 6.15.0 (a@b) #1 SMP", 1, {KSYM_LAYOUT_V6_4, KSYM_ADDR_RELATIVE}},
        {"Linux version 6.18.35-0-lts (b@c) #1-Alpine SMP PREEMPT_DYNAMIC", 1,
         {KSYM_LAYOUT_V6_4, KSYM_ADDR_RELATIVE}},
        {"Linux version 6.8.0 (a@b) #1 PREEMPT", 1, {KSYM_LAYOUT_V6_4, KSYM_ADDR_RELATIVE}}, /* !SMP */
        {"Linux version 6.8.0 (a@b) #1 SMPX", 1, {KSYM_LAYOUT_V6_4, KSYM_ADDR_RELATIVE}},
        {"Linux version 4.4.0 (a@b) #1 SMP", 0, {0}},
        {"Linux versio 6.8.0", 0, {0}},
        {"Linux version x.y", 0, {0}},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        ksym_cfg_t got = {0};
        char err[256];
        int rc = ksym_cfg_from_banner(cases[i].banner, &got, err, sizeof(err));
        CHECK((rc == 0) == cases[i].ok, "'%s': rc %d", cases[i].banner, rc);
        if (rc == 0 && cases[i].ok)
            CHECK(cfg_eq(got, cases[i].want), "'%s': got %s/%s", cases[i].banner, ksym_layout_name(got.layout),
                  ksym_addr_name(got.addr));
    }
}

/* ---- synthetic tables, laid out the way scripts/kallsyms emits them ---- */

#define SYN_TEXT 0xffffffff9a000000ull /* _text, and the image start */
#define SYN_RO 0xffffffff9b000000ull   /* the NX run holding the tables */
#define SYN_RO_LEN (1u << 20)
#define SYN_N 1000

typedef struct {
    uint64_t addr;
    char type;
    char name[400];
} syn_sym_t;

typedef struct {
    unsigned char *p;
    size_t len;
} out_t;

static void put(out_t *o, const void *b, size_t n) {
    memcpy(o->p + o->len, b, n);
    o->len += n;
}
static void put32(out_t *o, uint32_t v) {
    put(o, &v, 4);
}
static void put64(out_t *o, uint64_t v) {
    put(o, &v, 8);
}
static void pad8(out_t *o) {
    while (o->len & 7) o->p[o->len++] = 0;
}

/* identity tokens for every printable byte, two compression tokens in
 * spare slots, and the rest left empty the way an unused slot is */
static const char *syn_token(int i, char *one) {
    if (i == 1) return "func_";
    if (i == 2) return "kallsyms";
    if (i >= 0x20 && i <= 0x7e) {
        one[0] = (char) i;
        one[1] = '\0';
        return one;
    }
    return "";
}

static size_t syn_compress(const char *s, unsigned char *out) {
    size_t n = 0;
    while (*s) {
        if (strncmp(s, "func_", 5) == 0) out[n++] = 1, s += 5;
        else if (strncmp(s, "kallsyms", 8) == 0) out[n++] = 2, s += 8;
        else out[n++] = (unsigned char) *s++;
    }
    return n;
}

static syn_sym_t *syn_syms(bool percpu) {
    syn_sym_t *s = calloc(SYN_N, sizeof(*s));
    int i = 0;
    if (percpu) { /* absolute percpu symbols sort first, at 0.. */
        s[i++] = (syn_sym_t) {0x0, 'A', "fixed_percpu_data"};
        s[i++] = (syn_sym_t) {0x0, 'A', "__per_cpu_start"};
        s[i++] = (syn_sym_t) {0x1000, 'A', "cpu_debug_store"};
    }
    s[i++] = (syn_sym_t) {SYN_TEXT, 'T', "_text"};
    uint64_t a = SYN_TEXT;
    for (; i < SYN_N; i++) {
        a += (uint64_t) (i % 7) * 0x10;
        s[i].addr = a;
        s[i].type = "tTdDrRbB"[i % 8];
        if (i == 500) {
            /* past 127 compressed bytes, so the length takes two */
            s[i].type = 't';
            memset(s[i].name, 'x', 300);
        } else if (i == 600 || i == 601) {
            strcpy(s[i].name, "dup");
        } else if (i % 3 == 0) {
            snprintf(s[i].name, sizeof(s[i].name), "func_%d", i);
        } else if (i % 3 == 1) {
            snprintf(s[i].name, sizeof(s[i].name), "kallsyms_thing_%d.cold", i);
        } else {
            snprintf(s[i].name, sizeof(s[i].name), "linux_banner%s", i == 2 + 3 * 100 ? "" : "_not");
        }
    }
    return s;
}

static int cmp_by_name(const void *a, const void *b, void *ctx) {
    const syn_sym_t *s = ctx;
    return strcmp(s[*(const uint32_t *) a].name, s[*(const uint32_t *) b].name);
}

static void syn_tables(out_t *o, const syn_sym_t *s, ksym_layout_t layout, ksym_addr_t mode, uint64_t *relbase_out) {
    uint64_t base = SYN_TEXT; /* lowest relative address: _text */
    *relbase_out = base;

    unsigned char names[SYN_N * 410];
    size_t names_len = 0;
    uint32_t markers[(SYN_N + 255) / 256];
    for (int i = 0; i < SYN_N; i++) {
        if ((i & 0xff) == 0) markers[i >> 8] = (uint32_t) names_len;
        char full[402];
        snprintf(full, sizeof(full), "%c%s", s[i].type, s[i].name);
        unsigned char c[402];
        size_t cl = syn_compress(full, c);
        if (cl <= 0x7f) {
            names[names_len++] = (unsigned char) cl;
        } else {
            names[names_len++] = (unsigned char) ((cl & 0x7f) | 0x80);
            names[names_len++] = (unsigned char) (cl >> 7);
        }
        memcpy(names + names_len, c, cl);
        names_len += cl;
    }

    uint32_t seq[SYN_N];
    for (uint32_t i = 0; i < SYN_N; i++) seq[i] = i;
    qsort_r(seq, SYN_N, sizeof(*seq), cmp_by_name, (void *) s);

#define EMIT_OFFSETS()                                                                                                 \
    do {                                                                                                               \
        for (int i = 0; i < SYN_N; i++) {                                                                              \
            int64_t off;                                                                                               \
            if (mode == KSYM_ADDR_RELATIVE) off = (int64_t) (s[i].addr - base);                                        \
            else if (s[i].type == 'A') off = (int64_t) s[i].addr;                                                      \
            else off = (int64_t) base - 1 - (int64_t) s[i].addr;                                                       \
            put32(o, (uint32_t) off);                                                                                  \
        }                                                                                                              \
        pad8(o);                                                                                                       \
        put64(o, base);                                                                                                \
        pad8(o);                                                                                                       \
    } while (0)
#define EMIT_SEQS()                                                                                                    \
    do {                                                                                                               \
        for (int i = 0; i < SYN_N; i++) {                                                                              \
            unsigned char b[3] = {(unsigned char) (seq[i] >> 16), (unsigned char) (seq[i] >> 8),                       \
                                  (unsigned char) seq[i]};                                                             \
            put(o, b, 3);                                                                                              \
        }                                                                                                              \
        pad8(o);                                                                                                       \
    } while (0)

    if (layout != KSYM_LAYOUT_V6_4) EMIT_OFFSETS();
    put32(o, SYN_N);
    pad8(o);
    put(o, names, names_len);
    pad8(o);
    put(o, markers, sizeof(markers));
    pad8(o);
    if (layout == KSYM_LAYOUT_V6_2) EMIT_SEQS();

    uint16_t idx[256];
    size_t tt = o->len;
    for (int i = 0; i < 256; i++) {
        char one[2];
        const char *tok = syn_token(i, one);
        idx[i] = (uint16_t) (o->len - tt);
        put(o, tok, strlen(tok) + 1);
    }
    pad8(o);
    put(o, idx, sizeof(idx));
    pad8(o);

    if (layout == KSYM_LAYOUT_V6_4) {
        EMIT_OFFSETS();
        EMIT_SEQS();
    }
#undef EMIT_OFFSETS
#undef EMIT_SEQS
}

/* an image whose only loaded run holds a banner, a decoy digit run that
 * isn't a token table, then the tables */
static size_t syn_image(pt_image_t *img, const syn_sym_t *s, ksym_layout_t layout, ksym_addr_t mode,
                        const char *banner) {
    unsigned char *ro = calloc(1, SYN_RO_LEN);
    out_t o = {.p = ro, .len = 0};
    o.len = 0x100;
    put(&o, banner, strlen(banner) + 1);
    o.len = 0x400;
    put(&o, "x0\0001\0002\0003\0004\0005\0006\0007\0008\0009", 21); /* not after a NUL */
    o.len = 0x500;
    put(&o, "\0000\0001\0002\0003\0004\0005\0006\0007\0008\0009\0", 21); /* after one, but no table */
    o.len = 0x1000;
    uint64_t relbase;
    syn_tables(&o, s, layout, mode, &relbase);

    img->start = SYN_TEXT;
    img->end = SYN_RO + 0x400000;
    img->n_runs = 2;
    img->runs = calloc(2, sizeof(pt_run_t));
    img->runs[0] = (pt_run_t) {.va = SYN_TEXT, .len = SYN_RO - SYN_TEXT, .nx = false, .data = NULL};
    img->runs[1] = (pt_run_t) {.va = SYN_RO, .len = SYN_RO_LEN, .nx = true, .data = ro};
    return o.len;
}

static void test_synthetic(ksym_layout_t layout, ksym_addr_t mode) {
    printf("synthetic: %s, %s\n", ksym_layout_name(layout), ksym_addr_name(mode));
    syn_sym_t *s = syn_syms(mode == KSYM_ADDR_ABS_PERCPU);
    /* the real banner lives where the symbol says, so point linux_banner at it */
    for (int i = 0; i < SYN_N; i++)
        if (strcmp(s[i].name, "linux_banner") == 0) s[i].addr = SYN_RO + 0x100;
    /* that broke the address order; move it to keep the table sorted */
    for (int i = 1; i < SYN_N; i++)
        for (int j = i; j > 0 && s[j].addr < s[j - 1].addr; j--) {
            syn_sym_t t = s[j];
            s[j] = s[j - 1];
            s[j - 1] = t;
        }

    pt_image_t img;
    syn_image(&img, s, layout, mode, "Linux version 6.9.0 (syn@test) #1 SMP");

    ksym_cfg_t cfg = {layout, mode};
    ksym_table_t tab;
    char err[256];
    if (ksym_load(&img, &cfg, &tab, err, sizeof(err)) != 0) {
        CHECK(0, "load: %s", err);
    } else {
        CHECK(tab.n == SYN_N, "%zu symbols", tab.n);
        int bad = 0;
        for (size_t i = 0; i < tab.n && i < SYN_N; i++)
            if (tab.syms[i].addr != s[i].addr || tab.syms[i].type != s[i].type || strcmp(tab.syms[i].name, s[i].name))
                if (bad++ < 3)
                    CHECK(0, "sym %zu: got %016" PRIx64 " %c %s, want %016" PRIx64 " %c %s", i, tab.syms[i].addr,
                          tab.syms[i].type, tab.syms[i].name, s[i].addr, s[i].type, s[i].name);
        CHECK(bad == 0, "%d symbols differ", bad);

        int first_dup = 0;
        while (strcmp(s[first_dup].name, "dup") != 0) first_dup++;
        const ksym_t *d = ksym_by_name(&tab, "dup");
        CHECK(d && d == &tab.syms[first_dup], "dup should resolve to the first of the two");
        CHECK(ksym_by_name(&tab, "no_such_symbol") == NULL, "found a symbol that isn't there");
        uint64_t off;
        const ksym_t *at = ksym_by_addr(&tab, s[700].addr + 3, &off);
        CHECK(at && at->addr == s[700].addr && off == 3, "by_addr");
        CHECK(ksym_check_banner(&img, &tab, NULL, 0, err, sizeof(err)) == 0, "banner: %s", err);
        ksym_free(&tab);
    }

    for (size_t i = 0; i < N_CFGS; i++) {
        if (cfg_eq(ALL_CFGS[i], cfg)) continue;
        int rc = ksym_load(&img, &ALL_CFGS[i], &tab, err, sizeof(err));
        CHECK(rc != 0, "%s/%s accepted", ksym_layout_name(ALL_CFGS[i].layout), ksym_addr_name(ALL_CFGS[i].addr));
        if (rc == 0) ksym_free(&tab);
    }

    /* a token table that walks off the end of the run is rejected, not read */
    img.runs[1].len = 0x1000 + 0x40;
    CHECK(ksym_load(&img, &cfg, &tab, err, sizeof(err)) != 0, "truncated run accepted");

    pt_image_free(&img);
    free(s);
}

/* the parser's inputs are guest memory, so garbage must come back as an
 * error and never as a crash or a read past the run. each case gets an
 * exact-size copy, so an over-read is a real overflow under ASan. */
static void test_corrupt(void) {
    printf("synthetic: corrupted and truncated tables\n");
    syn_sym_t *s = syn_syms(false);
    pt_image_t img;
    size_t end = syn_image(&img, s, KSYM_LAYOUT_V6_4, KSYM_ADDR_RELATIVE, "Linux version 6.9.0 #1 SMP");
    unsigned char *orig = img.runs[1].data;
    ksym_cfg_t cfg = {KSYM_LAYOUT_V6_4, KSYM_ADDR_RELATIVE};
    ksym_table_t tab;
    char err[256];

    int accepted = 0, rejected = 0;
    uint64_t x = 0x243f6a8885a308d3ull;
    for (int iter = 0; iter < 3000; iter++) {
        unsigned char *copy = malloc(end);
        memcpy(copy, orig, end);
        int flips = 1 + iter % 4;
        for (int f = 0; f < flips; f++) {
            x ^= x << 13, x ^= x >> 7, x ^= x << 17;
            copy[0x1000 + x % (end - 0x1000)] ^= (unsigned char) (1u << ((x >> 32) % 8));
        }
        img.runs[1].data = copy;
        img.runs[1].len = end;
        if (ksym_load(&img, &cfg, &tab, err, sizeof(err)) == 0) {
            accepted++;
            CHECK(tab.n > 0 && ksym_by_name(&tab, "_text") && ksym_by_name(&tab, "_text")->addr == img.start,
                  "accepted a table without the _text check holding");
            ksym_free(&tab);
        } else {
            rejected++;
        }
        free(copy);
    }
    printf("  %d flips rejected, %d accepted (a flipped name byte can still decode)\n", rejected, accepted);

    /* cut the run at every 8 bytes through the tables: only the full run decodes */
    int cut_ok = 0;
    for (size_t len = 0x1000; len <= end; len += 8) {
        unsigned char *copy = malloc(len);
        memcpy(copy, orig, len);
        img.runs[1].data = copy;
        img.runs[1].len = len;
        if (ksym_load(&img, &cfg, &tab, err, sizeof(err)) == 0) {
            cut_ok++;
            CHECK(len >= end - 8, "decoded with the run cut at 0x%zx of 0x%zx", len, end);
            ksym_free(&tab);
        }
        free(copy);
    }
    CHECK(cut_ok >= 1, "the untruncated run didn't decode");

    img.runs[1].data = orig;
    pt_image_free(&img);
    free(s);
}

/* ---- ram-dump fixtures ---- */

typedef struct {
    char **lines;
    size_t n;
    char *buf;
} truth_t;

/* the core (vmlinux) lines of /proc/kallsyms: module, bpf and ftrace
 * entries end in a tab and a [bracketed] owner */
static int load_truth(const char *dir, const char *name, truth_t *t) {
    char cmd[4200];
    snprintf(cmd, sizeof(cmd), "gzip -dc '%s/%s/kallsyms.gz'", dir, name);
    FILE *f = popen(cmd, "r");
    if (!f) return -1;
    size_t cap = 1 << 24, len = 0;
    t->buf = malloc(cap);
    size_t got;
    while ((got = fread(t->buf + len, 1, cap - len - 1, f)) > 0) {
        len += got;
        if (len + 1 == cap) t->buf = realloc(t->buf, cap *= 2);
    }
    t->buf[len] = '\0';
    if (pclose(f) != 0) return -1;

    size_t lcap = 1 << 18;
    t->lines = malloc(lcap * sizeof(char *));
    t->n = 0;
    for (char *p = t->buf, *nl; *p; p = nl + 1) {
        nl = strchr(p, '\n');
        if (!nl) break;
        *nl = '\0';
        if (strchr(p, '\t')) continue;
        if (t->n == lcap) t->lines = realloc(t->lines, (lcap *= 2) * sizeof(char *));
        t->lines[t->n++] = p;
    }
    return 0;
}

static void test_fixture(const char *dir, const char *name) {
    if (fixture_has_dump(dir, name) <= 0) return;
    printf("fixture %s\n", name);

    char *config = fixture_file(dir, name, "config", NULL);
    char *uname = fixture_file(dir, name, "uname", NULL);
    char *syms = fixture_file(dir, name, "symcheck", NULL);
    size_t live_len = 0;
    char *live = fixture_file(dir, name, "live_banner.bin", &live_len);
    char *regs = NULL;
    truth_t truth = {0};
    CHECK(config && uname && syms && live, "missing fixture files");
    CHECK(load_truth(dir, name, &truth) == 0, "can't read kallsyms.gz");
    if (!config || !uname || !syms || !live || !truth.n) goto out;

    kmem_t m;
    pt_root_t r;
    char err[256];
    if (fixture_open(dir, name, &m, &r, &regs) != 0) goto out;

    pt_image_t img;
    if (pt_image(&m, &r, &img, err, sizeof(err)) != 0) {
        CHECK(0, "pt_image: %s", err);
        kmem_close(&m);
        goto out;
    }
    CHECK(pt_image_read_nx(&m, &r, &img, err, sizeof(err)) == 0, "%s", err);
    kmem_close(&m);

    /* raw scan first: the banner it finds picks the switches */
    uint64_t hits[16];
    size_t n_hits = ksym_banner_scan(&img, hits, 16);
    CHECK(n_hits > 0, "no raw \"Linux version \" in the NX pages");
    ksym_cfg_t cfg = {0};
    bool have_cfg = false;
    for (size_t i = 0; i < n_hits && i < 16 && !have_cfg; i++) {
        char b[512] = "";
        for (size_t l = 0; l < sizeof(b) - 1 && pt_image_ptr(&img, hits[i] + l, 1); l++)
            if (!(b[l] = (char) *pt_image_ptr(&img, hits[i] + l, 1))) break;
        have_cfg = ksym_cfg_from_banner(b, &cfg, NULL, 0) == 0;
    }
    CHECK(have_cfg, "no raw hit parses as a banner");

    /* the switches the fixture's own config and version say it needs */
    unsigned maj = 0, min = 0;
    sscanf(uname, "%u.%u", &maj, &min);
    ksym_cfg_t want = {
        .layout = maj * 1000 + min < 6002 ? KSYM_LAYOUT_V5
                  : maj * 1000 + min < 6004 ? KSYM_LAYOUT_V6_2
                                            : KSYM_LAYOUT_V6_4,
        .addr = strstr(config, "CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y") ? KSYM_ADDR_ABS_PERCPU : KSYM_ADDR_RELATIVE,
    };
    printf("  %zu raw banner hit(s); switches %s, %s\n", n_hits, ksym_layout_name(cfg.layout),
           ksym_addr_name(cfg.addr));
    CHECK(cfg_eq(cfg, want), "banner picked %s/%s, config says %s/%s", ksym_layout_name(cfg.layout),
          ksym_addr_name(cfg.addr), ksym_layout_name(want.layout), ksym_addr_name(want.addr));

    ksym_table_t tab;
    if (ksym_load(&img, &cfg, &tab, err, sizeof(err)) != 0) {
        CHECK(0, "ksym_load: %s", err);
        pt_image_free(&img);
        goto out;
    }
    printf("  %zu symbols; token_table 0x%" PRIx64 ", names 0x%" PRIx64 ", offsets 0x%" PRIx64
           ", relative_base 0x%" PRIx64 "\n",
           tab.n, tab.va_token_table, tab.va_names, tab.va_offsets, tab.relative_base);

    /* where the kernel lists its own tables (6.x does), they must agree */
    static const struct {
        const char *sym;
        size_t field;
    } tables[] = {
        {"kallsyms_num_syms", offsetof(ksym_table_t, va_num_syms)},
        {"kallsyms_names", offsetof(ksym_table_t, va_names)},
        {"kallsyms_markers", offsetof(ksym_table_t, va_markers)},
        {"kallsyms_token_table", offsetof(ksym_table_t, va_token_table)},
        {"kallsyms_token_index", offsetof(ksym_table_t, va_token_index)},
        {"kallsyms_offsets", offsetof(ksym_table_t, va_offsets)},
        {"kallsyms_seqs_of_names", offsetof(ksym_table_t, va_seqs)},
    };
    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
        const ksym_t *s = ksym_by_name(&tab, tables[i].sym);
        uint64_t found;
        memcpy(&found, (char *) &tab + tables[i].field, 8);
        if (s) CHECK(s->addr == found, "%s: found at 0x%" PRIx64 ", symbol says 0x%" PRIx64, tables[i].sym, found,
                     s->addr);
    }

    /* done-when: every core symbol matches /proc/kallsyms */
    CHECK(tab.n == truth.n, "%zu symbols decoded, /proc/kallsyms has %zu", tab.n, truth.n);
    size_t bad = 0;
    for (size_t i = 0; i < tab.n && i < truth.n; i++) {
        char line[1100];
        snprintf(line, sizeof(line), "%016" PRIx64 " %c %s", tab.syms[i].addr, tab.syms[i].type, tab.syms[i].name);
        if (strcmp(line, truth.lines[i]) != 0 && bad++ < 5)
            CHECK(0, "line %zu: got '%s', want '%s'", i, line, truth.lines[i]);
    }
    CHECK(bad == 0, "%zu of %zu symbols differ", bad, tab.n);
    if (!bad && tab.n == truth.n) printf("  all %zu symbols match /proc/kallsyms\n", tab.n);

    /* _text is the image start (ksym_load enforces it; this says so out loud) */
    const ksym_t *text = ksym_by_name(&tab, "_text");
    CHECK(text && text->addr == img.start, "_text != image start");

    char banner[1024];
    if (ksym_check_banner(&img, &tab, banner, sizeof(banner), err, sizeof(err)) == 0) {
        CHECK(strlen(banner) == live_len && memcmp(banner, live, live_len) == 0, "banner differs from the live read");
    } else {
        CHECK(0, "%s", err);
    }

    uint64_t lstar, off;
    regs_get(regs, "lstar", &lstar);
    const ksym_t *entry = ksym_by_addr(&tab, lstar, &off);
    CHECK(entry && strcmp(entry->name, "entry_SYSCALL_64") == 0 && off == 0, "lstar resolves to %s+0x%" PRIx64,
          entry ? entry->name : "?", off);
    const char *need[] = {"linux_banner", "init_top_pgt", "init_task", "sys_call_table", "phys_base", "__start_BTF"};
    for (size_t i = 0; i < sizeof(need) / sizeof(need[0]); i++) {
        uint64_t a;
        const ksym_t *s = ksym_by_name(&tab, need[i]);
        CHECK(sym_get(syms, need[i], &a) == 0 && s && s->addr == a, "%s", need[i]);
    }
    ksym_free(&tab);

    /* every other switch combination is rejected, not decoded into garbage */
    for (size_t i = 0; i < N_CFGS; i++) {
        if (cfg_eq(ALL_CFGS[i], cfg)) continue;
        int rc = ksym_load(&img, &ALL_CFGS[i], &tab, err, sizeof(err));
        CHECK(rc != 0, "%s/%s accepted", ksym_layout_name(ALL_CFGS[i].layout), ksym_addr_name(ALL_CFGS[i].addr));
        if (rc == 0) ksym_free(&tab);
        else if (ALL_CFGS[i].addr == cfg.addr) printf("  rejected as %s: %s\n", ksym_layout_name(ALL_CFGS[i].layout), err);
    }
    pt_image_free(&img);

out:
    free(config);
    free(uname);
    free(syms);
    free(live);
    free(regs);
    free(truth.lines);
    free(truth.buf);
}

int main(int argc, char **argv) {
    test_cfg_from_banner();
    for (int l = KSYM_LAYOUT_V5; l <= KSYM_LAYOUT_V6_4; l++)
        for (int a = KSYM_ADDR_RELATIVE; a <= KSYM_ADDR_ABS_PERCPU; a++) test_synthetic(l, a);
    test_corrupt();

    for_each_fixture(argc > 1 ? argv[1] : "tests/fixtures", test_fixture);

    printf(failures ? "\n%d FAILED\n" : "\nall passed\n", failures);
    return failures ? 1 : 0;
}
