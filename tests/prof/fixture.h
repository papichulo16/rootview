/* shared by the prof tests: the CHECK macro and the fixture readers. each
 * test binary includes this once and gets its own failure count. */
#ifndef ROOTVIEW_TEST_FIXTURE_H
#define ROOTVIEW_TEST_FIXTURE_H

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "kern/prof/kmem.h"
#include "kern/prof/kprof.h"
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

/* reads dir/name/file, or NULL */
static char *fixture_file(const char *dir, const char *name, const char *file, size_t *len) {
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s/%s", dir, name, file);
    unsigned char *out;
    size_t l;
    if (read_file(path, &out, &l) != 0) return NULL;
    if (len) *len = l;
    return (char *) out;
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

/* address of name in kallsyms-format text */
__attribute__((unused)) static int sym_get(const char *kallsyms, const char *name, uint64_t *addr) {
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

/* 1 if dir/name is a fixture with a dump, 0 if it isn't a fixture, -1 if
 * it is one but mem.raw is missing (prints the SKIP) */
static int fixture_has_dump(const char *dir, const char *name) {
    char path[4096];
    struct stat st;
    snprintf(path, sizeof(path), "%s/%s/regs", dir, name);
    if (stat(path, &st) != 0) return 0;
    snprintf(path, sizeof(path), "%s/%s/mem.raw", dir, name);
    if (stat(path, &st) != 0) {
        printf("fixture %s: SKIP (no mem.raw)\n", name);
        return -1;
    }
    return 1;
}

/* opens the dump and derives the kernel root from regs, the way the live
 * path does. regs_out (optional) keeps the regs text. */
__attribute__((unused)) static int fixture_open(const char *dir, const char *name, kmem_t *m, pt_root_t *r, char **regs_out) {
    char *regs = fixture_file(dir, name, "regs", NULL);
    uint64_t cr3, cr4, lstar;
    if (!regs || regs_get(regs, "cr3", &cr3) || regs_get(regs, "cr4", &cr4) || regs_get(regs, "lstar", &lstar)) {
        CHECK(0, "bad regs for %s", name);
        free(regs);
        return -1;
    }

    char path[4096], err[256];
    snprintf(path, sizeof(path), "%s/%s/mem.raw", dir, name);
    if (kmem_dump_open(path, m, err, sizeof(err)) != 0) {
        CHECK(0, "%s", err);
        free(regs);
        return -1;
    }
    if (pt_root_from_cr3(m, cr3, cr4, lstar, r, err, sizeof(err)) != 0) {
        CHECK(0, "pt_root: %s", err);
        kmem_close(m);
        free(regs);
        return -1;
    }
    if (regs_out) *regs_out = regs;
    else free(regs);
    return 0;
}

/* a kprof_target_t over a dump: pause and resume only count, and the
 * registers come from the fixture's regs file */
typedef struct {
    kprof_regs_t regs;
    int pauses, resumes;
} dump_ctx_t;

__attribute__((unused)) static int dump_pause(void *ctx, char *err, size_t err_len) {
    (void) err, (void) err_len;
    ((dump_ctx_t *) ctx)->pauses++;
    return 0;
}

__attribute__((unused)) static int dump_resume(void *ctx, char *err, size_t err_len) {
    (void) err, (void) err_len;
    ((dump_ctx_t *) ctx)->resumes++;
    return 0;
}

__attribute__((unused)) static int dump_regs(void *ctx, kprof_regs_t *regs, char *err, size_t err_len) {
    (void) err, (void) err_len;
    *regs = ((dump_ctx_t *) ctx)->regs;
    return 0;
}

/* opens the dump and runs kprof_init over it, as test_kprof checks in
 * full. ctx and target must outlive kp; kmem_close(&target->mem) after. */
__attribute__((unused)) static int fixture_kprof(const char *dir, const char *name, dump_ctx_t *ctx,
                                                 kprof_target_t *target, kprof_t *kp) {
    char *regs = fixture_file(dir, name, "regs", NULL);
    *ctx = (dump_ctx_t) {0};
    if (!regs || regs_get(regs, "cr3", &ctx->regs.cr3) || regs_get(regs, "cr4", &ctx->regs.cr4) ||
        regs_get(regs, "lstar", &ctx->regs.lstar) || regs_get(regs, "idtr", &ctx->regs.idtr_base)) {
        CHECK(0, "bad regs for %s", name);
        free(regs);
        return -1;
    }
    free(regs);
    char path[4096], err[512];
    *target = (kprof_target_t) {.pause = dump_pause, .resume = dump_resume, .read_regs = dump_regs, .ctx = ctx};
    snprintf(path, sizeof(path), "%s/%s/mem.raw", dir, name);
    if (kmem_dump_open(path, &target->mem, err, sizeof(err)) != 0) {
        CHECK(0, "%s", err);
        return -1;
    }
    if (kprof_init(kp, target, err, sizeof(err)) != 0) {
        CHECK(0, "kprof_init: %s", err);
        kmem_close(&target->mem);
        return -1;
    }
    return 0;
}

/* calls fn for each subdirectory of dir, sorted, so output order is stable */
static int cmp_str(const void *a, const void *b) {
    return strcmp(*(char *const *) a, *(char *const *) b);
}

static void for_each_fixture(const char *dir, void (*fn)(const char *dir, const char *name)) {
    DIR *d = opendir(dir);
    if (!d) return;
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
    qsort(names, (size_t) n, sizeof(*names), cmp_str);
    for (int i = 0; i < n; i++) {
        int before = failures;
        fn(dir, names[i]);
        if (failures != before) printf("  (fixture %s failed)\n", names[i]);
        free(names[i]);
    }
}

#endif
