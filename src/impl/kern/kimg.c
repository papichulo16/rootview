#include "kern/kimg.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vmi/vmi.h"

#define PAGE_SIZE_4K 4096ull
#define CHUNK_SIZE (2ull << 20)

/* x86_64: the 1GiB the image is mapped in; the module area starts right after it */
#define KIMG_X86_AREA_START 0xffffffff80000000ull
#define KIMG_X86_AREA_END 0xffffffffc0000000ull
/* arm64: the image is randomized anywhere in vmalloc space and is far smaller than this */
#define KIMG_ARM64_SPAN (512ull << 20)
/* arm64: the biggest hole inside the image (its freed init sections) */
#define KIMG_ARM64_GAP_MAX (16ull << 20)
/* arm64: how far below _stext the unmapped image header (_text) can sit */
#define KIMG_ARM64_HEAD_MAX (2ull << 20)

typedef struct {
    vmi_session_t *session;
    bool same_offset; /* arm64: only pages at the anchor's VA-to-PA offset are the image */
    uint64_t offset;
    uint64_t area_start, area_end;
} kimg_ctx_t;

static bool kimg_owns(const kimg_ctx_t *ctx, uint64_t va) {
    uint64_t pa;
    bool mapped = vmi_translate_virt(ctx->session, va, &pa, NULL, 0) == 0;
    return mapped && (!ctx->same_offset || pa - va == ctx->offset);
}

static int kimg_ctx_init(kimg_ctx_t *ctx, vmi_session_t *session, uint64_t anchor_va, char *err, size_t err_len) {
    int rc = -1;
    uint64_t pa;

    *ctx = (kimg_ctx_t) {.session = session, .area_start = KIMG_X86_AREA_START, .area_end = KIMG_X86_AREA_END};
    if (vmi_arch(session) == VMI_ARCH_ARM64) {
        if (vmi_translate_virt(session, anchor_va, &pa, err, err_len) != 0) goto out;
        ctx->same_offset = true;
        ctx->offset = pa - anchor_va;
        ctx->area_start = (anchor_va & ~(CHUNK_SIZE - 1)) - KIMG_ARM64_SPAN;
        ctx->area_end = anchor_va > UINT64_MAX - KIMG_ARM64_SPAN ? UINT64_MAX & ~(CHUNK_SIZE - 1)
                                                                 : (anchor_va & ~(CHUNK_SIZE - 1)) + KIMG_ARM64_SPAN;
    }
    if (anchor_va < ctx->area_start || anchor_va >= ctx->area_end) {
        if (err) snprintf(err, err_len, "anchor 0x%" PRIx64 " isn't in the kernel image area", anchor_va);
        goto out;
    }
    rc = 0;

out:
    return rc;
}

/* x86_64: head64 unmaps everything in the area below _text, which is 2MiB-aligned.
 * arm64: _stext is only page-aligned, so step down a page at a time. */
static uint64_t kimg_find_start(const kimg_ctx_t *ctx, uint64_t anchor_va) {
    uint64_t step = ctx->same_offset ? PAGE_SIZE_4K : CHUNK_SIZE;
    uint64_t start = anchor_va & ~(step - 1);
    while (start - step >= ctx->area_start && kimg_owns(ctx, start - step)) start -= step;
    return start;
}

/* the pages of [va, va + n pages) that are the image, read a run at a time */
static size_t kimg_read_pages(const kimg_ctx_t *ctx, uint64_t va, unsigned char *buf, bool *present, size_t n_pages) {
    size_t n_present = 0;

    for (size_t i = 0; i < n_pages; i++) present[i] = kimg_owns(ctx, va + i * PAGE_SIZE_4K);
    for (size_t i = 0; i < n_pages;) {
        size_t run = 0;
        while (i + run < n_pages && present[i + run]) run++;
        if (run && vmi_read_virt(ctx->session, va + i * PAGE_SIZE_4K, buf + i * PAGE_SIZE_4K, run * PAGE_SIZE_4K,
                                 NULL, 0) != 0) {
            /* a run that won't read whole: page by page */
            for (size_t j = i; j < i + run; j++)
                present[j] = vmi_read_virt(ctx->session, va + j * PAGE_SIZE_4K, buf + j * PAGE_SIZE_4K,
                                           PAGE_SIZE_4K, NULL, 0) == 0;
        }
        for (size_t j = i; j < i + run; j++) n_present += present[j];
        i += run ? run : 1;
    }
    for (size_t i = 0; i < n_pages; i++)
        if (!present[i]) memset(buf + i * PAGE_SIZE_4K, 0, PAGE_SIZE_4K);
    return n_present;
}

/* one 2MiB chunk at va into buf: in one read when it's all mapped (x86_64),
 * otherwise only its image pages. returns how many pages were the image. */
static size_t kimg_read_chunk(const kimg_ctx_t *ctx, uint64_t va, unsigned char *buf, bool *present) {
    size_t n_pages = CHUNK_SIZE / PAGE_SIZE_4K, n_present = n_pages;

    if (!ctx->same_offset && vmi_read_virt(ctx->session, va, buf, CHUNK_SIZE, NULL, 0) == 0)
        memset(present, 1, n_pages * sizeof(*present));
    else
        n_present = kimg_read_pages(ctx, va, buf, present, n_pages);
    return n_present;
}

static int kimg_build_runs(kimg_t *img, const bool *present, size_t n_pages) {
    int rc = -1;
    size_t count = 0;
    for (size_t i = 0; i < n_pages; i++)
        if (present[i] && (i == 0 || !present[i - 1])) count++;

    img->runs = calloc(count ? count : 1, sizeof(*img->runs));
    if (!img->runs) goto out;

    for (size_t i = 0; i < n_pages; i++) {
        if (!present[i]) continue;
        if (i == 0 || !present[i - 1]) {
            uint64_t off = i * PAGE_SIZE_4K;
            img->runs[img->n_runs++] = (kimg_run_t) {.va = img->start + off, .len = 0, .data = img->data + off};
        }
        img->runs[img->n_runs - 1].len += PAGE_SIZE_4K;
    }
    rc = 0;

out:
    return rc;
}

int kimg_load(vmi_session_t *session, uint64_t anchor_va, kimg_t *img, char *err, size_t err_len) {
    int rc = -1;
    bool *present = NULL;
    kimg_ctx_t ctx;
    *img = (kimg_t) {0};
    if (kimg_ctx_init(&ctx, session, anchor_va, err, err_len) != 0) goto out;

    img->start = kimg_find_start(&ctx, anchor_va);
    img->end = img->start;
    img->text_min = ctx.same_offset ? img->start - KIMG_ARM64_HEAD_MAX : img->start;
    present = calloc((ctx.area_end - img->start) / PAGE_SIZE_4K + CHUNK_SIZE / PAGE_SIZE_4K, sizeof(*present));
    if (!present) goto oom;

    /* the image ends at the first 2MiB with none of it in there. arm64 frees
     * and unmaps its init sections between rodata and data, so there it's the
     * first KIMG_ARM64_GAP_MAX with none of it. */
    uint64_t scan = img->start, gap_max = ctx.same_offset ? KIMG_ARM64_GAP_MAX : CHUNK_SIZE;
    while (scan < ctx.area_end && scan - img->end < gap_max) {
        uint64_t off = scan - img->start;
        unsigned char *grown = realloc(img->data, off + CHUNK_SIZE);
        if (!grown) goto oom;
        img->data = grown;
        if (kimg_read_chunk(&ctx, scan, img->data + off, present + off / PAGE_SIZE_4K) != 0)
            img->end = scan + CHUNK_SIZE;
        scan += CHUNK_SIZE;
    }
    if (img->end == img->start) {
        if (err) snprintf(err, err_len, "nothing is mapped at the anchor 0x%" PRIx64, anchor_va);
        goto out;
    }
    if (kimg_build_runs(img, present, (img->end - img->start) / PAGE_SIZE_4K) != 0) goto oom;
    rc = 0;
    goto out;

oom:
    if (err) snprintf(err, err_len, "out of memory copying the image");
out:
    free(present);
    if (rc != 0) kimg_free(img);
    return rc;
}

const unsigned char *kimg_ptr(const kimg_t *img, uint64_t va, size_t len) {
    const unsigned char *p = NULL;
    for (size_t i = 0; i < img->n_runs; i++) {
        const kimg_run_t *r = &img->runs[i];
        if (va < r->va || va - r->va >= r->len) continue;
        if (len <= r->len - (va - r->va)) p = r->data + (va - r->va);
        break;
    }
    return p;
}

void kimg_free(kimg_t *img) {
    free(img->data);
    free(img->runs);
    *img = (kimg_t) {0};
}
