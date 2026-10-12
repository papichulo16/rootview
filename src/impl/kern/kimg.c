#include "kern/kimg.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vmi/vmi.h"

#define PAGE_SIZE_4K 4096ull
#define CHUNK_SIZE (2ull << 20)

/* the 1GiB the image is mapped in; the module area starts right after it */
#define KIMG_AREA_START 0xffffffff80000000ull
#define KIMG_AREA_END 0xffffffffc0000000ull

static bool kimg_is_mapped(vmi_session_t *session, uint64_t va) {
    uint64_t pa;
    return vmi_translate_virt(session, va, &pa, NULL, 0) == 0;
}

/* head64 unmaps everything in the area below _text, which is 2MiB-aligned */
static uint64_t kimg_find_start(vmi_session_t *session, uint64_t anchor_va) {
    uint64_t start = anchor_va & ~(CHUNK_SIZE - 1);
    while (start - CHUNK_SIZE >= KIMG_AREA_START && kimg_is_mapped(session, start - CHUNK_SIZE)) start -= CHUNK_SIZE;
    return start;
}

/* one 2MiB chunk at va into buf, page by page only when the whole read fails.
 * returns how many pages were mapped. */
static size_t kimg_read_chunk(vmi_session_t *session, uint64_t va, unsigned char *buf, bool *present) {
    size_t n_pages = CHUNK_SIZE / PAGE_SIZE_4K, n_present = 0;

    if (vmi_read_virt(session, va, buf, CHUNK_SIZE, NULL, 0) == 0) {
        memset(present, 1, n_pages * sizeof(*present));
        n_present = n_pages;
        goto out;
    }
    for (size_t i = 0; i < n_pages; i++) {
        unsigned char *page = buf + i * PAGE_SIZE_4K;
        present[i] = vmi_read_virt(session, va + i * PAGE_SIZE_4K, page, PAGE_SIZE_4K, NULL, 0) == 0;
        if (present[i]) n_present++;
        else memset(page, 0, PAGE_SIZE_4K);
    }

out:
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
    *img = (kimg_t) {0};
    if (anchor_va < KIMG_AREA_START || anchor_va >= KIMG_AREA_END) {
        if (err) snprintf(err, err_len, "anchor 0x%" PRIx64 " isn't in the kernel image area", anchor_va);
        goto out;
    }

    img->start = kimg_find_start(session, anchor_va);
    img->end = img->start;
    present = calloc((KIMG_AREA_END - img->start) / PAGE_SIZE_4K, sizeof(*present));
    if (!present) goto oom;

    /* the image ends at the first 2MiB with nothing mapped in it */
    while (img->end < KIMG_AREA_END) {
        uint64_t off = img->end - img->start;
        unsigned char *grown = realloc(img->data, off + CHUNK_SIZE);
        if (!grown) goto oom;
        img->data = grown;
        if (kimg_read_chunk(session, img->end, img->data + off, present + off / PAGE_SIZE_4K) == 0) break;
        img->end += CHUNK_SIZE;
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
