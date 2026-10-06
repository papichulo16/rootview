#include "kern/prof/pt.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PTE_PRESENT (1ull << 0)
#define PTE_PS (1ull << 7)
#define PTE_NX (1ull << 63)

#define PML_TOP 511  /* PML5[511] and PML4[511] */
#define PDPT_KIMG 510

static int read_table(const kmem_t *mem, uint64_t ent, uint64_t out[512], char *err, size_t err_len) {
    if (kmem_read_pa(mem, ent & PT_PA_MASK, out, 4096, err, err_len) != 0) return -1;
    return 0;
}

static int add_page(pt_image_t *img, size_t *cap, uint64_t va, uint64_t len, bool nx, char *err, size_t err_len) {
    if (img->n_runs) {
        pt_run_t *last = &img->runs[img->n_runs - 1];
        if (last->va + last->len == va && last->nx == nx) {
            last->len += len;
            return 0;
        }
    }
    if (img->n_runs == *cap) {
        size_t ncap = *cap ? *cap * 2 : 64;
        pt_run_t *n = realloc(img->runs, ncap * sizeof(*n));
        if (!n) {
            if (err) snprintf(err, err_len, "out of memory");
            return -1;
        }
        img->runs = n;
        *cap = ncap;
    }
    img->runs[img->n_runs++] = (pt_run_t) {.va = va, .len = len, .nx = nx, .data = NULL};
    return 0;
}

int pt_image(const kmem_t *mem, const pt_root_t *root, pt_image_t *img, char *err, size_t err_len) {
    *img = (pt_image_t) {0};
    uint64_t tbl[512];
    uint64_t ent = root->pgd | PTE_PRESENT;
    bool nx = false;

    int levels = root->la57 ? 2 : 1; /* PML5[511], then PML4[511] */
    for (int i = 0; i < levels; i++) {
        if (read_table(mem, ent, tbl, err, err_len) != 0) return -1;
        ent = tbl[PML_TOP];
        if (!(ent & PTE_PRESENT)) {
            if (err) snprintf(err, err_len, "PML%d[511] not present", root->la57 && i == 0 ? 5 : 4);
            return -1;
        }
        nx |= (ent & PTE_NX) != 0;
    }

    if (read_table(mem, ent, tbl, err, err_len) != 0) return -1;
    ent = tbl[PDPT_KIMG];
    if (!(ent & PTE_PRESENT)) {
        if (err) snprintf(err, err_len, "PDPT[510] not present");
        return -1;
    }
    if (ent & PTE_PS) {
        if (err) snprintf(err, err_len, "PDPT[510] is a 1GiB page, not an image mapping");
        return -1;
    }
    nx |= (ent & PTE_NX) != 0;

    uint64_t pd[512];
    if (read_table(mem, ent, pd, err, err_len) != 0) return -1;

    int lo = 0;
    while (lo < 512 && !(pd[lo] & PTE_PRESENT)) lo++;
    if (lo == 512) {
        if (err) snprintf(err, err_len, "no present PD entry under PDPT[510]");
        return -1;
    }
    int hi = lo;
    while (hi < 512 && (pd[hi] & PTE_PRESENT)) hi++;

    img->start = PT_KIMG_BASE + ((uint64_t) lo << 21);
    img->end = PT_KIMG_BASE + ((uint64_t) hi << 21);

    size_t cap = 0;
    uint64_t pt[512];
    for (int i = lo; i < hi; i++) {
        uint64_t va = PT_KIMG_BASE + ((uint64_t) i << 21);
        bool pd_nx = nx || (pd[i] & PTE_NX);
        if (pd[i] & PTE_PS) {
            if (add_page(img, &cap, va, 2ull << 20, pd_nx, err, err_len) != 0) goto fail;
            continue;
        }
        if (read_table(mem, pd[i], pt, err, err_len) != 0) goto fail;
        for (int j = 0; j < 512; j++) {
            if (!(pt[j] & PTE_PRESENT)) continue;
            bool pte_nx = pd_nx || (pt[j] & PTE_NX);
            if (add_page(img, &cap, va + ((uint64_t) j << 12), 4096, pte_nx, err, err_len) != 0) goto fail;
        }
    }
    return 0;

fail:
    pt_image_free(img);
    return -1;
}

int pt_image_read_nx(const kmem_t *mem, const pt_root_t *root, pt_image_t *img, char *err, size_t err_len) {
    for (size_t i = 0; i < img->n_runs; i++) {
        pt_run_t *r = &img->runs[i];
        if (!r->nx || r->data) continue;
        r->data = malloc(r->len);
        if (!r->data) {
            if (err) snprintf(err, err_len, "out of memory reading run at 0x%" PRIx64 " (+0x%" PRIx64 ")", r->va,
                              r->len);
            return -1;
        }
        if (pt_read(mem, root, r->va, r->data, r->len, err, err_len) != 0) {
            free(r->data);
            r->data = NULL;
            return -1;
        }
    }
    return 0;
}

const unsigned char *pt_image_ptr(const pt_image_t *img, uint64_t va, size_t len) {
    for (size_t i = 0; i < img->n_runs; i++) {
        const pt_run_t *r = &img->runs[i];
        if (!r->data || va < r->va || va - r->va >= r->len) continue;
        if (len > r->len - (va - r->va)) return NULL;
        return r->data + (va - r->va);
    }
    return NULL;
}

void pt_image_free(pt_image_t *img) {
    for (size_t i = 0; i < img->n_runs; i++) free(img->runs[i].data);
    free(img->runs);
    *img = (pt_image_t) {0};
}
