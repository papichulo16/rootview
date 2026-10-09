#include "kern/prof/pt.h"

#include <inttypes.h>
#include <stdio.h>

#define PTE_PRESENT (1ull << 0)
#define PTE_PS (1ull << 7)
#define PTE_NX (1ull << 63)

static bool is_canonical(uint64_t va, bool la57) {
    int bits = la57 ? 57 : 48;
    int64_t sign = (int64_t) (va << (64 - bits)) >> (64 - bits);
    return (uint64_t) sign == va;
}

int pt_translate(const kmem_t *mem, const pt_root_t *root, uint64_t va, uint64_t *pa, uint64_t *page_size, char *err,
                 size_t err_len) {
    if (!is_canonical(va, root->la57)) {
        if (err) snprintf(err, err_len, "0x%" PRIx64 " is not canonical", va);
        return -1;
    }

    uint64_t table = root->pgd & PT_PA_MASK;
    int level = root->la57 ? 5 : 4;

    for (; level >= 1; level--) {
        int shift = 12 + 9 * (level - 1);
        uint64_t slot = table + ((va >> shift) & 0x1ff) * 8;

        uint64_t ent;
        if (kmem_read_pa(mem, slot, &ent, sizeof(ent), err, err_len) != 0) return -1;
        if (!(ent & PTE_PRESENT)) {
            if (err) snprintf(err, err_len, "0x%" PRIx64 " not present at level %d (entry at pa 0x%" PRIx64 ")", va,
                              level, slot);
            return -1;
        }

        /* PS only means a large page in the PDPTE (1GiB) and PDE (2MiB) */
        if (level == 1 || ((level == 2 || level == 3) && (ent & PTE_PS))) {
            uint64_t size = 1ull << shift;
            *pa = (ent & PT_PA_MASK & ~(size - 1)) | (va & (size - 1));
            if (page_size) *page_size = size;
            return 0;
        }
        table = ent & PT_PA_MASK;
    }

    return -1; /* unreachable: level 1 always returns */
}

int pt_read(const kmem_t *mem, const pt_root_t *root, uint64_t va, void *buf, size_t len, char *err, size_t err_len) {
    size_t done = 0;
    while (done < len) {
        uint64_t pa, size;
        if (pt_translate(mem, root, va + done, &pa, &size, err, err_len) != 0) return -1;

        size_t chunk = size - ((va + done) & (size - 1));
        if (chunk > len - done) chunk = len - done;
        if (kmem_read_pa(mem, pa, (char *) buf + done, chunk, err, err_len) != 0) return -1;
        done += chunk;
    }
    return 0;
}

typedef struct {
    const kmem_t *mem;
    uint64_t start, end;
    size_t left;
    pt_page_fn fn;
    void *ctx;
    char *err;
    size_t err_len;
} pages_t;

/* table: physical address of a level-`level` table mapping va_base up */
static int pages_level(pages_t *p, uint64_t table, int level, uint64_t va_base, bool nx) {
    int shift = 12 + 9 * (level - 1);
    uint64_t span = 1ull << shift;
    uint64_t ents[512];
    if (kmem_read_pa(p->mem, table & PT_PA_MASK, ents, sizeof(ents), p->err, p->err_len) != 0) return -1;
    for (unsigned i = 0; i < 512; i++) {
        uint64_t va = va_base + i * span;
        if (level == 4) va = (uint64_t) ((int64_t) (va << 16) >> 16); /* sign-extend bit 47 */
        uint64_t last = va + span - 1;
        if (last < p->start || va >= p->end) continue;
        uint64_t e = ents[i];
        if (!(e & PTE_PRESENT)) continue;
        bool enx = nx || (e & PTE_NX);
        if (level == 1 || ((level == 2 || level == 3) && (e & PTE_PS))) {
            if (p->left == 0) {
                if (p->err) snprintf(p->err, p->err_len, "more than the page cap under 0x%016" PRIx64, p->start);
                return -1;
            }
            p->left--;
            int rc = p->fn(va, e & PT_PA_MASK & ~(span - 1), span, enx, p->ctx);
            if (rc) return rc;
            continue;
        }
        int rc = pages_level(p, e, level - 1, va, enx);
        if (rc) return rc;
    }
    return 0;
}

int pt_for_each_page(const kmem_t *mem, const pt_root_t *root, uint64_t start, uint64_t end, size_t max_pages,
                     pt_page_fn fn, void *ctx, char *err, size_t err_len) {
    if (root->la57) {
        if (err) snprintf(err, err_len, "5-level paging isn't supported");
        return -1;
    }
    pages_t p = {mem, start, end, max_pages, fn, ctx, err, err_len};
    return pages_level(&p, root->pgd, 4, 0, false);
}
