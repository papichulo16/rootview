#include "kern/prof/pt.h"

#include <inttypes.h>
#include <stdio.h>

#define PTE_PRESENT (1ull << 0)
#define PTE_PS (1ull << 7)

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
