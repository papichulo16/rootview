#ifndef ROOTVIEW_KMEM_H
#define ROOTVIEW_KMEM_H

#include <stddef.h>
#include <stdint.h>

/* guest-physical memory source for the kernel profiler. everything above
 * this (page walks, kallsyms, btf) reads through a kmem_t, so the same code
 * runs against a live vm (kmem_vmi.h) or a raw ram dump (kmem_dump_open).
 * read_pa returns 0 on success, -1 with err filled on failure. */
typedef struct {
    int (*read_pa)(void *ctx, uint64_t pa, void *buf, size_t len, char *err, size_t err_len);
    void (*close)(void *ctx);
    void *ctx;
} kmem_t;

static inline int kmem_read_pa(const kmem_t *mem, uint64_t pa, void *buf, size_t len, char *err, size_t err_len) {
    return mem->read_pa(mem->ctx, pa, buf, len, err, err_len);
}

static inline void kmem_close(kmem_t *mem) {
    if (mem->close) mem->close(mem->ctx);
    mem->ctx = NULL;
}

/* raw dump from `pmemsave 0 <ram bytes> file`: file offset == guest-physical
 * address. only valid when guest ram is one contiguous range starting at 0,
 * i.e. guests with <= 2GiB so qemu doesn't split ram around the pci hole. */
int kmem_dump_open(const char *path, kmem_t *mem, char *err, size_t err_len);

#endif
