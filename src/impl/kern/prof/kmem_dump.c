#include "kern/prof/kmem.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    int fd;
    uint64_t size;
} dump_ctx_t;

static int dump_read_pa(void *ctx, uint64_t pa, void *buf, size_t len, char *err, size_t err_len) {
    dump_ctx_t *d = ctx;
    if (pa > d->size || len > d->size - pa) {
        if (err) snprintf(err, err_len, "pa 0x%" PRIx64 "+%zu is past the end of the dump", pa, len);
        return -1;
    }

    size_t done = 0;
    while (done < len) {
        ssize_t n = pread(d->fd, (char *) buf + done, len - done, (off_t) (pa + done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            if (err) snprintf(err, err_len, "dump read failed at pa 0x%" PRIx64, pa + done);
            return -1;
        }
        done += (size_t) n;
    }
    return 0;
}

static void dump_close(void *ctx) {
    dump_ctx_t *d = ctx;
    if (!d) return;
    close(d->fd);
    free(d);
}

int kmem_dump_open(const char *path, kmem_t *mem, char *err, size_t err_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (err) snprintf(err, err_len, "open '%s': %s", path, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        if (err) snprintf(err, err_len, "stat '%s': %s", path, strerror(errno));
        close(fd);
        return -1;
    }

    dump_ctx_t *d = malloc(sizeof(*d));
    if (!d) {
        if (err) snprintf(err, err_len, "out of memory");
        close(fd);
        return -1;
    }
    d->fd = fd;
    d->size = (uint64_t) st.st_size;

    *mem = (kmem_t) {.read_pa = dump_read_pa, .close = dump_close, .ctx = d};
    return 0;
}
