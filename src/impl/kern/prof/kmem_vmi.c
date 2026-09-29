#include "kern/prof/kmem_vmi.h"

#include "vmi/vmi.h"

static int vmi_mem_read_pa(void *ctx, uint64_t pa, void *buf, size_t len, char *err, size_t err_len) {
    return vmi_read_phys(ctx, pa, buf, len, err, err_len);
}

void kmem_vmi_open(vmi_session_t *session, kmem_t *mem) {
    *mem = (kmem_t) {.read_pa = vmi_mem_read_pa, .close = NULL, .ctx = session};
}
