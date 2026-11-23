#include <stdbool.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "pkvmi/pkvmi_adb.h"
#include "pkvmi/pkvmi_walk.h"
#include "vmi/vmi.h"
#include "vmi/vmi_ops.h"

#define PAGE PKVMI_ADB_PAGE
#define REGS_MAX 32
/* every pointer a walk follows is a ~40ms adb round trip */
#define WALK_BUDGET_MS 120000

struct pkvmi_conn {
    pkvmi_adb_t adb;
    pkvmi_walk_t walk;
    bool paused; /* keep the cached page tables until resume */
};

static int pkvmi_read_table(void *ctx, uint64_t pa, unsigned char *page, char *err, size_t err_len) {
    pkvmi_conn_t *c = ctx;
    return pkvmi_adb_read_pages(&c->adb, &pa, 1, page, err, err_len);
}

static int pkvmi_reg(pkvmi_conn_t *c, const char *name, uint64_t *value, char *err, size_t err_len) {
    int rc = -1;
    pkvmi_adb_reg_t regs[REGS_MAX];
    size_t n, len = strlen(name);
    const char *cmd = len > 4 && strcmp(name + len - 4, "_el2") == 0 ? "regdump" : "regdump_el1";

    if (pkvmi_adb_regdump(&c->adb, cmd, regs, REGS_MAX, &n, err, err_len) != 0) goto out;
    for (size_t i = 0; i < n && rc != 0; i++) {
        if (strcasecmp(regs[i].name, name) != 0) continue;
        *value = regs[i].value;
        rc = 0;
    }
    if (rc != 0 && err) snprintf(err, err_len, "unknown register '%s' (the EL1/EL2 system registers pkvmi dumps)", name);

out:
    return rc;
}

static int pkvmi_attach(const char *target, vmi_session_t *session, char *err, size_t err_len) {
    int rc = -1;
    uint64_t ttbr0, ttbr1, tcr;
    pkvmi_conn_t *c = calloc(1, sizeof(*c));

    if (!c) {
        if (err) snprintf(err, err_len, "out of memory");
        goto out;
    }
    if (pkvmi_adb_open(&c->adb, target, err, err_len) != 0) goto out;
    if (pkvmi_reg(c, "ttbr0_el1", &ttbr0, err, err_len) != 0 || pkvmi_reg(c, "ttbr1_el1", &ttbr1, err, err_len) != 0 ||
        pkvmi_reg(c, "tcr_el1", &tcr, err, err_len) != 0)
        goto out;
    if (pkvmi_walk_init(&c->walk, ttbr0, ttbr1, tcr, pkvmi_read_table, c, err, err_len) != 0) goto out;

    snprintf(session->vm_name, sizeof(session->vm_name), "%s", target[0] ? target : "adb");
    session->pkvmi = c;
    session->attached = true;
    c = NULL;
    rc = 0;

out:
    if (c) pkvmi_adb_close(&c->adb);
    free(c);
    return rc;
}

static void pkvmi_detach(vmi_session_t *session) {
    pkvmi_walk_free(&session->pkvmi->walk);
    pkvmi_adb_close(&session->pkvmi->adb);
    free(session->pkvmi);
    session->pkvmi = NULL;
}

/* the page-aligned pages [addr, addr + len) touches, through to_pa when it's
 * a virtual range. pas is owned by the caller once this returns 0. */
static int pkvmi_pages(pkvmi_conn_t *c, uint64_t addr, size_t len, bool virt, uint64_t **pas, size_t *n, char *err,
                       size_t err_len) {
    int rc = -1;
    uint64_t first = addr & ~(PAGE - 1);
    size_t count = (size_t) ((addr + len - first + PAGE - 1) / PAGE);
    uint64_t *out = calloc(count ? count : 1, sizeof(*out));

    if (!out) {
        if (err) snprintf(err, err_len, "out of memory");
        goto out;
    }
    for (size_t i = 0; i < count; i++) {
        uint64_t page = first + i * PAGE;
        if (virt && pkvmi_walk_translate(&c->walk, page, &out[i], err, err_len) != 0) goto out;
        if (!virt) out[i] = page;
    }
    *pas = out;
    *n = count;
    out = NULL;
    rc = 0;

out:
    free(out);
    return rc;
}

static int pkvmi_read(vmi_session_t *session, uint64_t addr, void *buf, size_t len, bool virt, char *err,
                      size_t err_len) {
    int rc = -1;
    pkvmi_conn_t *c = session->pkvmi;
    uint64_t *pas = NULL;
    unsigned char *pages = NULL;
    size_t n;

    if (len == 0) {
        rc = 0;
        goto out;
    }
    if (pkvmi_pages(c, addr, len, virt, &pas, &n, err, err_len) != 0) goto out;
    pages = malloc(n * PAGE);
    if (!pages) {
        if (err) snprintf(err, err_len, "out of memory");
        goto out;
    }
    if (pkvmi_adb_read_pages(&c->adb, pas, n, pages, err, err_len) != 0) goto out;
    memcpy(buf, pages + (addr & (PAGE - 1)), len);
    rc = 0;

out:
    if (!c->paused) pkvmi_walk_flush(&c->walk);
    free(pages);
    free(pas);
    return rc;
}

static int pkvmi_read_phys(vmi_session_t *session, uint64_t paddr, void *buf, size_t len, char *err, size_t err_len) {
    return pkvmi_read(session, paddr, buf, len, false, err, err_len);
}

static int pkvmi_read_virt(vmi_session_t *session, uint64_t vaddr, void *buf, size_t len, char *err, size_t err_len) {
    return pkvmi_read(session, vaddr, buf, len, true, err, err_len);
}

static int pkvmi_translate_virt(vmi_session_t *session, uint64_t vaddr, uint64_t *paddr, char *err, size_t err_len) {
    pkvmi_conn_t *c = session->pkvmi;
    int rc = pkvmi_walk_translate(&c->walk, vaddr, paddr, err, err_len);

    if (!c->paused) pkvmi_walk_flush(&c->walk);
    return rc;
}

static int pkvmi_pause(vmi_session_t *session, char *err, size_t err_len) {
    (void) err;
    (void) err_len;
    session->pkvmi->paused = true;
    return 0;
}

static int pkvmi_resume(vmi_session_t *session, char *err, size_t err_len) {
    (void) err;
    (void) err_len;
    session->pkvmi->paused = false;
    pkvmi_walk_flush(&session->pkvmi->walk);
    return 0;
}

static int pkvmi_read_reg_name(vmi_session_t *session, const char *name, uint64_t *value, char *err, size_t err_len) {
    return pkvmi_reg(session->pkvmi, name, value, err, err_len);
}

/* the exception vectors, always in the image's text */
static int pkvmi_kernel_anchor(vmi_session_t *session, uint64_t *vaddr, char *err, size_t err_len) {
    return pkvmi_reg(session->pkvmi, "vbar_el1", vaddr, err, err_len);
}

const vmi_ops_t g_pkvmi_ops = {
    .name = VMI_BACKEND_PKVMI,
    .arch = VMI_ARCH_ARM64,
    .hooks = false,
    .walk_budget_ms = WALK_BUDGET_MS,
    .attach = pkvmi_attach,
    .detach = pkvmi_detach,
    .read_phys = pkvmi_read_phys,
    .read_virt = pkvmi_read_virt,
    .translate_virt = pkvmi_translate_virt,
    .pause = pkvmi_pause,
    .resume = pkvmi_resume,
    .read_reg_name = pkvmi_read_reg_name,
    .kernel_anchor = pkvmi_kernel_anchor,
};
