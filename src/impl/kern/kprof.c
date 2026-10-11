#include "kern/kprof.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kern/kfield.h"
#include "vmi/vmi.h"

#define BANNER "Linux version "

static const char *const STEP_NAMES[KPROF_STEPS + 1] = {
    "", "pause", "registers", "root", "image", "kallsyms", "banner", "btf", "init_top_pgt", "init_task.comm", "resume",
};

const char *kprof_step_name(int step) {
    return step >= 1 && step <= KPROF_STEPS ? STEP_NAMES[step] : "?";
}

/* the banner as a string, from the loaded runs */
static void banner_at(const pt_image_t *img, uint64_t va, char *out, size_t out_len) {
    size_t l = 0;
    for (const unsigned char *p; l + 1 < out_len && (p = pt_image_ptr(img, va + l, 1)) && *p; l++) out[l] = (char) *p;
    out[l] = '\0';
}

/* step 5's switches: from the first raw hit that parses as a banner */
static int cfg_from_scan(const pt_image_t *img, ksym_cfg_t *cfg, char *err, size_t err_len) {
    uint64_t hits[16];
    size_t n = ksym_banner_scan(img, hits, 16);
    for (size_t i = 0; i < n && i < 16; i++) {
        char b[512];
        banner_at(img, hits[i], b, sizeof(b));
        if (ksym_cfg_from_banner(b, cfg, NULL, 0) == 0) return 0;
    }
    if (err) snprintf(err, err_len, "%zu raw \"" BANNER "\" hit(s) in the NX runs, none parse as a banner", n);
    return -1;
}

static int parse_release(kprof_t *kp, char *err, size_t err_len) {
    const char *r = kp->banner + strlen(BANNER);
    size_t n = strcspn(r, " \n");
    if (n == 0 || n >= sizeof(kp->release)) {
        if (err) snprintf(err, err_len, "no release in '%.60s'", kp->banner);
        return -1;
    }
    memcpy(kp->release, r, n);
    kp->release[n] = '\0';
    kp->patch = 0;
    if (sscanf(kp->release, "%u.%u.%u", &kp->major, &kp->minor, &kp->patch) < 2) {
        if (err) snprintf(err, err_len, "release '%s' isn't major.minor", kp->release);
        return -1;
    }
    return 0;
}

/* IDT gate 0 through root: the 16-byte descriptor and its handler */
static int idt_gate0(const kprof_t *kp, const pt_root_t *root, unsigned char gate[16], uint64_t *handler, char *err,
                     size_t err_len) {
    if (pt_read(&kp->mem, root, kp->regs.idtr_base, gate, 16, err, err_len) != 0) return -1;
    uint16_t lo, mid;
    uint32_t hi;
    memcpy(&lo, gate, 2);
    memcpy(&mid, gate + 6, 2);
    memcpy(&hi, gate + 8, 4);
    *handler = lo | (uint64_t) mid << 16 | (uint64_t) hi << 32;
    return 0;
}

/* step 8: init_top_pgt's physical address, through the vcpu's root, and the
 * checks that it really is the kernel's root */
static int switch_root(kprof_t *kp, char *err, size_t err_len) {
    const ksym_t *pgt = ksym_by_name(&kp->ksym, "init_top_pgt");
    if (!pgt) {
        if (err) snprintf(err, err_len, "no init_top_pgt symbol");
        return -1;
    }
    uint64_t pa;
    if (pt_translate(&kp->mem, &kp->vcpu_root, pgt->addr, &pa, NULL, err, err_len) != 0) return -1;
    kp->root = (pt_root_t) {.pgd = pa, .la57 = false};

    /* the image maps to the same frames either way */
    const uint64_t probes[] = {kp->img.start, kp->ksym.va_token_table, pgt->addr, kp->btf.va};
    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        uint64_t a, b;
        char e[200];
        if (pt_translate(&kp->mem, &kp->root, probes[i], &b, NULL, e, sizeof(e)) != 0) {
            if (err) snprintf(err, err_len, "init_top_pgt (pa 0x%" PRIx64 ") doesn't map 0x%" PRIx64 ": %s", pa,
                              probes[i], e);
            return -1;
        }
        pt_translate(&kp->mem, &kp->vcpu_root, probes[i], &a, NULL, NULL, 0);
        if (a != b) {
            if (err) snprintf(err, err_len, "0x%" PRIx64 " maps to pa 0x%" PRIx64 " under CR3 but 0x%" PRIx64
                              " under init_top_pgt", probes[i], a, b);
            return -1;
        }
    }

    /* the IDT is in the cpu entry area, outside the image: same gate both
     * ways, and its handler is kernel text */
    unsigned char g_vcpu[16], g_init[16];
    uint64_t h;
    char e[200];
    if (idt_gate0(kp, &kp->vcpu_root, g_vcpu, &h, e, sizeof(e)) != 0 ||
        idt_gate0(kp, &kp->root, g_init, &h, e, sizeof(e)) != 0) {
        if (err) snprintf(err, err_len, "IDT at 0x%" PRIx64 ": %s", kp->regs.idtr_base, e);
        return -1;
    }
    if (memcmp(g_vcpu, g_init, 16) != 0) {
        if (err) snprintf(err, err_len, "IDT[0] reads differently under CR3 and init_top_pgt");
        return -1;
    }
    if (h < kp->img.start || h >= kp->img.end) {
        if (err) snprintf(err, err_len, "IDT[0] handler 0x%" PRIx64 " is outside the image", h);
        return -1;
    }
    return 0;
}

static int check_init_task(kprof_t *kp, char *err, size_t err_len) {
    const ksym_t *it = ksym_by_name(&kp->ksym, "init_task");
    if (!it) {
        if (err) snprintf(err, err_len, "no init_task symbol");
        return -1;
    }
    kp->init_task = it->addr;
    kfield_t comm;
    kval_t v;
    if (kfield_resolve(&kp->btf, "task_struct", "comm", &comm, err, err_len) != 0) return -1;
    if (comm.kind != KF_CSTR) {
        if (err) snprintf(err, err_len, "task_struct.comm decodes as %s, not a string", kfield_kind_name(comm.kind));
        return -1;
    }
    if (kfield_read(kp, &comm, kp->init_task, &v, err, err_len) != 0) return -1;
    int rc = strcmp((const char *) v.bytes, "swapper/0") == 0 ? 0 : -1;
    if (rc && err) snprintf(err, err_len, "init_task.comm at 0x%" PRIx64 " is '%.16s', not 'swapper/0'",
                            kp->init_task + comm.offset, v.bytes);
    kval_free(&v);
    return rc;
}

/* the page walks read through a kmem_t */
static int kprof_read_phys(void *ctx, uint64_t pa, void *buf, size_t len, char *err, size_t err_len) {
    return vmi_read_phys(ctx, pa, buf, len, err, err_len);
}

int kprof_init(kprof_t *kp, vmi_session_t *session, char *err, size_t err_len) {
    *kp = (kprof_t) {.session = session, .mem = {.read_pa = kprof_read_phys, .close = NULL, .ctx = session}};
    char e[400] = "";
    int step = 1;
    bool paused = false;

    if (vmi_pause(session, e, sizeof(e)) != 0) goto fail;
    paused = true;

    step = 2;
    if (kprof_read_regs(kp, &kp->regs, e, sizeof(e)) != 0) goto fail;

    step = 3;
    if (kp->regs.cr4 & PT_CR4_LA57) {
        snprintf(e, sizeof(e), "CR4.LA57 is set: 5-level paging isn't supported");
        goto fail;
    }
    if (pt_root_from_cr3(&kp->mem, kp->regs.cr3, kp->regs.cr4, kp->regs.lstar, &kp->vcpu_root, e, sizeof(e)) != 0)
        goto fail;

    step = 4;
    if (pt_image(&kp->mem, &kp->vcpu_root, &kp->img, e, sizeof(e)) != 0) goto fail;
    if (pt_image_read_nx(&kp->mem, &kp->vcpu_root, &kp->img, e, sizeof(e)) != 0) goto fail;

    step = 5;
    ksym_cfg_t cfg;
    if (cfg_from_scan(&kp->img, &cfg, e, sizeof(e)) != 0) goto fail;
    if (ksym_load(&kp->img, &cfg, &kp->ksym, e, sizeof(e)) != 0) goto fail;

    step = 6;
    if (ksym_check_banner(&kp->img, &kp->ksym, kp->banner, sizeof(kp->banner), e, sizeof(e)) != 0) goto fail;
    ksym_cfg_t cfg2;
    if (ksym_cfg_from_banner(kp->banner, &cfg2, e, sizeof(e)) != 0) goto fail;
    if (cfg2.layout != cfg.layout || cfg2.addr != cfg.addr) {
        snprintf(e, sizeof(e), "linux_banner picks %s/%s, but kallsyms was decoded as %s/%s",
                 ksym_layout_name(cfg2.layout), ksym_addr_name(cfg2.addr), ksym_layout_name(cfg.layout),
                 ksym_addr_name(cfg.addr));
        goto fail;
    }
    if (parse_release(kp, e, sizeof(e)) != 0) goto fail;

    step = 7;
    if (btf_load(&kp->img, &kp->ksym, &kp->btf, e, sizeof(e)) != 0) goto fail;

    step = 8;
    if (switch_root(kp, e, sizeof(e)) != 0) goto fail;

    step = 9;
    if (check_init_task(kp, e, sizeof(e)) != 0) goto fail;

    step = 10;
    paused = false;
    if (vmi_resume(session, e, sizeof(e)) != 0) goto fail;
    return 0;

fail:
    if (err) snprintf(err, err_len, "step %d (%s): %s", step, kprof_step_name(step), e);
    if (paused) vmi_resume(session, NULL, 0);
    kprof_free(kp);
    return -1;
}

void kprof_free(kprof_t *kp) {
    pt_image_free(&kp->img);
    ksym_free(&kp->ksym);
    btf_free(&kp->btf);
    free(kp->hash);
    kp->hash = NULL;
}

int kprof_read(const kprof_t *kp, uint64_t va, void *buf, size_t len, char *err, size_t err_len) {
    if (len == 0) return 0;
    return pt_read(&kp->mem, &kp->root, va, buf, len, err, err_len);
}

int kprof_read_regs(const kprof_t *kp, kprof_regs_t *regs, char *err, size_t err_len) {
    int rc = -1;
    if (vmi_read_reg(kp->session, CR3, &regs->cr3, err, err_len) != 0) goto out;
    if (vmi_read_reg(kp->session, CR4, &regs->cr4, err, err_len) != 0) goto out;
    if (vmi_read_reg(kp->session, MSR_LSTAR, &regs->lstar, err, err_len) != 0) goto out;
    if (vmi_read_reg(kp->session, IDTR_BASE, &regs->idtr_base, err, err_len) != 0) goto out;
    rc = 0;

out:
    return rc;
}
