#include "kern/kprof.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kern/kfield.h"
#include "kern/kimg.h"
#include "vmi/vmi.h"

#define BANNER "Linux version "
#define BANNER_HITS_MAX 16

static const char *const STEP_NAMES[KPROF_STEPS + 1] = {
    "", "pause", "lstar", "image", "kallsyms", "banner", "btf", "init_task.comm", "resume",
};

const char *kprof_step_name(int step) {
    return step >= 1 && step <= KPROF_STEPS ? STEP_NAMES[step] : "?";
}

/* the banner as a string, from the copied image */
static void banner_at(const kimg_t *img, uint64_t va, char *out, size_t out_len) {
    size_t l = 0;
    for (const unsigned char *p; l + 1 < out_len && (p = kimg_ptr(img, va + l, 1)) && *p; l++) out[l] = (char) *p;
    out[l] = '\0';
}

/* step 4's switches: from the first raw hit that parses as a banner */
static int cfg_from_scan(const kimg_t *img, ksym_cfg_t *cfg, char *err, size_t err_len) {
    uint64_t hits[BANNER_HITS_MAX];
    size_t n = ksym_banner_scan(img, hits, BANNER_HITS_MAX);
    for (size_t i = 0; i < n && i < BANNER_HITS_MAX; i++) {
        char b[512];
        banner_at(img, hits[i], b, sizeof(b));
        if (ksym_cfg_from_banner(b, cfg, NULL, 0) == 0) return 0;
    }
    if (err) snprintf(err, err_len, "%zu raw \"" BANNER "\" hit(s) in the image, none parse as a banner", n);
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

int kprof_init(kprof_t *kp, vmi_session_t *session, char *err, size_t err_len) {
    *kp = (kprof_t) {.session = session};
    kimg_t img = {0};
    char e[400] = "";
    int step = 1;
    bool paused = false;

    if (vmi_pause(session, e, sizeof(e)) != 0) goto fail;
    paused = true;

    step = 2;
    uint64_t lstar;
    if (vmi_read_reg(session, MSR_LSTAR, &lstar, e, sizeof(e)) != 0) goto fail;

    step = 3;
    if (kimg_load(session, lstar, &img, e, sizeof(e)) != 0) goto fail;
    kp->img_start = img.start;
    kp->img_end = img.end;

    step = 4;
    ksym_cfg_t cfg;
    if (cfg_from_scan(&img, &cfg, e, sizeof(e)) != 0) goto fail;
    if (ksym_load(&img, &cfg, &kp->ksym, e, sizeof(e)) != 0) goto fail;

    step = 5;
    if (ksym_check_banner(&img, &kp->ksym, kp->banner, sizeof(kp->banner), e, sizeof(e)) != 0) goto fail;
    ksym_cfg_t cfg2;
    if (ksym_cfg_from_banner(kp->banner, &cfg2, e, sizeof(e)) != 0) goto fail;
    if (cfg2.layout != cfg.layout || cfg2.addr != cfg.addr) {
        snprintf(e, sizeof(e), "linux_banner picks %s/%s, but kallsyms was decoded as %s/%s",
                 ksym_layout_name(cfg2.layout), ksym_addr_name(cfg2.addr), ksym_layout_name(cfg.layout),
                 ksym_addr_name(cfg.addr));
        goto fail;
    }
    if (parse_release(kp, e, sizeof(e)) != 0) goto fail;

    step = 6;
    if (btf_load(&img, &kp->ksym, &kp->btf, e, sizeof(e)) != 0) goto fail;

    step = 7;
    if (check_init_task(kp, e, sizeof(e)) != 0) goto fail;

    step = 8;
    paused = false;
    if (vmi_resume(session, e, sizeof(e)) != 0) goto fail;
    kimg_free(&img);
    return 0;

fail:
    if (err) snprintf(err, err_len, "step %d (%s): %s", step, kprof_step_name(step), e);
    if (paused) vmi_resume(session, NULL, 0);
    kimg_free(&img);
    kprof_free(kp);
    return -1;
}

void kprof_free(kprof_t *kp) {
    ksym_free(&kp->ksym);
    btf_free(&kp->btf);
}
