#ifndef ROOTVIEW_KIMG_H
#define ROOTVIEW_KIMG_H

#include <stddef.h>
#include <stdint.h>

#include "vmi/vmi_types.h"

/* the kernel image copied out of the guest once, so kallsyms, the banner
 * and BTF can be found by scanning its bytes. unmapped pages (freed init
 * memory) split it into runs. */

typedef struct {
    uint64_t va;
    uint64_t len;
    const unsigned char *data; /* points into kimg_t.data */
} kimg_run_t;

typedef struct {
    uint64_t start, end; /* 2MiB-aligned: _text rounded down, and the first unmapped 2MiB after it */
    unsigned char *data; /* [start, end), unmapped pages zeroed */
    kimg_run_t *runs;
    size_t n_runs;
} kimg_t;

/* anchor_va is any kernel text address, e.g. MSR_LSTAR. the vm has to be
 * paused so the image doesn't change while it's copied. */
int kimg_load(vmi_session_t *session, uint64_t anchor_va, kimg_t *img, char *err, size_t err_len);

/* points at len copied bytes at va, or NULL unless one run holds all of them */
const unsigned char *kimg_ptr(const kimg_t *img, uint64_t va, size_t len);

void kimg_free(kimg_t *img);

#endif
