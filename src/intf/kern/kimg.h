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
    /* x86_64: 2MiB-aligned, _text rounded down, and the first unmapped 2MiB after it.
     * arm64: _stext (the image header page below it isn't mapped) to the first
     * 2MiB after it with no page of the image in it. */
    uint64_t start, end;
    uint64_t text_min; /* the lowest address _text can decode to: start, or the image header below it */
    unsigned char *data; /* [start, end), unmapped pages zeroed */
    kimg_run_t *runs;
    size_t n_runs;
} kimg_t;

/* anchor_va is any kernel text address (vmi_kernel_anchor). the vm has to be
 * paused so the image doesn't change while it's copied. on arm64 the image
 * shares its VA range with vmalloc and modules, so a page only counts as the
 * image when it has the anchor's VA-to-PA offset: the image is physically
 * contiguous. */
int kimg_load(vmi_session_t *session, uint64_t anchor_va, kimg_t *img, char *err, size_t err_len);

/* points at len copied bytes at va, or NULL unless one run holds all of them */
const unsigned char *kimg_ptr(const kimg_t *img, uint64_t va, size_t len);

void kimg_free(kimg_t *img);

#endif
