#ifndef ROOTVIEW_KPROF_H
#define ROOTVIEW_KPROF_H

#include <stddef.h>
#include <stdint.h>

#include "kern/btf.h"
#include "kern/ksym.h"
#include "vmi/vmi_types.h"

/* the kernel profile: kallsyms and BTF decoded out of an attached vm's
 * kernel image, so the guest's kernel can be read by name. guest memory is
 * read through the vmi module (vmi_read_virt). */

typedef struct {
    vmi_session_t *session; /* borrowed: kprof_free doesn't detach it */
    uint64_t img_start, img_end;
    ksym_table_t ksym;
    btf_t btf;
    char banner[512];
    char release[65]; /* "6.18.35-0-lts", what uname -r says */
    unsigned major, minor, patch;
    uint64_t init_task;
} kprof_t;

/* the init sequence, each step's failure reported as "step N (what): ...":
 *   1 pause the vm
 *   2 read MSR_LSTAR
 *   3 copy the image, found from LSTAR
 *   4 find and decode kallsyms, with the switches the raw banner picks
 *   5 cross-check linux_banner against the raw scan and parse the release
 *   6 find and parse BTF
 *   7 read init_task.comm: "swapper/0"
 *   8 resume the vm
 * the vm is resumed on failure too, if it was paused. */
int kprof_init(kprof_t *kp, vmi_session_t *session, char *err, size_t err_len);

#define KPROF_STEPS 8
const char *kprof_step_name(int step);

void kprof_free(kprof_t *kp);

#endif
