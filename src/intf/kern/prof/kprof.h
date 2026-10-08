#ifndef ROOTVIEW_KPROF_H
#define ROOTVIEW_KPROF_H

#include <stddef.h>
#include <stdint.h>

#include "kern/prof/btf.h"
#include "kern/prof/kmem.h"
#include "kern/prof/ksym.h"
#include "kern/prof/pt.h"

/* the kernel profile: everything the later layers need to read the guest's
 * kernel by name - the canonical page-table root, the image, kallsyms and
 * BTF - built once by kprof_init from nothing but guest memory and a vcpu's
 * registers. */

typedef struct {
    uint64_t cr3, cr4, lstar, idtr_base;
} kprof_regs_t;

/* where kprof_init gets its inputs. pause and resume may be NULL when there
 * is nothing to pause (a ram dump). kmem_vmi.h/kprof_vmi.h build one over a
 * live session. */
typedef struct {
    kmem_t mem;
    int (*pause)(void *ctx, char *err, size_t err_len);
    int (*resume)(void *ctx, char *err, size_t err_len);
    int (*read_regs)(void *ctx, kprof_regs_t *regs, char *err, size_t err_len);
    void *ctx;
} kprof_target_t;

typedef struct {
    kprof_target_t target; /* borrowed: kprof_free doesn't close it */
    kprof_regs_t regs;     /* as read at init */
    pt_root_t vcpu_root;   /* the kernel root derived from CR3 */
    pt_root_t root;        /* init_top_pgt: what every read after init goes through */
    pt_image_t img;
    ksym_table_t ksym;
    btf_t btf;
    char banner[512];
    char release[65]; /* "6.18.35-0-lts", what uname -r says */
    unsigned major, minor, patch;
    uint64_t init_task;
} kprof_t;

/* the init sequence, each step's failure reported as "step N (what): ...":
 *    1 pause the vm
 *    2 read CR3, CR4, LSTAR and IDTR
 *    3 choose the kernel root from CR3; 5-level paging is rejected
 *    4 find the image and load its NX runs
 *    5 find and decode kallsyms, with the switches the raw banner picks
 *    6 cross-check linux_banner against the raw scan and parse the release
 *    7 find and parse BTF
 *    8 switch to init_top_pgt: it must map the image and the IDT the same
 *      way the vcpu's root does, and IDT[0] must point into the image
 *    9 read init_task.comm through it: "swapper/0"
 *   10 resume the vm
 * the vm is resumed on failure too, if it was paused. */
int kprof_init(kprof_t *kp, const kprof_target_t *target, char *err, size_t err_len);

/* the step kprof_init's error came from, for callers that report it apart */
#define KPROF_STEPS 10
const char *kprof_step_name(int step);

void kprof_free(kprof_t *kp);

/* reads len bytes of kernel virtual memory through the canonical root: one
 * call for a whole struct, which kfield_decode then slices. page by page
 * underneath, so a struct costs a read per page it touches rather than one
 * per field. */
int kprof_read(const kprof_t *kp, uint64_t va, void *buf, size_t len, char *err, size_t err_len);

int kprof_pause(const kprof_t *kp, char *err, size_t err_len);
int kprof_resume(const kprof_t *kp, char *err, size_t err_len);

#endif
