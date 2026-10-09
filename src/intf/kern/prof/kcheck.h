#ifndef ROOTVIEW_KCHECK_H
#define ROOTVIEW_KCHECK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "kern/prof/kscan.h"
#include "kern/prof/kwalk.h"

/* targeted structure integrity: the handful of kernel pointers a rootkit
 * redirects to get control - syscall table entries, IDT gates, MSR_LSTAR -
 * each read, located and named. far more specific than khash: a page hash
 * says text moved, this says sys_call_table[217] now points into module
 * "rk" at offset 0x40.
 *
 * every target is placed: inside [_stext, _etext) or not, inside a module's
 * text (named from a kscan_modules result, when the caller has one), and
 * reverse-looked-up in kallsyms. each check then applies its own rule for
 * what a clean kernel's slot holds, and sets suspect where it doesn't. the
 * flags are the facts, suspect is the rule's reading of them; both are
 * evidence for an analyst, not a verdict.
 *
 * ftrace (optional, version-sensitive) lists the functions ftrace has
 * patched. many hiding rootkits now hook through ftrace rather than the
 * syscall table, but so do tracers and livepatch, so an enabled record is
 * listed, not suspect - only a record whose flags and patched bytes
 * disagree is. */

typedef enum {
    KCHECK_SYSCALL,
    KCHECK_IDT,
    KCHECK_LSTAR,
    KCHECK_FTRACE,
} kcheck_kind_t;

/* where a target points */
#define KCHECK_OUT_OF_TEXT (1u << 0) /* outside [_stext, _etext) */
#define KCHECK_IN_MODULE (1u << 1)   /* inside a module's text: owner names it */
#define KCHECK_NO_SYMBOL (1u << 2)   /* no text symbol at or below it */
#define KCHECK_MID_SYMBOL (1u << 3)  /* not at the start of its symbol */
#define KCHECK_UNEXPECTED (1u << 4)  /* a symbol, but not the kind this slot holds */
#define KCHECK_NULL (1u << 5)        /* the slot holds 0 */
#define KCHECK_UNREADABLE (1u << 6)  /* the slot itself couldn't be read */

/* IDT gates */
#define KCHECK_IDT_BAD_GATE (1u << 8) /* selector isn't __KERNEL_CS, or not an interrupt/trap gate */
#define KCHECK_IDT_USER (1u << 9)     /* DPL 3: int3, into and int 0x80 have it on a clean kernel */
/* a reserved vector still on early_idt_handler_array, in freed init text:
 * what every kernel leaves for vectors nothing installs a handler for */
#define KCHECK_IDT_EARLY_STUB (1u << 10)
/* a device vector on its irq_entries_start / spurious_entries_start stub:
 * mid-symbol by design */
#define KCHECK_IDT_IRQ_STUB (1u << 11)
/* the table IDTR points at isn't idt_table's frame: the IDT was replaced
 * wholesale (set on every gate, since lidt moves them all) */
#define KCHECK_IDT_NOT_IDT_TABLE (1u << 12)

/* ftrace records */
#define KCHECK_FTRACE_ENABLED (1u << 16)  /* FTRACE_FL_ENABLED: some ftrace_ops is attached */
#define KCHECK_FTRACE_IPMODIFY (1u << 17) /* an ops may change the return ip: how ftrace hooks redirect */
#define KCHECK_FTRACE_DIRECT (1u << 18)   /* a direct call (bpf trampolines, direct ops) */
#define KCHECK_FTRACE_CALL (1u << 19)     /* the bytes at ip are a call or jmp, not the nop */
#define KCHECK_FTRACE_MISMATCH (1u << 20) /* enabled with the nop in place, or patched while not enabled */

typedef struct {
    kcheck_kind_t kind;
    uint32_t index;       /* syscall nr, vector, 0 for LSTAR, record number for ftrace */
    uint64_t slot;        /* the entry's own address: table entry, gate, dyn_ftrace; 0 for LSTAR */
    uint64_t target;      /* where it sends control; ftrace: the call's destination, 0 for the nop */
    const char *sym;      /* target's kallsyms symbol, or NULL; points into kp->ksym */
    uint64_t sym_off;
    char owner[KSCAN_NAME_MAX]; /* IN_MODULE: the module */
    uint64_t site;        /* ftrace: the patched ip */
    const char *site_sym; /* ftrace: the function it's in */
    uint64_t site_off;
    uint64_t raw;         /* IDT: the gate's type/attr byte | selector << 8 | ist << 24; ftrace: dyn_ftrace.flags */
    uint32_t flags;
    bool suspect;
} kcheck_entry_t;

typedef struct {
    kcheck_kind_t kind;
    kcheck_entry_t *e; /* syscalls and IDT: every slot; ftrace: only patched or enabled records */
    size_t n, cap;
    size_t checked; /* slots or records looked at */
    size_t suspect;
    char note[256]; /* a fact about the whole check: the table length's source, a fallback taken */
} kcheck_result_t;

void kcheck_free(kcheck_result_t *r);
const char *kcheck_kind_name(kcheck_kind_t kind);

/* each check runs in one snapshot window, the caller's if open. mods
 * (optional) is a kscan_modules result, for naming the module a target
 * lands in; without it a module target is still OUT_OF_TEXT. -1 only when
 * the check couldn't run at all. */

/* sys_call_table[0..n): n is the index of the first NULL entry, capped by
 * the distance to the next kallsyms symbol (the table has no length of its
 * own in kallsyms or BTF). suspect: outside text, mid-symbol, or not a
 * __x64_sys_* symbol.
 *
 * x86_64 kernels since 6.9 (and distro kernels with the backport, such as
 * Ubuntu's 5.15.0-1xx) dispatch through x64_sys_call's switch rather than
 * this table, which then only feeds tracing and audit: a patched entry is
 * still a rootkit's fingerprint, but no longer its hook. that switch is
 * text, so khash covers it. */
int kcheck_syscalls(kwalk_t *w, const kscan_result_t *mods, kcheck_result_t *r, char *err, size_t err_len);

/* the 256 gates at IDTR's base, read fresh from the vcpu. present gates
 * only. suspect: a bad gate, a handler outside text, mid-symbol, or not
 * asm_* / entry_* - except a reserved vector (< 32) on its own
 * early_idt_handler_array stub, and a device vector inside the irq or
 * spurious stub arrays at a stub boundary. */
int kcheck_idt(kwalk_t *w, const kscan_result_t *mods, kcheck_result_t *r, char *err, size_t err_len);

/* MSR_LSTAR, read fresh from the vcpu, against entry_SYSCALL_64. one vcpu:
 * a rootkit that only patches the others isn't seen. */
int kcheck_lstar(kwalk_t *w, const kscan_result_t *mods, kcheck_result_t *r, char *err, size_t err_len);

/* the dyn_ftrace records under ftrace_pages_start, with the 5 bytes at each
 * ip decoded as the nop or a call/jmp. lists every record that's enabled or
 * patched; suspect only on MISMATCH. the flag bits come from BTF's
 * FTRACE_FL_* enumerators when it has them (note says when it didn't). */
int kcheck_ftrace(kwalk_t *w, const kscan_result_t *mods, kcheck_result_t *r, char *err, size_t err_len);

#endif
