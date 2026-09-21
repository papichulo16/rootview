#ifndef ROOTVIEW_HOOK_TYPES_H
#define ROOTVIEW_HOOK_TYPES_H

#include <stdbool.h>
#include <stdint.h>

#include <libvmi/events.h>
#include <libvmi/libvmi.h>

#include "vmi/vmi_types.h"

#define HOOK_NAME_MAX 64
#define HOOK_MAX 64

/* sentinel cpuid_leaf value meaning "match every leaf" */
#define HOOK_CPUID_ANY_LEAF UINT32_MAX

typedef enum {
    HOOK_KIND_REGISTER,   /* write to cr0/cr3/cr4, or any msr (msr_all) */
    HOOK_KIND_BREAKPOINT, /* 0xcc planted at a virtual address */
    HOOK_KIND_CPUID,      /* cpuid instruction execution */
    HOOK_KIND_DESCRIPTOR, /* load/store of a descriptor table register */
    HOOK_KIND_MEM,        /* r/w/x access to a guest page */
} hook_kind_t;

/* the descriptor table an HOOK_KIND_DESCRIPTOR hook watches - mirrors
 * libvmi's VMI_DESCRIPTOR_* constants. */
typedef enum {
    HOOK_DESC_IDTR = VMI_DESCRIPTOR_IDTR,
    HOOK_DESC_GDTR = VMI_DESCRIPTOR_GDTR,
    HOOK_DESC_LDTR = VMI_DESCRIPTOR_LDTR,
    HOOK_DESC_TR   = VMI_DESCRIPTOR_TR,
} hook_desc_t;

/* which fields apply depends on kind:
 *   HOOK_KIND_BREAKPOINT: vaddr
 *   HOOK_KIND_REGISTER:   old_value, new_value
 *   HOOK_KIND_CPUID:      cpuid_leaf, cpuid_subleaf
 *   HOOK_KIND_DESCRIPTOR: descriptor, desc_is_write
 *   HOOK_KIND_MEM:        mem_gpa, mem_access */
typedef struct {
    hook_kind_t kind;
    const char *name;
    uint32_t vcpu_id;

    uint64_t vaddr;
    uint64_t old_value;
    uint64_t new_value;

    uint32_t cpuid_leaf;
    uint32_t cpuid_subleaf;

    hook_desc_t descriptor;
    bool desc_is_write;

    uint64_t mem_gpa;
    uint8_t mem_access; /* VMI_MEMACCESS_* bits that fired */
} hook_event_t;

typedef void (*hook_callback_t)(const hook_event_t *ev, void *user_data);

typedef struct hook {
    bool active;
    char name[HOOK_NAME_MAX];
    hook_kind_t kind;

    /* HOOK_KIND_REGISTER and HOOK_KIND_MEM only - each of these hooks owns
     * an independent libvmi registration. CPUID and DESCRIPTOR hooks are
     * multiplexed off the manager's shared singleton event instead, since
     * KVMI only allows one registration of each at a time (same reason
     * breakpoints share bp_event/ss_event below). */
    vmi_event_t vmi_event;

    reg_t reg;         /* HOOK_KIND_REGISTER */
    uint64_t vaddr;     /* HOOK_KIND_BREAKPOINT */
    uint8_t orig_byte;  /* HOOK_KIND_BREAKPOINT: byte the 0xcc replaced */

    uint32_t cpuid_leaf; /* HOOK_KIND_CPUID: leaf to match, or HOOK_CPUID_ANY_LEAF */

    hook_desc_t descriptor; /* HOOK_KIND_DESCRIPTOR */

    uint64_t mem_gfn;   /* HOOK_KIND_MEM: guest frame number being watched */
    uint8_t mem_access; /* HOOK_KIND_MEM: VMI_MEMACCESS_* mask being watched */

    hook_callback_t callback;
    void *user_data;
} hook_t;

/* mgr must stay at a fixed address while any hook is active - libvmi keeps
 * a pointer into each hook's embedded vmi_event. */
typedef struct {
    vmi_session_t *session;
    hook_t hooks[HOOK_MAX];
    int count;

    bool bp_active;
    vmi_event_t bp_event;
    vmi_event_t ss_event;
    hook_t *pending_bp; /* hook mid-recoil, if any */

    bool cpuid_active;
    vmi_event_t cpuid_event;

    bool desc_active;
    vmi_event_t desc_event;
} hook_manager_t;

#endif
