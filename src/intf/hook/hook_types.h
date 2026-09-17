#ifndef ROOTVIEW_HOOK_TYPES_H
#define ROOTVIEW_HOOK_TYPES_H

#include <stdbool.h>
#include <stdint.h>

#include <libvmi/events.h>
#include <libvmi/libvmi.h>

#include "vmi/vmi_types.h"

#define HOOK_NAME_MAX 64
#define HOOK_MAX 64

typedef enum {
    HOOK_KIND_REGISTER,   /* write to cr0/cr3/cr4, or any msr (msr_all) */
    HOOK_KIND_BREAKPOINT, /* 0xcc planted at a virtual address */
} hook_kind_t;

/* vaddr is set for HOOK_KIND_BREAKPOINT only; old/new_value for
 * HOOK_KIND_REGISTER only. */
typedef struct {
    hook_kind_t kind;
    const char *name;
    uint32_t vcpu_id;
    uint64_t vaddr;
    uint64_t old_value;
    uint64_t new_value;
} hook_event_t;

typedef void (*hook_callback_t)(const hook_event_t *ev, void *user_data);

typedef struct hook {
    bool active;
    char name[HOOK_NAME_MAX];
    hook_kind_t kind;

    vmi_event_t vmi_event; /* HOOK_KIND_REGISTER only */

    reg_t reg;         /* HOOK_KIND_REGISTER */
    uint64_t vaddr;     /* HOOK_KIND_BREAKPOINT */
    uint8_t orig_byte;  /* HOOK_KIND_BREAKPOINT: byte the 0xcc replaced */

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
} hook_manager_t;

#endif
