#include "hook/hook.h"

#include <stdio.h>
#include <string.h>

#include "hook_priv.h"
#include "vmi/vmi.h"

static event_response_t on_bp_hit(vmi_instance_t vmi, vmi_event_t *event) {
    (void) vmi;
    hook_manager_t *mgr = (hook_manager_t *) event->data;

    event->interrupt_event.reinject = 1;
    if (!event->interrupt_event.insn_length) event->interrupt_event.insn_length = 1;

    uint64_t vaddr = event->x86_regs->rip;
    hook_t *h = hook_find_bp_by_vaddr(mgr, vaddr);
    if (!h) return VMI_EVENT_RESPONSE_NONE;

    event->interrupt_event.reinject = 0;

    char err[128];
    if (vmi_write_virt(mgr->session, h->vaddr, &h->orig_byte, 1, err, sizeof(err)) != 0) {
        return VMI_EVENT_RESPONSE_NONE;
    }
    mgr->pending_bp = h;

    hook_event_t ev = {
        .kind = HOOK_KIND_BREAKPOINT,
        .name = h->name,
        .vcpu_id = event->vcpu_id,
        .vaddr = vaddr,
        .old_value = 0,
        .new_value = 0,
    };
    if (h->callback) h->callback(&ev, h->user_data);

    return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

static event_response_t on_bp_singlestep(vmi_instance_t vmi, vmi_event_t *event) {
    (void) vmi;
    hook_manager_t *mgr = (hook_manager_t *) event->data;

    hook_t *h = mgr->pending_bp;
    if (h) {
        unsigned char cc = 0xcc;
        char err[128];
        vmi_write_virt(mgr->session, h->vaddr, &cc, 1, err, sizeof(err));
        mgr->pending_bp = NULL;
    }
    return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

/* KVMI allows only one INT3 registration at a time, so every breakpoint
 * hook shares this one bp_event/ss_event pair. */
static int ensure_bp_infra(hook_manager_t *mgr, char *err, size_t err_len) {
    if (mgr->bp_active) return 0;

    memset(&mgr->bp_event, 0, sizeof(mgr->bp_event));
    mgr->bp_event.version = VMI_EVENTS_VERSION;
    mgr->bp_event.type = VMI_EVENT_INTERRUPT;
    mgr->bp_event.interrupt_event.intr = INT3;
    mgr->bp_event.callback = on_bp_hit;
    mgr->bp_event.data = mgr;

    if (vmi_register_event(mgr->session->vmi, &mgr->bp_event) != VMI_SUCCESS) {
        if (err) snprintf(err, err_len, "failed to enable INT3 trapping on this vm");
        return -1;
    }

    memset(&mgr->ss_event, 0, sizeof(mgr->ss_event));
    mgr->ss_event.version = VMI_EVENTS_VERSION;
    mgr->ss_event.type = VMI_EVENT_SINGLESTEP;
    mgr->ss_event.callback = on_bp_singlestep;
    mgr->ss_event.data = mgr;
    mgr->ss_event.ss_event.enable = false;
    unsigned int num_vcpus = vmi_get_num_vcpus(mgr->session->vmi);
    for (unsigned int vcpu = 0; vcpu < num_vcpus; vcpu++) SET_VCPU_SINGLESTEP(mgr->ss_event.ss_event, vcpu);

    if (vmi_register_event(mgr->session->vmi, &mgr->ss_event) != VMI_SUCCESS) {
        if (err) snprintf(err, err_len, "failed to set up single-step recoil for breakpoints");
        vmi_clear_event(mgr->session->vmi, &mgr->bp_event, NULL);
        return -1;
    }

    mgr->bp_active = true;
    return 0;
}

int hook_bp_add(hook_manager_t *mgr, const char *name, uint64_t vaddr, hook_callback_t callback, void *user_data,
                 char *err, size_t err_len) {
    if (hook_find_by_name(mgr, name)) {
        if (err) snprintf(err, err_len, "hook '%s' already exists", name);
        return -1;
    }
    if (hook_find_bp_by_vaddr(mgr, vaddr)) {
        if (err) snprintf(err, err_len, "a breakpoint is already planted at 0x%lx", (unsigned long) vaddr);
        return -1;
    }

    if (ensure_bp_infra(mgr, err, err_len) != 0) return -1;

    hook_t *h = hook_alloc_slot(mgr);
    if (!h) {
        if (err) snprintf(err, err_len, "hook limit reached (%d)", HOOK_MAX);
        return -1;
    }

    unsigned char orig;
    if (vmi_read_virt(mgr->session, vaddr, &orig, 1, err, err_len) != 0) return -1;

    unsigned char cc = 0xcc;
    if (vmi_write_virt(mgr->session, vaddr, &cc, 1, err, err_len) != 0) return -1;

    memset(h, 0, sizeof(*h));
    snprintf(h->name, sizeof(h->name), "%s", name);
    h->kind = HOOK_KIND_BREAKPOINT;
    h->vaddr = vaddr;
    h->orig_byte = orig;
    h->callback = callback;
    h->user_data = user_data;
    h->active = true;

    return 0;
}
