#include "hook/hook.h"

#include <stdio.h>
#include <string.h>

#include "hook_priv.h"
#include "vmi/vmi.h"

hook_t *hook_find_by_name(hook_manager_t *mgr, const char *name) {
    for (int i = 0; i < mgr->count; i++) {
        if (mgr->hooks[i].active && strcmp(mgr->hooks[i].name, name) == 0) return &mgr->hooks[i];
    }
    return NULL;
}

hook_t *hook_find_bp_by_vaddr(hook_manager_t *mgr, uint64_t vaddr) {
    for (int i = 0; i < mgr->count; i++) {
        hook_t *h = &mgr->hooks[i];
        if (h->active && h->kind == HOOK_KIND_BREAKPOINT && h->vaddr == vaddr) return h;
    }
    return NULL;
}

/* an exact leaf match wins; a hook watching every leaf only answers when
 * nothing more specific does. */
hook_t *hook_find_cpuid_by_leaf(hook_manager_t *mgr, uint32_t leaf) {
    hook_t *wildcard = NULL;
    for (int i = 0; i < mgr->count; i++) {
        hook_t *h = &mgr->hooks[i];
        if (!h->active || h->kind != HOOK_KIND_CPUID) continue;
        if (h->cpuid_leaf == leaf) return h;
        if (h->cpuid_leaf == HOOK_CPUID_ANY_LEAF) wildcard = h;
    }
    return wildcard;
}

hook_t *hook_find_desc(hook_manager_t *mgr, hook_desc_t descriptor) {
    for (int i = 0; i < mgr->count; i++) {
        hook_t *h = &mgr->hooks[i];
        if (h->active && h->kind == HOOK_KIND_DESCRIPTOR && h->descriptor == descriptor) return h;
    }
    return NULL;
}

/* never compacts - active slots keep a stable address for libvmi's pointer
 * into &h->vmi_event. */
hook_t *hook_alloc_slot(hook_manager_t *mgr) {
    for (int i = 0; i < mgr->count; i++) {
        if (!mgr->hooks[i].active) return &mgr->hooks[i];
    }
    if (mgr->count < HOOK_MAX) return &mgr->hooks[mgr->count++];
    return NULL;
}

static event_response_t on_singlestep(vmi_instance_t vmi, vmi_event_t *event) {
    (void) vmi;
    hook_manager_t *mgr = (hook_manager_t *) event->data;
    hook_bp_stepped(mgr);
    hook_mem_stepped(mgr, event->vcpu_id);
    return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
}

int hook_ss_ensure(hook_manager_t *mgr, char *err, size_t err_len) {
    if (mgr->ss_active) return 0;
    memset(&mgr->ss_event, 0, sizeof(mgr->ss_event));
    mgr->ss_event.version = VMI_EVENTS_VERSION;
    mgr->ss_event.type = VMI_EVENT_SINGLESTEP;
    mgr->ss_event.callback = on_singlestep;
    mgr->ss_event.data = mgr;
    mgr->ss_event.ss_event.enable = false;
    unsigned int num_vcpus = vmi_get_num_vcpus(mgr->session->vmi);
    for (unsigned int vcpu = 0; vcpu < num_vcpus; vcpu++) SET_VCPU_SINGLESTEP(mgr->ss_event.ss_event, vcpu);

    if (vmi_register_event(mgr->session->vmi, &mgr->ss_event) != VMI_SUCCESS) {
        if (err) snprintf(err, err_len, "failed to set up single-stepping on this vm");
        return -1;
    }
    mgr->ss_active = true;
    return 0;
}

void hook_manager_init(hook_manager_t *mgr, vmi_session_t *session) {
    memset(mgr, 0, sizeof(*mgr));
    mgr->session = session;
}

/* per-hook teardown for kinds that own no shared infra - the caller clears
 * bp_event/ss_event/cpuid_event/desc_event separately, once, since those
 * are shared across every hook of their kind. */
static int hook_teardown(hook_manager_t *mgr, hook_t *h, char *err, size_t err_len) {
    switch (h->kind) {
        case HOOK_KIND_REGISTER:
            vmi_clear_event(mgr->session->vmi, &h->vmi_event, NULL);
            break;
        case HOOK_KIND_MEM:
            vmi_clear_event(mgr->session->vmi, &h->vmi_event, NULL);
            hook_mem_forget(mgr, h);
            break;
        case HOOK_KIND_BREAKPOINT:
            if (vmi_write_virt(mgr->session, h->vaddr, &h->orig_byte, 1, err, err_len) != 0) return -1;
            if (mgr->pending_bp == h) mgr->pending_bp = NULL;
            break;
        case HOOK_KIND_CPUID:
        case HOOK_KIND_DESCRIPTOR:
            break;
    }
    return 0;
}

void hook_manager_clear(hook_manager_t *mgr) {
    for (int i = 0; i < mgr->count; i++) {
        hook_t *h = &mgr->hooks[i];
        if (!h->active) continue;

        char err[128];
        hook_teardown(mgr, h, err, sizeof(err));
        h->active = false;
    }
    mgr->count = 0;
    mgr->pending_bp = NULL;

    if (mgr->bp_active) {
        vmi_clear_event(mgr->session->vmi, &mgr->bp_event, NULL);
        mgr->bp_active = false;
    }
    if (mgr->ss_active) {
        vmi_clear_event(mgr->session->vmi, &mgr->ss_event, NULL);
        mgr->ss_active = false;
    }
    if (mgr->cpuid_active) {
        vmi_clear_event(mgr->session->vmi, &mgr->cpuid_event, NULL);
        mgr->cpuid_active = false;
    }
    if (mgr->desc_active) {
        vmi_clear_event(mgr->session->vmi, &mgr->desc_event, NULL);
        mgr->desc_active = false;
    }
}

int hook_remove(hook_manager_t *mgr, const char *name, char *err, size_t err_len) {
    hook_t *h = hook_find_by_name(mgr, name);
    if (!h) {
        if (err) snprintf(err, err_len, "no hook named '%s'", name);
        return -1;
    }

    if (hook_teardown(mgr, h, err, err_len) != 0) return -1;

    h->active = false;
    return 0;
}

int hook_poll(hook_manager_t *mgr, uint32_t timeout_ms, char *err, size_t err_len) {
    if (vmi_events_listen(mgr->session->vmi, timeout_ms) != VMI_SUCCESS) {
        if (err) snprintf(err, err_len, "event listen failed");
        return -1;
    }
    return 0;
}

int hook_count(const hook_manager_t *mgr) {
    int n = 0;
    for (int i = 0; i < mgr->count; i++) {
        if (mgr->hooks[i].active) n++;
    }
    return n;
}

const hook_t *hook_at(const hook_manager_t *mgr, int index) {
    int n = 0;
    for (int i = 0; i < mgr->count; i++) {
        if (!mgr->hooks[i].active) continue;
        if (n == index) return &mgr->hooks[i];
        n++;
    }
    return NULL;
}
