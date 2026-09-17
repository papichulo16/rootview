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

/* never compacts - active slots keep a stable address for libvmi's pointer
 * into &h->vmi_event. */
hook_t *hook_alloc_slot(hook_manager_t *mgr) {
    for (int i = 0; i < mgr->count; i++) {
        if (!mgr->hooks[i].active) return &mgr->hooks[i];
    }
    if (mgr->count < HOOK_MAX) return &mgr->hooks[mgr->count++];
    return NULL;
}

void hook_manager_init(hook_manager_t *mgr, vmi_session_t *session) {
    memset(mgr, 0, sizeof(*mgr));
    mgr->session = session;
}

void hook_manager_clear(hook_manager_t *mgr) {
    for (int i = 0; i < mgr->count; i++) {
        hook_t *h = &mgr->hooks[i];
        if (!h->active) continue;

        if (h->kind == HOOK_KIND_REGISTER) {
            vmi_clear_event(mgr->session->vmi, &h->vmi_event, NULL);
        } else {
            char err[128];
            vmi_write_virt(mgr->session, h->vaddr, &h->orig_byte, 1, err, sizeof(err));
        }
        h->active = false;
    }
    mgr->count = 0;
    mgr->pending_bp = NULL;

    if (mgr->bp_active) {
        vmi_clear_event(mgr->session->vmi, &mgr->bp_event, NULL);
        vmi_clear_event(mgr->session->vmi, &mgr->ss_event, NULL);
        mgr->bp_active = false;
    }
}

int hook_remove(hook_manager_t *mgr, const char *name, char *err, size_t err_len) {
    hook_t *h = hook_find_by_name(mgr, name);
    if (!h) {
        if (err) snprintf(err, err_len, "no hook named '%s'", name);
        return -1;
    }

    if (h->kind == HOOK_KIND_REGISTER) {
        vmi_clear_event(mgr->session->vmi, &h->vmi_event, NULL);
    } else {
        if (vmi_write_virt(mgr->session, h->vaddr, &h->orig_byte, 1, err, err_len) != 0) return -1;
        if (mgr->pending_bp == h) mgr->pending_bp = NULL;
    }

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
