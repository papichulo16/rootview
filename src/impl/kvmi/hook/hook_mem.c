#include "hook/hook.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "hook_priv.h"
#include "vmi/vmi.h"

static int parse_access(const char *s, uint8_t *access) {
    uint8_t mask = 0;
    for (const char *c = s; *c; c++) {
        switch (tolower((unsigned char) *c)) {
            case 'r': mask |= VMI_MEMACCESS_R; break;
            case 'w': mask |= VMI_MEMACCESS_W; break;
            case 'x': mask |= VMI_MEMACCESS_X; break;
            default: return -1;
        }
    }
    if (!mask) return -1;
    *access = mask;
    return 0;
}

static event_response_t on_mem_hit(vmi_instance_t vmi, vmi_event_t *event) {
    (void) vmi;
    hook_t *h = (hook_t *) event->data;
    hook_manager_t *mgr = h->mgr;

    hook_event_t ev = {
        .kind = HOOK_KIND_MEM,
        .name = h->name,
        .vcpu_id = event->vcpu_id,
        .mem_gpa = event->mem_event.gfn * VMI_PS_4KB + event->mem_event.offset,
        .mem_access = event->mem_event.out_access,
        .rip = event->x86_regs ? event->x86_regs->rip : 0,
    };

    /* a write to capture: the window as it is now, before the write lands,
     * then a step over the instruction - hook_mem_stepped finishes it */
    if (h->mem_capture && (ev.mem_access & VMI_MEMACCESS_W)) {
        ev.mem_captured = true;
        ev.mem_window = ev.mem_gpa & ~(uint64_t) (HOOK_MEM_WINDOW - 1);
        char err[128];
        vmi_read_phys(mgr->session, ev.mem_window, ev.mem_before, HOOK_MEM_WINDOW, err, sizeof(err));
        memcpy(ev.mem_after, ev.mem_before, HOOK_MEM_WINDOW);
        if (mgr->ss_active && ev.vcpu_id < HOOK_MAX_VCPUS) {
            /* one pending per vcpu: a stale one (a step that never came) goes out as it is */
            if (mgr->mem_pending[ev.vcpu_id].active) hook_mem_stepped(mgr, ev.vcpu_id);
            mgr->mem_pending[ev.vcpu_id].active = true;
            mgr->mem_pending[ev.vcpu_id].hook = h;
            mgr->mem_pending[ev.vcpu_id].ev = ev;
            return VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP;
        }
    }
    if (h->callback) h->callback(&ev, h->user_data);
    return VMI_EVENT_RESPONSE_NONE;
}

void hook_mem_stepped(hook_manager_t *mgr, uint32_t vcpu) {
    if (vcpu >= HOOK_MAX_VCPUS || !mgr->mem_pending[vcpu].active) return;
    hook_t *h = mgr->mem_pending[vcpu].hook;
    hook_event_t ev = mgr->mem_pending[vcpu].ev;
    mgr->mem_pending[vcpu].active = false;
    char err[128];
    ev.mem_after_ok = vmi_read_phys(mgr->session, ev.mem_window, ev.mem_after, HOOK_MEM_WINDOW, err, sizeof(err)) == 0;
    if (!ev.mem_after_ok) memcpy(ev.mem_after, ev.mem_before, HOOK_MEM_WINDOW);
    ev.name = h->name;
    if (h->active && h->callback) h->callback(&ev, h->user_data);
}

void hook_mem_forget(hook_manager_t *mgr, hook_t *h) {
    for (int v = 0; v < HOOK_MAX_VCPUS; v++)
        if (mgr->mem_pending[v].active && mgr->mem_pending[v].hook == h) mgr->mem_pending[v].active = false;
}

int hook_mem_add_gfn(hook_manager_t *mgr, const char *name, uint64_t gfn, const char *access_str, bool capture,
                     hook_callback_t callback, void *user_data, char *err, size_t err_len) {
    if (hook_find_by_name(mgr, name)) {
        if (err) snprintf(err, err_len, "hook '%s' already exists", name);
        return -1;
    }

    uint8_t access;
    if (parse_access(access_str, &access) != 0) {
        if (err) snprintf(err, err_len, "invalid access mask '%s' - use any combination of r, w, x", access_str);
        return -1;
    }
    if (capture && hook_ss_ensure(mgr, err, err_len) != 0) return -1;

    hook_t *h = hook_alloc_slot(mgr);
    if (!h) {
        if (err) snprintf(err, err_len, "hook limit reached (%d)", HOOK_MAX);
        return -1;
    }

    memset(h, 0, sizeof(*h));
    snprintf(h->name, sizeof(h->name), "%s", name);
    h->kind = HOOK_KIND_MEM;
    h->mem_gfn = gfn;
    h->mem_access = access;
    h->mem_capture = capture;
    h->mgr = mgr;
    h->callback = callback;
    h->user_data = user_data;

    h->vmi_event.version = VMI_EVENTS_VERSION;
    h->vmi_event.type = VMI_EVENT_MEMORY;
    h->vmi_event.mem_event.gfn = gfn;
    h->vmi_event.mem_event.in_access = access;
    h->vmi_event.callback = on_mem_hit;
    h->vmi_event.data = h;

    if (vmi_register_event(mgr->session->vmi, &h->vmi_event) != VMI_SUCCESS) {
        if (err) {
            snprintf(err, err_len, "failed to register mem access event on gfn 0x%lx (already watched?)",
                     (unsigned long) gfn);
        }
        return -1;
    }

    h->active = true;
    return 0;
}

int hook_mem_add(hook_manager_t *mgr, const char *name, uint64_t vaddr, const char *access_str,
                  hook_callback_t callback, void *user_data, char *err, size_t err_len) {
    uint64_t paddr;
    if (vmi_translate_virt(mgr->session, vaddr, &paddr, err, err_len) != 0) return -1;
    return hook_mem_add_gfn(mgr, name, paddr / VMI_PS_4KB, access_str, false, callback, user_data, err, err_len);
}
