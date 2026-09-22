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

    hook_event_t ev = {
        .kind = HOOK_KIND_MEM,
        .name = h->name,
        .vcpu_id = event->vcpu_id,
        .mem_gpa = event->mem_event.gfn * VMI_PS_4KB + event->mem_event.offset,
        .mem_access = event->mem_event.out_access,
    };
    if (h->callback) h->callback(&ev, h->user_data);

    return VMI_EVENT_RESPONSE_NONE;
}

int hook_mem_add(hook_manager_t *mgr, const char *name, uint64_t vaddr, const char *access_str,
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

    uint64_t paddr;
    if (vmi_translate_virt(mgr->session, vaddr, &paddr, err, err_len) != 0) return -1;
    uint64_t gfn = paddr / VMI_PS_4KB;

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
