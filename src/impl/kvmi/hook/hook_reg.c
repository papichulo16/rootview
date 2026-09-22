#include "hook/hook.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "hook_priv.h"
#include "vmi/vmi.h"
#include "vmi/vmi_reg_names.h"

static event_response_t on_reg_hit(vmi_instance_t vmi, vmi_event_t *event) {
    (void) vmi;
    hook_t *h = (hook_t *) event->data;

    hook_event_t ev = {
        .kind = HOOK_KIND_REGISTER,
        .name = h->name,
        .vcpu_id = event->vcpu_id,
        .vaddr = 0,
        .old_value = event->reg_event.previous,
        .new_value = event->reg_event.value,
    };
    if (h->callback) h->callback(&ev, h->user_data);
    return VMI_EVENT_RESPONSE_NONE;
}

int hook_reg_add(hook_manager_t *mgr, const char *name, const char *reg_name, hook_callback_t callback,
                  void *user_data, char *err, size_t err_len) {
    if (hook_find_by_name(mgr, name)) {
        if (err) snprintf(err, err_len, "hook '%s' already exists", name);
        return -1;
    }

    reg_t reg;
    if (strcasecmp(reg_name, "msr_all") == 0) {
        reg = MSR_ALL;
    } else if (vmi_reg_lookup(reg_name, &reg) != 0 || (reg != CR0 && reg != CR3 && reg != CR4)) {
        if (err) {
            snprintf(err, err_len, "unsupported hook register '%s' - only cr0, cr3, cr4 and msr_all", reg_name);
        }
        return -1;
    }

    hook_t *h = hook_alloc_slot(mgr);
    if (!h) {
        if (err) snprintf(err, err_len, "hook limit reached (%d)", HOOK_MAX);
        return -1;
    }

    memset(h, 0, sizeof(*h));
    snprintf(h->name, sizeof(h->name), "%s", name);
    h->kind = HOOK_KIND_REGISTER;
    h->reg = reg;
    h->callback = callback;
    h->user_data = user_data;

    h->vmi_event.version = VMI_EVENTS_VERSION;
    h->vmi_event.type = VMI_EVENT_REGISTER;
    h->vmi_event.reg_event.reg = reg;
    h->vmi_event.reg_event.in_access = VMI_REGACCESS_W;
    h->vmi_event.callback = on_reg_hit;
    h->vmi_event.data = h;

    if (vmi_register_event(mgr->session->vmi, &h->vmi_event) != VMI_SUCCESS) {
        if (err) snprintf(err, err_len, "failed to register write event on '%s' (already watched?)", reg_name);
        return -1;
    }

    h->active = true;
    return 0;
}
