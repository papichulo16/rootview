#include "hook/hook.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "hook_priv.h"
#include "vmi/vmi.h"

static int parse_table(const char *s, hook_desc_t *table) {
    if (strcasecmp(s, "idtr") == 0) *table = HOOK_DESC_IDTR;
    else if (strcasecmp(s, "gdtr") == 0) *table = HOOK_DESC_GDTR;
    else if (strcasecmp(s, "ldtr") == 0) *table = HOOK_DESC_LDTR;
    else if (strcasecmp(s, "tr") == 0) *table = HOOK_DESC_TR;
    else return -1;
    return 0;
}

static event_response_t on_desc_hit(vmi_instance_t vmi, vmi_event_t *event) {
    (void) vmi;
    hook_manager_t *mgr = (hook_manager_t *) event->data;

    hook_t *h = hook_find_desc(mgr, (hook_desc_t) event->descriptor_event.descriptor);
    if (!h) return VMI_EVENT_RESPONSE_NONE;

    hook_event_t ev = {
        .kind = HOOK_KIND_DESCRIPTOR,
        .name = h->name,
        .vcpu_id = event->vcpu_id,
        .descriptor = h->descriptor,
        .desc_is_write = event->descriptor_event.is_write,
    };
    if (h->callback) h->callback(&ev, h->user_data);

    return VMI_EVENT_RESPONSE_NONE;
}

/* KVMI allows only one DESCRIPTOR registration at a time, so every
 * descriptor hook shares this one event. */
static int ensure_desc_infra(hook_manager_t *mgr, char *err, size_t err_len) {
    if (mgr->desc_active) return 0;

    memset(&mgr->desc_event, 0, sizeof(mgr->desc_event));
    mgr->desc_event.version = VMI_EVENTS_VERSION;
    mgr->desc_event.type = VMI_EVENT_DESCRIPTOR_ACCESS;
    mgr->desc_event.callback = on_desc_hit;
    mgr->desc_event.data = mgr;

    if (vmi_register_event(mgr->session->vmi, &mgr->desc_event) != VMI_SUCCESS) {
        if (err) snprintf(err, err_len, "failed to enable descriptor-access trapping on this vm");
        return -1;
    }

    mgr->desc_active = true;
    return 0;
}

int hook_desc_add(hook_manager_t *mgr, const char *name, const char *table_str, hook_callback_t callback,
                   void *user_data, char *err, size_t err_len) {
    if (hook_find_by_name(mgr, name)) {
        if (err) snprintf(err, err_len, "hook '%s' already exists", name);
        return -1;
    }

    hook_desc_t table;
    if (parse_table(table_str, &table) != 0) {
        if (err) snprintf(err, err_len, "unsupported descriptor table '%s' - only idtr, gdtr, ldtr and tr", table_str);
        return -1;
    }
    if (hook_find_desc(mgr, table)) {
        if (err) snprintf(err, err_len, "a descriptor hook is already watching this table");
        return -1;
    }

    if (ensure_desc_infra(mgr, err, err_len) != 0) return -1;

    hook_t *h = hook_alloc_slot(mgr);
    if (!h) {
        if (err) snprintf(err, err_len, "hook limit reached (%d)", HOOK_MAX);
        return -1;
    }

    memset(h, 0, sizeof(*h));
    snprintf(h->name, sizeof(h->name), "%s", name);
    h->kind = HOOK_KIND_DESCRIPTOR;
    h->descriptor = table;
    h->callback = callback;
    h->user_data = user_data;
    h->active = true;

    return 0;
}
