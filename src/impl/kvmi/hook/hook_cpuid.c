#include "hook/hook.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "hook_priv.h"
#include "vmi/vmi.h"

static int parse_leaf(const char *s, uint32_t *leaf) {
    if (strcasecmp(s, "any") == 0) {
        *leaf = HOOK_CPUID_ANY_LEAF;
        return 0;
    }

    char *end;
    unsigned long v = strtoul(s, &end, 16);
    if (*s == '\0' || *end != '\0' || v > UINT32_MAX) return -1;
    *leaf = (uint32_t) v;
    return 0;
}

static event_response_t on_cpuid_hit(vmi_instance_t vmi, vmi_event_t *event) {
    (void) vmi;
    hook_manager_t *mgr = (hook_manager_t *) event->data;

    hook_t *h = hook_find_cpuid_by_leaf(mgr, event->cpuid_event.leaf);
    if (!h) return VMI_EVENT_RESPONSE_NONE;

    hook_event_t ev = {
        .kind = HOOK_KIND_CPUID,
        .name = h->name,
        .vcpu_id = event->vcpu_id,
        .cpuid_leaf = event->cpuid_event.leaf,
        .cpuid_subleaf = event->cpuid_event.subleaf,
    };
    if (h->callback) h->callback(&ev, h->user_data);

    return VMI_EVENT_RESPONSE_NONE;
}

/* KVMI allows only one CPUID registration at a time, so every cpuid hook
 * shares this one event. */
static int ensure_cpuid_infra(hook_manager_t *mgr, char *err, size_t err_len) {
    if (mgr->cpuid_active) return 0;

    memset(&mgr->cpuid_event, 0, sizeof(mgr->cpuid_event));
    mgr->cpuid_event.version = VMI_EVENTS_VERSION;
    mgr->cpuid_event.type = VMI_EVENT_CPUID;
    mgr->cpuid_event.callback = on_cpuid_hit;
    mgr->cpuid_event.data = mgr;

    if (vmi_register_event(mgr->session->vmi, &mgr->cpuid_event) != VMI_SUCCESS) {
        if (err) snprintf(err, err_len, "failed to enable cpuid trapping on this vm");
        return -1;
    }

    mgr->cpuid_active = true;
    return 0;
}

int hook_cpuid_add(hook_manager_t *mgr, const char *name, const char *leaf_str, hook_callback_t callback,
                    void *user_data, char *err, size_t err_len) {
    if (hook_find_by_name(mgr, name)) {
        if (err) snprintf(err, err_len, "hook '%s' already exists", name);
        return -1;
    }

    uint32_t leaf;
    if (parse_leaf(leaf_str, &leaf) != 0) {
        if (err) snprintf(err, err_len, "invalid cpuid leaf '%s' - use a hex value or 'any'", leaf_str);
        return -1;
    }

    if (ensure_cpuid_infra(mgr, err, err_len) != 0) return -1;

    hook_t *h = hook_alloc_slot(mgr);
    if (!h) {
        if (err) snprintf(err, err_len, "hook limit reached (%d)", HOOK_MAX);
        return -1;
    }

    memset(h, 0, sizeof(*h));
    snprintf(h->name, sizeof(h->name), "%s", name);
    h->kind = HOOK_KIND_CPUID;
    h->cpuid_leaf = leaf;
    h->callback = callback;
    h->user_data = user_data;
    h->active = true;

    return 0;
}
