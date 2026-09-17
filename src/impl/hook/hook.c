#include "hook/hook.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "vmi/vmi.h"
#include "vmi/vmi_reg_names.h"

static hook_t *find_by_name(hook_manager_t *mgr, const char *name) {
    for (int i = 0; i < mgr->count; i++) {
        if (mgr->hooks[i].active && strcmp(mgr->hooks[i].name, name) == 0) return &mgr->hooks[i];
    }
    return NULL;
}

static hook_t *find_bp_by_vaddr(hook_manager_t *mgr, uint64_t vaddr) {
    for (int i = 0; i < mgr->count; i++) {
        hook_t *h = &mgr->hooks[i];
        if (h->active && h->kind == HOOK_KIND_BREAKPOINT && h->vaddr == vaddr) return h;
    }
    return NULL;
}

static hook_t *alloc_slot(hook_manager_t *mgr) {
    for (int i = 0; i < mgr->count; i++) {
        if (!mgr->hooks[i].active) return &mgr->hooks[i];
    }
    if (mgr->count < HOOK_MAX) return &mgr->hooks[mgr->count++];
    return NULL;
}

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

static event_response_t on_bp_hit(vmi_instance_t vmi, vmi_event_t *event) {
    (void) vmi;
    hook_manager_t *mgr = (hook_manager_t *) event->data;

    event->interrupt_event.reinject = 1;
    if (!event->interrupt_event.insn_length) event->interrupt_event.insn_length = 1;

    uint64_t vaddr = event->x86_regs->rip;
    hook_t *h = find_bp_by_vaddr(mgr, vaddr);
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

int hook_reg_add(hook_manager_t *mgr, const char *name, const char *reg_name, hook_callback_t callback,
                  void *user_data, char *err, size_t err_len) {
    if (find_by_name(mgr, name)) {
        if (err) snprintf(err, err_len, "hook '%s' already exists", name);
        return -1;
    }

    reg_t reg;
    if (strcasecmp(reg_name, "msr_all") == 0) {
        reg = MSR_ALL;
    } else if (vmi_reg_lookup(reg_name, &reg) != 0 || (reg != CR0 && reg != CR3 && reg != CR4)) {
        if (err) {
            snprintf(err, err_len,
                     "unsupported hook register '%s' - only cr0, cr3, cr4 and msr_all can be write-hooked "
                     "on this kvmi build",
                     reg_name);
        }
        return -1;
    }

    hook_t *h = alloc_slot(mgr);
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

int hook_bp_add(hook_manager_t *mgr, const char *name, uint64_t vaddr, hook_callback_t callback, void *user_data,
                 char *err, size_t err_len) {
    if (find_by_name(mgr, name)) {
        if (err) snprintf(err, err_len, "hook '%s' already exists", name);
        return -1;
    }
    if (find_bp_by_vaddr(mgr, vaddr)) {
        if (err) snprintf(err, err_len, "a breakpoint is already planted at 0x%lx", (unsigned long) vaddr);
        return -1;
    }

    if (ensure_bp_infra(mgr, err, err_len) != 0) return -1;

    hook_t *h = alloc_slot(mgr);
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

int hook_remove(hook_manager_t *mgr, const char *name, char *err, size_t err_len) {
    hook_t *h = find_by_name(mgr, name);
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
