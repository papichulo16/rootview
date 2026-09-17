#include "vmi/vmi.h"

#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vm/vm_state.h"
#include "vm/vm_store.h"

int vmi_attach(const char *vm_name, vmi_session_t *session, char *err, size_t err_len) {
    if (session->attached) {
        if (err) snprintf(err, err_len, "session is already attached to '%s'", session->vm_name);
        return -1;
    }

    if (!vm_store_exists(vm_name)) {
        if (err) snprintf(err, err_len, "vm '%s' does not exist", vm_name);
        return -1;
    }

    vm_runtime_state_t st;
    vm_state_load(vm_name, &st);
    if (!vm_state_is_alive(&st)) {
        if (err) snprintf(err, err_len, "vm '%s' is not running", vm_name);
        return -1;
    }
    if (st.kvmi_socket[0] == '\0') {
        if (err) snprintf(err, err_len, "vm '%s' was started without --kvmi", vm_name);
        return -1;
    }

    int rc = -1;
    vmi_init_data_t *init_data = calloc(1, sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
    if (!init_data) {
        if (err) snprintf(err, err_len, "out of memory");
        goto out;
    }
    init_data->count = 1;
    init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
    init_data->entry[0].data = st.kvmi_socket;

    vmi_init_error_t init_err = VMI_INIT_ERROR_NONE;
    status_t status = vmi_init(&session->vmi, VMI_KVM, vm_name, VMI_INIT_DOMAINNAME, init_data, &init_err);
    if (status != VMI_SUCCESS) {
        if (err) snprintf(err, err_len, "libvmi init failed for '%s' (init_error %d)", vm_name, (int) init_err);
        goto out;
    }

    if (VMI_PM_UNKNOWN == vmi_init_paging(session->vmi, 0)) {
        if (err) snprintf(err, err_len, "failed to determine paging mode for '%s'", vm_name);
        vmi_destroy(session->vmi);
        goto out;
    }

    snprintf(session->vm_name, sizeof(session->vm_name), "%s", vm_name);
    session->attached = true;
    rc = 0;

out:
    free(init_data);
    return rc;
}

void vmi_detach(vmi_session_t *session) {
    if (!session->attached) return;
    vmi_destroy(session->vmi);
    memset(session, 0, sizeof(*session));
}

bool vmi_is_attached(const vmi_session_t *session) {
    return session->attached;
}

int vmi_read_phys(vmi_session_t *session, uint64_t paddr, void *buf, size_t len, char *err, size_t err_len) {
    if (!session->attached) {
        if (err) snprintf(err, err_len, "session not attached");
        return -1;
    }

    size_t got = 0;
    status_t rc = vmi_read_pa(session->vmi, paddr, len, buf, &got);
    if (rc != VMI_SUCCESS || got != len) {
        if (err) snprintf(err, err_len, "read_pa failed at 0x%lx (%zu/%zu bytes)", (unsigned long) paddr, got, len);
        return -1;
    }
    return 0;
}

int vmi_write_phys(vmi_session_t *session, uint64_t paddr, const void *buf, size_t len, char *err, size_t err_len) {
    if (!session->attached) {
        if (err) snprintf(err, err_len, "session not attached");
        return -1;
    }

    size_t put = 0;
    status_t rc = vmi_write_pa(session->vmi, paddr, len, (void *) buf, &put);
    if (rc != VMI_SUCCESS || put != len) {
        if (err) snprintf(err, err_len, "write_pa failed at 0x%lx (%zu/%zu bytes)", (unsigned long) paddr, put, len);
        return -1;
    }
    return 0;
}

static int current_dtb(vmi_session_t *session, addr_t *dtb, char *err, size_t err_len) {
    uint64_t cr3;
    if (vmi_get_vcpureg(session->vmi, &cr3, CR3, 0) != VMI_SUCCESS) {
        if (err) snprintf(err, err_len, "failed to read CR3");
        return -1;
    }
    *dtb = cr3 & ~0x1fffull;
    return 0;
}

static void dtb_access_context(vmi_session_t *session, addr_t dtb, uint64_t vaddr, access_context_t *ctx) {
    *ctx = (access_context_t) {
        .version = ACCESS_CONTEXT_VERSION,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = dtb,
        .pm = vmi_get_page_mode(session->vmi, 0),
        .addr = vaddr,
    };
}

int vmi_read_virt(vmi_session_t *session, uint64_t vaddr, void *buf, size_t len, char *err, size_t err_len) {
    if (!session->attached) {
        if (err) snprintf(err, err_len, "session not attached");
        return -1;
    }

    addr_t dtb;
    if (current_dtb(session, &dtb, err, err_len) != 0) return -1;

    access_context_t ctx;
    dtb_access_context(session, dtb, vaddr, &ctx);

    size_t got = 0;
    status_t rc = vmi_read(session->vmi, &ctx, len, buf, &got);
    if (rc != VMI_SUCCESS || got != len) {
        if (err) snprintf(err, err_len, "read failed at 0x%lx (%zu/%zu bytes)", (unsigned long) vaddr, got, len);
        return -1;
    }
    return 0;
}

int vmi_write_virt(vmi_session_t *session, uint64_t vaddr, const void *buf, size_t len, char *err, size_t err_len) {
    if (!session->attached) {
        if (err) snprintf(err, err_len, "session not attached");
        return -1;
    }

    addr_t dtb;
    if (current_dtb(session, &dtb, err, err_len) != 0) return -1;

    access_context_t ctx;
    dtb_access_context(session, dtb, vaddr, &ctx);

    size_t put = 0;
    status_t rc = vmi_write(session->vmi, &ctx, len, (void *) buf, &put);
    if (rc != VMI_SUCCESS || put != len) {
        if (err) snprintf(err, err_len, "write failed at 0x%lx (%zu/%zu bytes)", (unsigned long) vaddr, put, len);
        return -1;
    }
    return 0;
}

int vmi_pause(vmi_session_t *session, char *err, size_t err_len) {
    if (!session->attached) {
        if (err) snprintf(err, err_len, "session not attached");
        return -1;
    }
    if (vmi_pause_vm(session->vmi) != VMI_SUCCESS) {
        if (err) snprintf(err, err_len, "pause failed");
        return -1;
    }
    return 0;
}

int vmi_resume(vmi_session_t *session, char *err, size_t err_len) {
    if (!session->attached) {
        if (err) snprintf(err, err_len, "session not attached");
        return -1;
    }
    if (vmi_resume_vm(session->vmi) != VMI_SUCCESS) {
        if (err) snprintf(err, err_len, "resume failed");
        return -1;
    }
    return 0;
}

int vmi_read_reg(vmi_session_t *session, reg_t reg, uint64_t *value, char *err, size_t err_len) {
    if (!session->attached) {
        if (err) snprintf(err, err_len, "session not attached");
        return -1;
    }
    if (vmi_get_vcpureg(session->vmi, value, reg, 0) != VMI_SUCCESS) {
        if (err) snprintf(err, err_len, "failed to read register %" PRIu64, (uint64_t) reg);
        return -1;
    }
    return 0;
}

int vmi_write_reg(vmi_session_t *session, reg_t reg, uint64_t value, char *err, size_t err_len) {
    if (!session->attached) {
        if (err) snprintf(err, err_len, "session not attached");
        return -1;
    }
    if (vmi_set_vcpureg(session->vmi, value, reg, 0) != VMI_SUCCESS) {
        if (err) snprintf(err, err_len, "failed to write register %" PRIu64, (uint64_t) reg);
        return -1;
    }
    return 0;
}

int vmi_read_regs(vmi_session_t *session, x86_registers_t *regs, char *err, size_t err_len) {
    if (!session->attached) {
        if (err) snprintf(err, err_len, "session not attached");
        return -1;
    }
    registers_t full;
    if (vmi_get_vcpuregs(session->vmi, &full, 0) != VMI_SUCCESS) {
        if (err) snprintf(err, err_len, "failed to read register set");
        return -1;
    }
    *regs = full.x86;
    return 0;
}
