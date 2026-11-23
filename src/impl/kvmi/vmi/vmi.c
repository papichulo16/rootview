#include "vmi/vmi.h"

#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vmi/vmi_ops.h"
#include "vmi/vmi_reg_names.h"
#include "vm/vm_state.h"
#include "vm/vm_store.h"

static int kvmi_attach(const char *vm_name, vmi_session_t *session, char *err, size_t err_len) {
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
    status_t status = vmi_init(&session->vmi, VMI_KVM, vm_name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data,
                                &init_err);
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

static void kvmi_detach(vmi_session_t *session) {
    vmi_destroy(session->vmi);
}

static int kvmi_read_phys(vmi_session_t *session, uint64_t paddr, void *buf, size_t len, char *err, size_t err_len) {
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

static int kvmi_write_phys(vmi_session_t *session, uint64_t paddr, const void *buf, size_t len, char *err, size_t err_len) {
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

/* physical-address bits 51:12 - drops the PCID (11:0) and no-flush (63) bits */
#define CR3_PA_MASK 0x000ffffffffff000ull
/* KPTI's user PGD is the kernel PGD's 8KiB-pair partner with this bit set */
#define CR3_PTI_USER (1ull << 12)

/* picks the root to walk for vaddr: CR3 as-is first, since that's the table
 * the vcpu is really using - without KPTI bit 12 is just part of the root's
 * address, and clearing it lands on an unrelated page. only if that doesn't
 * map vaddr and bit 12 is set, retry with it cleared, which under KPTI is the
 * kernel PGD behind a vcpu paused in userspace. */
static int current_dtb(vmi_session_t *session, uint64_t vaddr, addr_t *dtb, char *err, size_t err_len) {
    uint64_t cr3;
    if (vmi_get_vcpureg(session->vmi, &cr3, CR3, 0) != VMI_SUCCESS) {
        if (err) snprintf(err, err_len, "failed to read CR3");
        return -1;
    }

    addr_t kept = cr3 & CR3_PA_MASK, pa;
    *dtb = kept;
    if (vmi_pagetable_lookup(session->vmi, kept, vaddr, &pa) == VMI_SUCCESS) return 0;
    if ((kept & CR3_PTI_USER) &&
        vmi_pagetable_lookup(session->vmi, kept & ~CR3_PTI_USER, vaddr, &pa) == VMI_SUCCESS)
        *dtb = kept & ~CR3_PTI_USER;
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

static int kvmi_read_virt(vmi_session_t *session, uint64_t vaddr, void *buf, size_t len, char *err, size_t err_len) {
    if (!session->attached) {
        if (err) snprintf(err, err_len, "session not attached");
        return -1;
    }

    addr_t dtb;
    if (current_dtb(session, vaddr, &dtb, err, err_len) != 0) return -1;

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

static int kvmi_write_virt(vmi_session_t *session, uint64_t vaddr, const void *buf, size_t len, char *err, size_t err_len) {
    if (!session->attached) {
        if (err) snprintf(err, err_len, "session not attached");
        return -1;
    }

    addr_t dtb;
    if (current_dtb(session, vaddr, &dtb, err, err_len) != 0) return -1;

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

static int kvmi_translate_virt(vmi_session_t *session, uint64_t vaddr, uint64_t *paddr, char *err, size_t err_len) {
    if (!session->attached) {
        if (err) snprintf(err, err_len, "session not attached");
        return -1;
    }

    addr_t dtb;
    if (current_dtb(session, vaddr, &dtb, err, err_len) != 0) return -1;

    addr_t pa;
    if (vmi_pagetable_lookup(session->vmi, dtb, vaddr, &pa) != VMI_SUCCESS) {
        if (err) snprintf(err, err_len, "failed to translate 0x%lx to a physical address", (unsigned long) vaddr);
        return -1;
    }

    *paddr = pa;
    return 0;
}

/* what libvmi cached while the guest ran can be stale: vmalloc addresses get
 * remapped as kernel objects are freed and reallocated */
static void drop_caches(vmi_session_t *session) {
    vmi_v2pcache_flush(session->vmi, ~0ull);
    vmi_pagecache_flush(session->vmi);
}

static int kvmi_refresh_paging(vmi_session_t *session, char *err, size_t err_len) {
    if (!session->attached) {
        if (err) snprintf(err, err_len, "session not attached");
        return -1;
    }
    drop_caches(session);
    if (VMI_PM_UNKNOWN == vmi_init_paging(session->vmi, 0)) {
        if (err) snprintf(err, err_len, "failed to determine paging mode");
        return -1;
    }
    return 0;
}

static int kvmi_pause(vmi_session_t *session, char *err, size_t err_len) {
    if (!session->attached) {
        if (err) snprintf(err, err_len, "session not attached");
        return -1;
    }
    if (vmi_pause_vm(session->vmi) != VMI_SUCCESS) {
        if (err) snprintf(err, err_len, "pause failed");
        return -1;
    }
    drop_caches(session);
    return 0;
}

static int kvmi_resume(vmi_session_t *session, char *err, size_t err_len) {
    if (!session->attached) {
        if (err) snprintf(err, err_len, "session not attached");
        return -1;
    }
    drop_caches(session);
    if (vmi_resume_vm(session->vmi) != VMI_SUCCESS) {
        if (err) snprintf(err, err_len, "resume failed");
        return -1;
    }
    return 0;
}

static int kvmi_read_reg(vmi_session_t *session, reg_t reg, uint64_t *value, char *err, size_t err_len) {
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

static int kvmi_write_reg(vmi_session_t *session, reg_t reg, uint64_t value, char *err, size_t err_len) {
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

static int kvmi_read_regs(vmi_session_t *session, x86_registers_t *regs, char *err, size_t err_len) {
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

static int kvmi_read_reg_name(vmi_session_t *session, const char *name, uint64_t *value, char *err, size_t err_len) {
    reg_t reg;
    if (vmi_reg_lookup(name, &reg) != 0) {
        if (err) snprintf(err, err_len, "unknown register '%s'", name);
        return -1;
    }
    return kvmi_read_reg(session, reg, value, err, err_len);
}

static int kvmi_write_reg_name(vmi_session_t *session, const char *name, uint64_t value, char *err, size_t err_len) {
    reg_t reg;
    if (vmi_reg_lookup(name, &reg) != 0) {
        if (err) snprintf(err, err_len, "unknown register '%s'", name);
        return -1;
    }
    if (!vmi_reg_write_supported(reg)) {
        if (err) snprintf(err, err_len, "'%s' can't be written: only rax..r15, rip and rflags", name);
        return -1;
    }
    return kvmi_write_reg(session, reg, value, err, err_len);
}

/* the syscall entry point, always in the image's text */
static int kvmi_kernel_anchor(vmi_session_t *session, uint64_t *vaddr, char *err, size_t err_len) {
    return kvmi_read_reg(session, MSR_LSTAR, vaddr, err, err_len);
}

const vmi_ops_t g_kvmi_ops = {
    .name = VMI_BACKEND_KVMI,
    .arch = VMI_ARCH_X86_64,
    .hooks = true,
    .attach = kvmi_attach,
    .detach = kvmi_detach,
    .read_phys = kvmi_read_phys,
    .write_phys = kvmi_write_phys,
    .read_virt = kvmi_read_virt,
    .write_virt = kvmi_write_virt,
    .translate_virt = kvmi_translate_virt,
    .refresh_paging = kvmi_refresh_paging,
    .pause = kvmi_pause,
    .resume = kvmi_resume,
    .read_reg_name = kvmi_read_reg_name,
    .write_reg_name = kvmi_write_reg_name,
    .kernel_anchor = kvmi_kernel_anchor,
    .read_reg = kvmi_read_reg,
    .write_reg = kvmi_write_reg,
    .read_regs = kvmi_read_regs,
};
