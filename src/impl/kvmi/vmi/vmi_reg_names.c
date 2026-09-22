#include "vmi/vmi_reg_names.h"

#include <stddef.h>
#include <strings.h>

typedef struct {
    const char *name;
    reg_t reg;
} reg_entry_t;

static const reg_entry_t REG_TABLE[] = {
    /* general purpose */
    { "rax", RAX }, { "rbx", RBX }, { "rcx", RCX }, { "rdx", RDX },
    { "rbp", RBP }, { "rsi", RSI }, { "rdi", RDI }, { "rsp", RSP },
    { "rip", RIP }, { "rflags", RFLAGS },
    { "r8", R8 }, { "r9", R9 }, { "r10", R10 }, { "r11", R11 },
    { "r12", R12 }, { "r13", R13 }, { "r14", R14 }, { "r15", R15 },

    /* control / debug - kernel-only, high privilege */
    { "cr0", CR0 }, { "cr2", CR2 }, { "cr3", CR3 }, { "cr4", CR4 }, { "xcr0", XCR0 },
    { "dr0", DR0 }, { "dr1", DR1 }, { "dr2", DR2 }, { "dr3", DR3 },
    { "dr6", DR6 }, { "dr7", DR7 },

    /* descriptor tables */
    { "idtr_base", IDTR_BASE }, { "idtr_limit", IDTR_LIMIT },
    { "gdtr_base", GDTR_BASE }, { "gdtr_limit", GDTR_LIMIT },

    /* segment selectors / bases */
    { "cs_sel", CS_SEL }, { "ds_sel", DS_SEL }, { "es_sel", ES_SEL },
    { "fs_sel", FS_SEL }, { "gs_sel", GS_SEL }, { "ss_sel", SS_SEL },
    { "tr_sel", TR_SEL }, { "ldtr_sel", LDTR_SEL },
    { "fs_base", FS_BASE }, { "gs_base", GS_BASE }, { "shadow_gs", SHADOW_GS },

    /* syscall / sysenter setup - classic rootkit hook targets */
    { "sysenter_cs", SYSENTER_CS }, { "sysenter_esp", SYSENTER_ESP }, { "sysenter_eip", SYSENTER_EIP },
    { "msr_efer", MSR_EFER }, { "msr_star", MSR_STAR }, { "msr_lstar", MSR_LSTAR },
    { "msr_cstar", MSR_CSTAR }, { "msr_syscall_mask", MSR_SYSCALL_MASK },

    { "tsc", TSC },
};

int vmi_reg_lookup(const char *name, reg_t *out) {
    for (size_t i = 0; i < sizeof(REG_TABLE) / sizeof(REG_TABLE[0]); i++) {
        if (strcasecmp(name, REG_TABLE[i].name) == 0) {
            *out = REG_TABLE[i].reg;
            return 0;
        }
    }
    return -1;
}

bool vmi_reg_write_supported(reg_t reg) {
    return reg <= R15; /* RAX..R15, RIP, RFLAGS are the contiguous 0..R15 range */
}
