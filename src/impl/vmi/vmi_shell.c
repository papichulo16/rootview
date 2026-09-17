#include "vmi/vmi_shell.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "vmi/vmi.h"
#include "vmi/vmi_reg_names.h"

#define DUMP_MAX 4096
#define REG_NAME_MAX 32

static void print_help(void) {
    printf("commands:\n"
           "  pause                       pause the vm\n"
           "  resume                      resume the vm\n"
           "  rp <paddr hex> <len>        read physical memory, hex dump\n"
           "  wp <paddr hex> <hex bytes>  write physical memory\n"
           "  rv <vaddr hex> <len>        read virtual memory (walks the current CR3)\n"
           "  wv <vaddr hex> <hex bytes>  write virtual memory (walks the current CR3)\n"
           "  reg <name>                  read a vcpu register (gp, control, debug, MSR, ...)\n"
           "  setreg <name> <value hex>   write a vcpu register - pause the vm first\n"
           "  regs                        dump the common registers\n"
           "  help                        show this message\n"
           "  quit | exit                 detach and leave the shell\n");
}

static void hex_dump(uint64_t base, const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i += 16) {
        printf("%016" PRIx64 "  ", base + i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len) printf("%02x ", buf[i + j]);
            else printf("   ");
        }
        printf(" ");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            unsigned char c = buf[i + j];
            putchar(isprint(c) ? c : '.');
        }
        putchar('\n');
    }
}

/* parses contiguous hex pairs ("4142..."), stops at the first non-hex byte */
static size_t parse_hex_bytes(const char *s, unsigned char *out, size_t max) {
    size_t n = 0;
    while (n < max && isxdigit((unsigned char) s[0]) && isxdigit((unsigned char) s[1])) {
        unsigned int byte;
        sscanf(s, "%2x", &byte);
        out[n++] = (unsigned char) byte;
        s += 2;
    }
    return n;
}

static void cmd_read_phys(vmi_session_t *session, const char *args) {
    uint64_t paddr;
    size_t len;
    if (sscanf(args, "%" SCNx64 " %zu", &paddr, &len) != 2 || len == 0 || len > DUMP_MAX) {
        printf("usage: rp <paddr hex> <len <= %d>\n", DUMP_MAX);
        return;
    }

    unsigned char buf[DUMP_MAX];
    char err[256];
    if (vmi_read_phys(session, paddr, buf, len, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    hex_dump(paddr, buf, len);
}

static void cmd_write_phys(vmi_session_t *session, const char *args) {
    uint64_t paddr;
    int consumed;
    if (sscanf(args, "%" SCNx64 " %n", &paddr, &consumed) != 1) {
        printf("usage: wp <paddr hex> <hex bytes>\n");
        return;
    }

    unsigned char buf[DUMP_MAX];
    size_t len = parse_hex_bytes(args + consumed, buf, sizeof(buf));
    if (len == 0) {
        printf("usage: wp <paddr hex> <hex bytes>\n");
        return;
    }

    char err[256];
    if (vmi_write_phys(session, paddr, buf, len, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    printf("wrote %zu bytes to 0x%" PRIx64 "\n", len, paddr);
}

static void cmd_read_virt(vmi_session_t *session, const char *args) {
    uint64_t vaddr;
    size_t len;
    if (sscanf(args, "%" SCNx64 " %zu", &vaddr, &len) != 2 || len == 0 || len > DUMP_MAX) {
        printf("usage: rv <vaddr hex> <len <= %d>\n", DUMP_MAX);
        return;
    }

    unsigned char buf[DUMP_MAX];
    char err[256];
    if (vmi_read_virt(session, vaddr, buf, len, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    hex_dump(vaddr, buf, len);
}

static void cmd_write_virt(vmi_session_t *session, const char *args) {
    uint64_t vaddr;
    int consumed;
    if (sscanf(args, "%" SCNx64 " %n", &vaddr, &consumed) != 1) {
        printf("usage: wv <vaddr hex> <hex bytes>\n");
        return;
    }

    unsigned char buf[DUMP_MAX];
    size_t len = parse_hex_bytes(args + consumed, buf, sizeof(buf));
    if (len == 0) {
        printf("usage: wv <vaddr hex> <hex bytes>\n");
        return;
    }

    char err[256];
    if (vmi_write_virt(session, vaddr, buf, len, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    printf("wrote %zu bytes to 0x%" PRIx64 "\n", len, vaddr);
}

static void cmd_read_reg(vmi_session_t *session, const char *args) {
    char name[REG_NAME_MAX];
    if (sscanf(args, "%31s", name) != 1) {
        printf("usage: reg <name>\n");
        return;
    }

    reg_t reg;
    if (vmi_reg_lookup(name, &reg) != 0) {
        printf("unknown register '%s'\n", name);
        return;
    }

    uint64_t value;
    char err[256];
    if (vmi_read_reg(session, reg, &value, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    printf("%s = 0x%016" PRIx64 "\n", name, value);
}

static void cmd_write_reg(vmi_session_t *session, const char *args) {
    char name[REG_NAME_MAX];
    uint64_t value;
    if (sscanf(args, "%31s %" SCNx64, name, &value) != 2) {
        printf("usage: setreg <name> <value hex>\n");
        return;
    }

    reg_t reg;
    if (vmi_reg_lookup(name, &reg) != 0) {
        printf("unknown register '%s'\n", name);
        return;
    }

    char err[256];
    if (vmi_write_reg(session, reg, value, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    printf("%s = 0x%016" PRIx64 "\n", name, value);
}

static void cmd_dump_regs(vmi_session_t *session) {
    x86_registers_t regs;
    char err[256];
    if (vmi_read_regs(session, &regs, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }

    printf("rip=0x%016" PRIx64 " rsp=0x%016" PRIx64 " rflags=0x%016" PRIx64 "\n",
           regs.rip, regs.rsp, regs.rflags);
    printf("cr0=0x%016" PRIx64 " cr3=0x%016" PRIx64 " cr4=0x%016" PRIx64 "\n",
           regs.cr0, regs.cr3, regs.cr4);
    printf("dr6=0x%016" PRIx64 " dr7=0x%016" PRIx64 "\n", regs.dr6, regs.dr7);
    printf("idtr_base=0x%016" PRIx64 " idtr_limit=0x%04" PRIx64 "  "
           "gdtr_base=0x%016" PRIx64 " gdtr_limit=0x%04" PRIx64 "\n",
           regs.idtr_base, regs.idtr_limit, regs.gdtr_base, regs.gdtr_limit);
    printf("msr_efer=0x%016" PRIx64 " msr_star=0x%016" PRIx64 " "
           "msr_lstar=0x%016" PRIx64 " msr_cstar=0x%016" PRIx64 "\n",
           regs.msr_efer, regs.msr_star, regs.msr_lstar, regs.msr_cstar);
}

static void cmd_pause(vmi_session_t *session) {
    char err[256];
    if (vmi_pause(session, err, sizeof(err)) != 0) printf("error: %s\n", err);
    else printf("paused\n");
}

static void cmd_resume(vmi_session_t *session) {
    char err[256];
    if (vmi_resume(session, err, sizeof(err)) != 0) printf("error: %s\n", err);
    else printf("resumed\n");
}

static bool dispatch(vmi_session_t *session, char *line) {
    char *cmd = strtok(line, " \t\r\n");
    if (!cmd) return true;
    char *args = strtok(NULL, "\r\n");
    if (!args) args = "";
    while (*args == ' ' || *args == '\t') args++;

    if (strcmp(cmd, "rp") == 0) cmd_read_phys(session, args);
    else if (strcmp(cmd, "wp") == 0) cmd_write_phys(session, args);
    else if (strcmp(cmd, "rv") == 0) cmd_read_virt(session, args);
    else if (strcmp(cmd, "wv") == 0) cmd_write_virt(session, args);
    else if (strcmp(cmd, "reg") == 0) cmd_read_reg(session, args);
    else if (strcmp(cmd, "setreg") == 0) cmd_write_reg(session, args);
    else if (strcmp(cmd, "regs") == 0) cmd_dump_regs(session);
    else if (strcmp(cmd, "pause") == 0) cmd_pause(session);
    else if (strcmp(cmd, "resume") == 0) cmd_resume(session);
    else if (strcmp(cmd, "help") == 0) print_help();
    else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) return false;
    else printf("unknown command '%s' (try 'help')\n", cmd);

    return true;
}

void vmi_shell_run(vmi_session_t *session) {
    char line[DUMP_MAX * 2 + 64];

    while (vmi_is_attached(session)) {
        printf("vmi(%s)> ", session->vm_name);
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            putchar('\n');
            break;
        }
        if (!dispatch(session, line)) break;
    }
}
