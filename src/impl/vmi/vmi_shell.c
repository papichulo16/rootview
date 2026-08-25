#include "vmi/vmi_shell.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "vmi/vmi.h"

#define DUMP_MAX 4096

static void print_help(void) {
    printf("commands:\n"
           "  rp <paddr hex> <len>              read physical memory, hex dump\n"
           "  wp <paddr hex> <hex bytes>        write physical memory\n"
           "  rv <vaddr hex> <pid> <len>        read virtual memory (pid 0 = kernel)\n"
           "  wv <vaddr hex> <pid> <hex bytes>  write virtual memory\n"
           "  pause                             pause the vm\n"
           "  resume                            resume the vm\n"
           "  help                              show this message\n"
           "  quit | exit                       detach and leave the shell\n");
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
    int32_t pid;
    size_t len;
    if (sscanf(args, "%" SCNx64 " %" SCNi32 " %zu", &vaddr, &pid, &len) != 3 || len == 0 || len > DUMP_MAX) {
        printf("usage: rv <vaddr hex> <pid> <len <= %d>\n", DUMP_MAX);
        return;
    }

    unsigned char buf[DUMP_MAX];
    char err[256];
    if (vmi_read_virt(session, vaddr, pid, buf, len, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    hex_dump(vaddr, buf, len);
}

static void cmd_write_virt(vmi_session_t *session, const char *args) {
    uint64_t vaddr;
    int32_t pid;
    int consumed;
    if (sscanf(args, "%" SCNx64 " %" SCNi32 " %n", &vaddr, &pid, &consumed) != 2) {
        printf("usage: wv <vaddr hex> <pid> <hex bytes>\n");
        return;
    }

    unsigned char buf[DUMP_MAX];
    size_t len = parse_hex_bytes(args + consumed, buf, sizeof(buf));
    if (len == 0) {
        printf("usage: wv <vaddr hex> <pid> <hex bytes>\n");
        return;
    }

    char err[256];
    if (vmi_write_virt(session, vaddr, pid, buf, len, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    printf("wrote %zu bytes to 0x%" PRIx64 " (pid %d)\n", len, vaddr, pid);
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
