#include "hook/hook_shell.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "hook/hook.h"
#include "hook/hook_types.h"
#include "vmi/vmi.h"

#define LINE_MAX 256

static void print_help(void) {
    printf("commands:\n"
           "  watch <name> <cr0|cr3|cr4|msr_all>  hook writes to a register\n"
           "  bp <name> <vaddr hex>               plant a breakpoint hook\n"
           "  unhook <name>                       remove a hook\n"
           "  list                                list active hooks\n"
           "  listen [ms]                          poll for hook events (default 1000ms, 0 drains only)\n"
           "  pause                                pause the vm\n"
           "  resume                               resume the vm\n"
           "  help                                 show this message\n"
           "  quit | exit                          detach and leave the shell\n");
}

static void on_hook_event(const hook_event_t *ev, void *user_data) {
    (void) user_data;
    if (ev->kind == HOOK_KIND_REGISTER) {
        printf("[hook] %-16s vcpu=%u write 0x%016" PRIx64 " -> 0x%016" PRIx64 "\n", ev->name, ev->vcpu_id,
               ev->old_value, ev->new_value);
    } else {
        printf("[hook] %-16s vcpu=%u hit at 0x%016" PRIx64 "\n", ev->name, ev->vcpu_id, ev->vaddr);
    }
}

static void cmd_watch(hook_manager_t *mgr, const char *args) {
    char name[HOOK_NAME_MAX], reg[32];
    if (sscanf(args, "%63s %31s", name, reg) != 2) {
        printf("usage: watch <name> <cr0|cr3|cr4|msr_all>\n");
        return;
    }

    char err[256];
    if (hook_reg_add(mgr, name, reg, on_hook_event, NULL, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    printf("watching '%s' on %s\n", name, reg);
}

static void cmd_bp(hook_manager_t *mgr, const char *args) {
    char name[HOOK_NAME_MAX];
    uint64_t vaddr;
    if (sscanf(args, "%63s %" SCNx64, name, &vaddr) != 2) {
        printf("usage: bp <name> <vaddr hex>\n");
        return;
    }

    char err[256];
    if (hook_bp_add(mgr, name, vaddr, on_hook_event, NULL, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    printf("planted '%s' at 0x%" PRIx64 "\n", name, vaddr);
}

static void cmd_unhook(hook_manager_t *mgr, const char *args) {
    char name[HOOK_NAME_MAX];
    if (sscanf(args, "%63s", name) != 1) {
        printf("usage: unhook <name>\n");
        return;
    }

    char err[256];
    if (hook_remove(mgr, name, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    printf("removed '%s'\n", name);
}

static void cmd_list(hook_manager_t *mgr) {
    int n = hook_count(mgr);
    if (n == 0) {
        printf("no active hooks\n");
        return;
    }
    for (int i = 0; i < n; i++) {
        const hook_t *h = hook_at(mgr, i);
        if (h->kind == HOOK_KIND_REGISTER) printf("  %-16s register\n", h->name);
        else printf("  %-16s breakpoint @ 0x%016" PRIx64 "\n", h->name, h->vaddr);
    }
}

static void cmd_listen(hook_manager_t *mgr, const char *args) {
    unsigned int ms = 1000;
    sscanf(args, "%u", &ms);

    char err[256];
    if (hook_poll(mgr, ms, err, sizeof(err)) != 0) printf("error: %s\n", err);
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

static bool dispatch(vmi_session_t *session, hook_manager_t *mgr, char *line) {
    char *cmd = strtok(line, " \t\r\n");
    if (!cmd) return true;
    char *args = strtok(NULL, "\r\n");
    if (!args) args = "";
    while (*args == ' ' || *args == '\t') args++;

    if (strcmp(cmd, "watch") == 0) cmd_watch(mgr, args);
    else if (strcmp(cmd, "bp") == 0) cmd_bp(mgr, args);
    else if (strcmp(cmd, "unhook") == 0) cmd_unhook(mgr, args);
    else if (strcmp(cmd, "list") == 0) cmd_list(mgr);
    else if (strcmp(cmd, "listen") == 0) cmd_listen(mgr, args);
    else if (strcmp(cmd, "pause") == 0) cmd_pause(session);
    else if (strcmp(cmd, "resume") == 0) cmd_resume(session);
    else if (strcmp(cmd, "help") == 0) print_help();
    else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) return false;
    else printf("unknown command '%s' (try 'help')\n", cmd);

    return true;
}

void hook_shell_run(vmi_session_t *session) {
    hook_manager_t mgr;
    hook_manager_init(&mgr, session);

    char line[LINE_MAX];
    while (vmi_is_attached(session)) {
        printf("hook(%s)> ", session->vm_name);
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            putchar('\n');
            break;
        }
        if (!dispatch(session, &mgr, line)) break;
    }

    hook_manager_clear(&mgr);
}
