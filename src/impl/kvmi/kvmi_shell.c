#include "kvmi/kvmi_shell.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "hook/hook.h"
#include "hook/hook_types.h"
#include "kern/prof/kfield.h"
#include "kern/prof/kprof.h"
#include "kern/prof/kprof_vmi.h"
#include "vmi/vmi.h"
#include "vmi/vmi_reg_names.h"

#define DUMP_MAX 4096
#define REG_NAME_MAX 32

static void print_help(void) {
    printf("introspection commands:\n"
           "  pause                       pause the vm\n"
           "  resume                      resume the vm\n"
           "  rp <paddr hex> <len>        read physical memory, hex dump\n"
           "  wp <paddr hex> <hex bytes>  write physical memory\n"
           "  rv <vaddr hex> <len>        read virtual memory (walks the current CR3)\n"
           "  wv <vaddr hex> <hex bytes>  write virtual memory (walks the current CR3)\n"
           "  reg <name>                  read a vcpu register (gp, control, debug, MSR, ...)\n"
           "  setreg <name> <value hex>   write a gp register (rax..r15, rip, rflags) -\n"
           "                              pause the vm first; this kvmi build has no wire\n"
           "                              command to write CR/DR/MSR registers. the write\n"
           "                              only lands on 'resume', 'reg' keeps showing the\n"
           "                              old value until then\n"
           "  regs                        dump the common registers\n"
           "\n"
           "kernel profile commands (prof pauses and resumes the vm):\n"
           "  prof                        build the kernel profile: root, kallsyms, BTF\n"
           "  tasks                       walk init_task.tasks: pid and comm of each process\n"
           "  field <type> <path> [vaddr hex]\n"
           "                              resolve a struct field (\"task_struct se.vruntime\")\n"
           "                              and, given the struct's address, read it\n"
           "\n"
           "hook commands:\n"
           "  watch <name> <cr0|cr3|cr4|msr_all>   hook writes to a register\n"
           "  bp <name> <vaddr hex>                plant a breakpoint hook\n"
           "  cpuidhook <name> <leaf hex | any>    hook cpuid execution\n"
           "  deschook <name> <idtr|gdtr|ldtr|tr>  hook a descriptor table load/store\n"
           "  memhook <name> <vaddr hex> <rwx>     hook r/w/x access to a page\n"
           "  unhook <name>                        remove a hook\n"
           "  list                                 list active hooks\n"
           "  listen [ms]                          poll for hook events (default 1000ms, 0 drains only)\n"
           "\n"
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
    if (!vmi_reg_write_supported(reg)) {
        printf("'%s' can't be written: this kvmi build only supports writing "
               "general-purpose registers (rax..r15, rip, rflags)\n", name);
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

static const char *desc_name(hook_desc_t d) {
    switch (d) {
        case HOOK_DESC_IDTR: return "idtr";
        case HOOK_DESC_GDTR: return "gdtr";
        case HOOK_DESC_LDTR: return "ldtr";
        case HOOK_DESC_TR:   return "tr";
    }
    return "?";
}

/* not re-entrant - fine here since callbacks fire synchronously off the
 * single-threaded shell loop and the result is used before the next call. */
static const char *mem_access_str(uint8_t access) {
    static char buf[4];
    int i = 0;
    if (access & VMI_MEMACCESS_R) buf[i++] = 'r';
    if (access & VMI_MEMACCESS_W) buf[i++] = 'w';
    if (access & VMI_MEMACCESS_X) buf[i++] = 'x';
    buf[i] = '\0';
    return buf;
}

static void on_hook_event(const hook_event_t *ev, void *user_data) {
    (void) user_data;
    switch (ev->kind) {
        case HOOK_KIND_REGISTER:
            printf("[hook] %-16s vcpu=%u write 0x%016" PRIx64 " -> 0x%016" PRIx64 "\n", ev->name, ev->vcpu_id,
                   ev->old_value, ev->new_value);
            break;
        case HOOK_KIND_BREAKPOINT:
            printf("[hook] %-16s vcpu=%u hit at 0x%016" PRIx64 "\n", ev->name, ev->vcpu_id, ev->vaddr);
            break;
        case HOOK_KIND_CPUID:
            printf("[hook] %-16s vcpu=%u cpuid leaf=0x%08" PRIx32 " subleaf=0x%08" PRIx32 "\n", ev->name,
                   ev->vcpu_id, ev->cpuid_leaf, ev->cpuid_subleaf);
            break;
        case HOOK_KIND_DESCRIPTOR:
            printf("[hook] %-16s vcpu=%u %s %s\n", ev->name, ev->vcpu_id, desc_name(ev->descriptor),
                   ev->desc_is_write ? "write" : "read");
            break;
        case HOOK_KIND_MEM:
            printf("[hook] %-16s vcpu=%u mem %s @ 0x%016" PRIx64 "\n", ev->name, ev->vcpu_id,
                   mem_access_str(ev->mem_access), ev->mem_gpa);
            break;
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

static void cmd_cpuidhook(hook_manager_t *mgr, const char *args) {
    char name[HOOK_NAME_MAX], leaf[32];
    if (sscanf(args, "%63s %31s", name, leaf) != 2) {
        printf("usage: cpuidhook <name> <leaf hex | any>\n");
        return;
    }

    char err[256];
    if (hook_cpuid_add(mgr, name, leaf, on_hook_event, NULL, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    printf("watching cpuid leaf '%s' as '%s'\n", leaf, name);
}

static void cmd_deschook(hook_manager_t *mgr, const char *args) {
    char name[HOOK_NAME_MAX], table[16];
    if (sscanf(args, "%63s %15s", name, table) != 2) {
        printf("usage: deschook <name> <idtr|gdtr|ldtr|tr>\n");
        return;
    }

    char err[256];
    if (hook_desc_add(mgr, name, table, on_hook_event, NULL, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    printf("watching %s as '%s'\n", table, name);
}

static void cmd_memhook(hook_manager_t *mgr, const char *args) {
    char name[HOOK_NAME_MAX], access[8];
    uint64_t vaddr;
    if (sscanf(args, "%63s %" SCNx64 " %7s", name, &vaddr, access) != 3) {
        printf("usage: memhook <name> <vaddr hex> <r|w|x combination>\n");
        return;
    }

    char err[256];
    if (hook_mem_add(mgr, name, vaddr, access, on_hook_event, NULL, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    printf("watching '%s' (%s) at 0x%" PRIx64 "\n", name, access, vaddr);
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
        switch (h->kind) {
            case HOOK_KIND_REGISTER:
                printf("  %-16s register\n", h->name);
                break;
            case HOOK_KIND_BREAKPOINT:
                printf("  %-16s breakpoint @ 0x%016" PRIx64 "\n", h->name, h->vaddr);
                break;
            case HOOK_KIND_CPUID:
                if (h->cpuid_leaf == HOOK_CPUID_ANY_LEAF) printf("  %-16s cpuid (any leaf)\n", h->name);
                else printf("  %-16s cpuid leaf=0x%08" PRIx32 "\n", h->name, h->cpuid_leaf);
                break;
            case HOOK_KIND_DESCRIPTOR:
                printf("  %-16s descriptor %s\n", h->name, desc_name(h->descriptor));
                break;
            case HOOK_KIND_MEM:
                printf("  %-16s mem %s @ gfn 0x%016" PRIx64 "\n", h->name, mem_access_str(h->mem_access),
                       h->mem_gfn);
                break;
        }
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

typedef struct {
    kprof_target_t target;
    kprof_t kp;
    bool ready;
} prof_state_t;

static void cmd_prof(vmi_session_t *session, prof_state_t *ps) {
    if (ps->ready) kprof_free(&ps->kp);
    ps->ready = false;
    kprof_vmi_target(session, &ps->target);

    char err[512];
    if (kprof_init(&ps->kp, &ps->target, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    ps->ready = true;
    kprof_t *kp = &ps->kp;
    printf("%s\n", kp->banner);
    printf("  release      %s (%u.%u.%u)\n", kp->release, kp->major, kp->minor, kp->patch);
    printf("  image        0x%016" PRIx64 "-0x%016" PRIx64 "\n", kp->img.start, kp->img.end);
    printf("  vcpu root    0x%" PRIx64 " (cr3 0x%" PRIx64 ")\n", kp->vcpu_root.pgd, kp->regs.cr3);
    printf("  init_top_pgt 0x%" PRIx64 "\n", kp->root.pgd);
    printf("  kallsyms     %zu symbols\n", kp->ksym.n);
    printf("  btf          %u types at 0x%016" PRIx64 " (%s)\n", kp->btf.n, kp->btf.va,
           kp->btf.by_symbol ? "__start_BTF" : "scan");
    printf("  init_task    0x%016" PRIx64 " (comm swapper/0)\n", kp->init_task);
}

static void cmd_tasks(prof_state_t *ps) {
    if (!ps->ready) {
        printf("error: run 'prof' first\n");
        return;
    }
    const kprof_t *kp = &ps->kp;
    char err[256];
    kfield_t f_next, f_pid, f_comm;
    if (kfield_resolve(&kp->btf, "task_struct", "tasks.next", &f_next, err, sizeof(err)) != 0 ||
        kfield_resolve(&kp->btf, "task_struct", "pid", &f_pid, err, sizeof(err)) != 0 ||
        kfield_resolve(&kp->btf, "task_struct", "comm", &f_comm, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    /* the fields sit near each other; one read spans them */
    uint64_t lo = f_next.offset, hi = f_next.offset + f_next.size;
    const kfield_t *fs[] = {&f_pid, &f_comm};
    for (size_t i = 0; i < 2; i++) {
        if (fs[i]->offset < lo) lo = fs[i]->offset;
        if (fs[i]->offset + fs[i]->size > hi) hi = fs[i]->offset + fs[i]->size;
    }
    unsigned char buf[DUMP_MAX];
    if (hi - lo > sizeof(buf)) {
        printf("error: task_struct fields span %" PRIu64 " bytes\n", hi - lo);
        return;
    }
    kfield_t rel[3] = {f_next, f_pid, f_comm};
    for (size_t i = 0; i < 3; i++) rel[i].offset -= lo;

    if (kprof_pause(kp, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    printf("%7s  %s\n", "PID", "COMM");
    uint64_t task = kp->init_task;
    size_t n = 0;
    for (; n < 1000000; n++) {
        kval_t next, pid, comm;
        if (kprof_read(kp, task + lo, buf, hi - lo, err, sizeof(err)) != 0) {
            printf("error: task 0x%016" PRIx64 ": %s\n", task, err);
            break;
        }
        kfield_decode(&kp->btf, &rel[0], buf, hi - lo, &next, NULL, 0);
        if (task != kp->init_task) {
            kfield_decode(&kp->btf, &rel[1], buf, hi - lo, &pid, NULL, 0);
            kfield_decode(&kp->btf, &rel[2], buf, hi - lo, &comm, NULL, 0);
            printf("%7" PRId64 "  %s\n", pid.s, (const char *) comm.bytes);
            kval_free(&comm);
        }
        task = next.u - f_next.offset;
        if (task == kp->init_task) break;
    }
    if (kprof_resume(kp, err, sizeof(err)) != 0) printf("error: %s\n", err);
}

static void cmd_field(prof_state_t *ps, const char *args) {
    char type[128], path[256];
    uint64_t va = 0;
    int n = sscanf(args, "%127s %255s %" SCNx64, type, path, &va);
    if (n < 2) {
        printf("usage: field <type> <path> [vaddr hex]\n");
        return;
    }
    if (!ps->ready) {
        printf("error: run 'prof' first\n");
        return;
    }
    const kprof_t *kp = &ps->kp;
    kfield_t f;
    char err[512];
    if (kfield_resolve(&kp->btf, type, path, &f, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    btf_type_t t, r;
    btf_type(&kp->btf, f.type, &t);
    printf("%s.%s: +0x%" PRIx64 " size %u, %s, type %u (%s %s)", type, path, f.offset, f.size,
           kfield_kind_name(f.kind), f.type, btf_kind_name(t.kind), t.name[0] ? t.name : "<anon>");
    if (f.bit_size) printf(", bits %u..%u", f.bit_off, f.bit_off + f.bit_size - 1);
    if (f.ref && btf_type(&kp->btf, f.ref, &r) == 0) printf(", -> %s %s", btf_kind_name(r.kind), r.name);
    putchar('\n');
    if (n < 3) return;

    kval_t v;
    if (kfield_read(kp, &f, va, &v, err, sizeof(err)) != 0) {
        printf("error: %s\n", err);
        return;
    }
    switch (v.kind) {
    case KF_U: printf("= %" PRIu64 " (0x%" PRIx64 ")\n", v.u, v.u); break;
    case KF_S: printf("= %" PRId64 "\n", v.s); break;
    case KF_PTR: printf("= 0x%016" PRIx64 "\n", v.u); break;
    case KF_ENUM: printf("= %" PRId64 " (%s)\n", v.s, v.enum_name ? v.enum_name : "?"); break;
    case KF_CSTR: printf("= \"%s\"\n", (const char *) v.bytes); break;
    case KF_BYTES: hex_dump(va + f.offset, v.bytes, v.len > DUMP_MAX ? DUMP_MAX : v.len); break;
    }
    kval_free(&v);
}

static bool dispatch(vmi_session_t *session, hook_manager_t *mgr, prof_state_t *ps, char *line) {
    char *cmd = strtok(line, " \t\r\n");
    if (!cmd) return true;
    char *args = strtok(NULL, "\r\n");
    if (!args) args = "";
    while (*args == ' ' || *args == '\t') args++;

    /* introspection commands */
    if (strcmp(cmd, "rp") == 0) cmd_read_phys(session, args);
    else if (strcmp(cmd, "wp") == 0) cmd_write_phys(session, args);
    else if (strcmp(cmd, "rv") == 0) cmd_read_virt(session, args);
    else if (strcmp(cmd, "wv") == 0) cmd_write_virt(session, args);
    else if (strcmp(cmd, "reg") == 0) cmd_read_reg(session, args);
    else if (strcmp(cmd, "setreg") == 0) cmd_write_reg(session, args);
    else if (strcmp(cmd, "regs") == 0) cmd_dump_regs(session);
    /* kernel profile commands */
    else if (strcmp(cmd, "prof") == 0) cmd_prof(session, ps);
    else if (strcmp(cmd, "tasks") == 0) cmd_tasks(ps);
    else if (strcmp(cmd, "field") == 0) cmd_field(ps, args);
    /* hook commands */
    else if (strcmp(cmd, "watch") == 0) cmd_watch(mgr, args);
    else if (strcmp(cmd, "bp") == 0) cmd_bp(mgr, args);
    else if (strcmp(cmd, "cpuidhook") == 0) cmd_cpuidhook(mgr, args);
    else if (strcmp(cmd, "deschook") == 0) cmd_deschook(mgr, args);
    else if (strcmp(cmd, "memhook") == 0) cmd_memhook(mgr, args);
    else if (strcmp(cmd, "unhook") == 0) cmd_unhook(mgr, args);
    else if (strcmp(cmd, "list") == 0) cmd_list(mgr);
    else if (strcmp(cmd, "listen") == 0) cmd_listen(mgr, args);
    /* shared */
    else if (strcmp(cmd, "pause") == 0) cmd_pause(session);
    else if (strcmp(cmd, "resume") == 0) cmd_resume(session);
    else if (strcmp(cmd, "help") == 0) print_help();
    else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) return false;
    else printf("unknown command '%s' (try 'help')\n", cmd);

    return true;
}

void kvmi_shell_run(vmi_session_t *session) {
    hook_manager_t mgr;
    hook_manager_init(&mgr, session);
    prof_state_t ps = {0};

    char line[DUMP_MAX * 2 + 64];
    while (vmi_is_attached(session)) {
        printf("kvmi(%s)> ", session->vm_name);
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            putchar('\n');
            break;
        }
        if (!dispatch(session, &mgr, &ps, line)) break;
    }

    if (ps.ready) kprof_free(&ps.kp);
    hook_manager_clear(&mgr);
}
