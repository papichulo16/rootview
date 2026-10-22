#ifndef ROOTVIEW_BIND_RV_HOOK_H
#define ROOTVIEW_BIND_RV_HOOK_H

#include "bind/rv.h"

#define RV_EVENTS_MAX 4096
#define RV_SYM_MAX 128
#define RV_WINDOW 16

enum { RV_HOOK_REGISTER, RV_HOOK_BREAKPOINT, RV_HOOK_CPUID, RV_HOOK_DESCRIPTOR, RV_HOOK_MEM };
enum { RV_DESC_IDTR = 1, RV_DESC_GDTR, RV_DESC_LDTR, RV_DESC_TR };
enum { RV_ACCESS_R = 1, RV_ACCESS_W = 2, RV_ACCESS_X = 4 };

typedef struct {
    char name[RV_NAME_MAX];
    int kind;
    char reg[32];
    uint64_t vaddr;
    uint32_t cpuid_leaf;
    int cpuid_any;
    int descriptor;
    uint64_t mem_gfn;
    uint32_t mem_access;
    int mem_capture;
} rv_hook_t;

typedef struct {
    uint64_t seq;
    int kind;
    char name[RV_NAME_MAX];
    uint32_t vcpu;
    uint64_t vaddr;
    uint64_t old_value, new_value;
    uint32_t cpuid_leaf, cpuid_subleaf;
    int descriptor, desc_is_write;
    uint64_t mem_gpa;
    uint32_t mem_access;
    uint64_t rip;
    char rip_sym[RV_SYM_MAX];
    uint64_t rip_off;

    int captured, after_ok;
    uint64_t window;
    uint8_t before[RV_WINDOW], after[RV_WINDOW];
} rv_event_t;

int rv_hook_reg(rv_handle_t *h, const char *name, const char *reg, char *err, size_t err_len);
int rv_hook_bp(rv_handle_t *h, const char *name, uint64_t va, char *err, size_t err_len);
int rv_hook_cpuid(rv_handle_t *h, const char *name, const char *leaf, char *err, size_t err_len);
int rv_hook_desc(rv_handle_t *h, const char *name, const char *table, char *err, size_t err_len);
int rv_hook_mem(rv_handle_t *h, const char *name, uint64_t va, const char *access, char *err, size_t err_len);
int rv_hook_mem_gfn(rv_handle_t *h, const char *name, uint64_t gfn, const char *access, int capture, char *err,
                    size_t err_len);
int rv_hook_remove(rv_handle_t *h, const char *name, char *err, size_t err_len);
int rv_hooks(rv_handle_t *h, rv_hook_t *out, size_t max, size_t *n, char *err, size_t err_len);

int rv_hook_poll(rv_handle_t *h, uint32_t timeout_ms, char *err, size_t err_len);
int rv_events(rv_handle_t *h, rv_event_t *out, size_t max, size_t *n, uint64_t *dropped, char *err, size_t err_len);

#endif
