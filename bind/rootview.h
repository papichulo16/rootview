#ifndef ROOTVIEW_BIND_H
#define ROOTVIEW_BIND_H

#include <stddef.h>
#include <stdint.h>

/* the flat api librootview.so exports, for ctypes and anything else that
 * can't see the internal headers. one opaque handle per attached vm, plain
 * fixed-size structs filled through out-params, and every fallible call
 * returns 0 or -1 with the reason in err. nothing here is thread-safe: a
 * caller sharing a handle across threads serializes its calls.
 *
 * calls that fill an array take max and set *n to the full count, which can
 * exceed max; only the first max are written. */

#define RV_ERR_MAX 512
#define RV_NAME_MAX 64
#define RV_COMM_MAX 16
#define RV_EVENTS_MAX 4096 /* the hook event ring */

typedef struct rv_handle rv_handle_t;

typedef struct {
    char name[RV_NAME_MAX];
    int running; /* the qemu pid is alive */
    int kvmi;    /* it was started with a kvmi socket */
    int memory_mb;
    int cpus;
} rv_vm_t;

typedef struct {
    char banner[512];
    char release[65];
    uint32_t major, minor, patch;
    uint64_t image_start, image_end;
    uint64_t root_pgd; /* init_top_pgt */
    uint64_t nsyms;    /* kallsyms */
    uint32_t btf_types;
    uint64_t init_task;
} rv_info_t;

typedef struct {
    uint64_t addr; /* the task_struct */
    int64_t pid;
    int64_t tgid;
    char comm[RV_COMM_MAX + 1];
} rv_task_t;

/* rv_field's kind, mirroring kfield_kind_t */
enum { RV_U, RV_S, RV_PTR, RV_BYTES, RV_CSTR, RV_ENUM };

typedef struct {
    uint64_t offset;
    uint32_t size;
    uint32_t bit_off, bit_size;
    int kind;
    uint32_t type, ref; /* btf ids */
} rv_field_t;

typedef struct {
    int kind;
    uint64_t u;
    int64_t s;
    char enum_name[64];
    size_t len;               /* BYTES and CSTR: the full length */
    unsigned char bytes[256]; /* the first sizeof(bytes) of it; CSTR NUL-terminated */
} rv_value_t;

typedef struct {
    uint64_t id;
    uint64_t ptr;
} rv_idr_entry_t;

/* rv_event_t's kind, mirroring hook_kind_t */
enum { RV_HOOK_REGISTER, RV_HOOK_BREAKPOINT, RV_HOOK_CPUID, RV_HOOK_DESCRIPTOR, RV_HOOK_MEM };

typedef struct {
    uint64_t seq; /* counts every event pushed, dropped ones included */
    int kind;
    char name[RV_NAME_MAX];
    uint32_t vcpu;
    uint64_t vaddr;                /* BREAKPOINT */
    uint64_t old_value, new_value; /* REGISTER */
    uint32_t cpuid_leaf, cpuid_subleaf;
    int descriptor, desc_is_write; /* DESCRIPTOR: libvmi's VMI_DESCRIPTOR_* */
    uint64_t mem_gpa;              /* MEM */
    uint32_t mem_access;           /* MEM: VMI_MEMACCESS_* bits that fired */
} rv_event_t;

/* where the vm store lives: <dir>/.rootview/vms. defaults to the cwd. */
void rv_set_base(const char *dir);

int rv_vm_list(rv_vm_t *out, size_t max, size_t *n, char *err, size_t err_len);

/* attaches to a running kvmi vm and builds its kernel profile, which pauses
 * the vm for the duration. NULL on failure. */
rv_handle_t *rv_init(const char *vm_name, char *err, size_t err_len);
/* removes every hook, ends an open snapshot window and detaches */
void rv_close(rv_handle_t *h);

int rv_info(rv_handle_t *h, rv_info_t *out, char *err, size_t err_len);

/* a snapshot window: begin pauses the vm and starts a page cache that every
 * read below goes through, end drops it and resumes. reads outside a
 * window go straight to the guest, and rv_tasks opens its own window. */
int rv_snapshot_begin(rv_handle_t *h, char *err, size_t err_len);
int rv_snapshot_end(rv_handle_t *h, char *err, size_t err_len);

/* kernel virtual memory through the profile's root */
int rv_read(rv_handle_t *h, uint64_t va, void *buf, size_t len, char *err, size_t err_len);
int rv_sym(rv_handle_t *h, const char *name, uint64_t *addr, char *err, size_t err_len);

int rv_field(rv_handle_t *h, const char *type, const char *path, rv_field_t *out, char *err, size_t err_len);
int rv_field_read(rv_handle_t *h, const char *type, const char *path, uint64_t base_va, rv_value_t *out, char *err,
                  size_t err_len);

/* every process but swapper: init_task.tasks, bounded like rv_list */
int rv_tasks(rv_handle_t *h, rv_task_t *out, size_t max, size_t *n, char *err, size_t err_len);

/* kwalk_list and kwalk_hlist: container addresses. unlike the others, more
 * than max nodes is an error here - it's the walker's node cap. */
int rv_list(rv_handle_t *h, uint64_t head, const char *type, const char *member, uint64_t *out, size_t max, size_t *n,
            char *err, size_t err_len);
int rv_hlist(rv_handle_t *h, uint64_t head, const char *type, const char *member, uint64_t *out, size_t max,
             size_t *n, char *err, size_t err_len);

int rv_nr_cpus(rv_handle_t *h, uint32_t *n, char *err, size_t err_len);
int rv_percpu_addr(rv_handle_t *h, const char *sym, uint32_t cpu, uint64_t *addr, char *err, size_t err_len);

/* (id, pointer) pairs of the struct idr at idr, e.g. rv_sym("prog_idr") */
int rv_idr(rv_handle_t *h, uint64_t idr, rv_idr_entry_t *out, size_t max, size_t *n, char *err, size_t err_len);

/* hooks: each pushes its events into the handle's ring, which rv_hook_poll
 * fills and rv_events drains, oldest first: up to max per call, *n how
 * many it took, the rest left for the next. the ring keeps the newest
 * RV_EVENTS_MAX; *dropped counts the ones overwritten since the last drain. bp and mem
 * pause the vm around the address walk unless a snapshot is open. */
int rv_hook_reg(rv_handle_t *h, const char *name, const char *reg, char *err, size_t err_len);
int rv_hook_bp(rv_handle_t *h, const char *name, uint64_t va, char *err, size_t err_len);
int rv_hook_cpuid(rv_handle_t *h, const char *name, const char *leaf, char *err, size_t err_len);
int rv_hook_desc(rv_handle_t *h, const char *name, const char *table, char *err, size_t err_len);
int rv_hook_mem(rv_handle_t *h, const char *name, uint64_t va, const char *access, char *err, size_t err_len);
int rv_hook_remove(rv_handle_t *h, const char *name, char *err, size_t err_len);
int rv_hook_poll(rv_handle_t *h, uint32_t timeout_ms, char *err, size_t err_len);
int rv_events(rv_handle_t *h, rv_event_t *out, size_t max, size_t *n, uint64_t *dropped, char *err, size_t err_len);

#endif
