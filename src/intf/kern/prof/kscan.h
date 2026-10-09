#ifndef ROOTVIEW_KSCAN_H
#define ROOTVIEW_KSCAN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "kern/prof/kwalk.h"

/* cross-view scanning. a rootkit hides an object by editing one of the
 * structures the kernel enumerates it through - unlinking a task from the
 * task list, a module from the module list, a prog from prog_idr - but the
 * object itself still exists, and other structures still reach it. so each
 * scan enumerates one kind of object several independent ways (sources)
 * into one table keyed by the object's own address: two sources that reach
 * the same task_struct reach the same address, whatever ids a rootkit
 * reuses or skips. each source sets its bit on every object it finds.
 *
 * the result is the evidence, not the verdict: per object, which sources saw
 * it, plus which sources ran at all. what a missing bit means (a thread is
 * never on the task list; carving is additive) is the caller's rule, not
 * this code's. a source that fails leaves its bit out of ran_mask and its
 * reason in source_err, and the scan carries on with the others. */

typedef enum {
    KSCAN_TASK,
    KSCAN_MODULE,
    KSCAN_BPF_PROG,
    KSCAN_BPF_MAP,
} kscan_kind_t;

/* task sources */
enum {
    KSCAN_SRC_TASK_LIST = 0, /* init_task.tasks: group leaders only */
    KSCAN_SRC_PID_IDR = 1,   /* init_pid_ns.idr -> pid->tasks[PIDTYPE_PID]: what /proc lists */
    KSCAN_SRC_RUNQUEUE = 2,  /* each cpu's rq->curr and rq->idle */
    KSCAN_SRC_CHILDREN = 3,  /* task->children of every task found by any source */
    KSCAN_SRC_THREADS = 4,   /* signal->thread_head of every task found by any source */
};

/* module sources */
enum {
    KSCAN_SRC_MOD_LIST = 0,  /* the modules list */
    KSCAN_SRC_MOD_TREE = 1,  /* mod_tree's latch tree, by address */
    KSCAN_SRC_MOD_CARVE = 2, /* struct module signatures in the module mapping: additive only */
};

/* bpf sources: progs */
enum {
    KSCAN_SRC_PROG_IDR = 0,  /* prog_idr: what bpftool lists */
    KSCAN_SRC_BPF_KSYM = 1,  /* the bpf_kallsyms list: bpf_prog_<tag> in /proc/kallsyms */
    KSCAN_SRC_BPF_TREE = 2,  /* bpf_tree, the latch tree kallsyms lookups by address use */
    KSCAN_SRC_PROG_FUNC = 3, /* aux->func[] of a prog found by another source: its subprogs */
};

/* bpf sources: maps. numbered after the prog sources, since one result
 * holds both and shares ran_mask */
enum {
    KSCAN_SRC_MAP_IDR = 4,   /* map_idr */
    KSCAN_SRC_USED_MAPS = 5, /* aux->used_maps[] of every prog found */
};

#define KSCAN_SOURCES 8
#define KSCAN_NAME_MAX 64

/* any kind: the object's own fields couldn't be read, so only addr and
 * source_mask mean anything */
#define KSCAN_UNREADABLE (1u << 31)

/* task flags */
#define KSCAN_TASK_LEADER (1u << 0)  /* pid == tgid */
#define KSCAN_TASK_KTHREAD (1u << 1) /* PF_KTHREAD */
#define KSCAN_TASK_IDLE (1u << 2)    /* pid 0: init_task and the per-cpu idle tasks */
#define KSCAN_TASK_NO_MM (1u << 3)
/* its children / thread list didn't walk: CHILDREN and THREADS still ran,
 * but missed whatever hangs off this task. the walker's reason is in
 * source_err when it's the first such failure. */
#define KSCAN_TASK_BAD_CHILDREN (1u << 4)
#define KSCAN_TASK_BAD_THREADS (1u << 5)

/* module flags */
#define KSCAN_MOD_NO_TEXT_SYMS (1u << 0) /* has text, but none of its kallsyms fall in it */
#define KSCAN_MOD_BAD_KALLSYMS (1u << 1) /* mod->kallsyms unreadable or absurd */

/* prog flags */
#define KSCAN_PROG_JITED (1u << 0)
#define KSCAN_PROG_DYING (1u << 1) /* refcnt 0 or id 0: on its way out, not hidden */
#define KSCAN_PROG_SUBPROG (1u << 2) /* found in another prog's aux->func[] */

typedef struct {
    kscan_kind_t kind;
    uint64_t addr;  /* task_struct, module, bpf_prog, bpf_map */
    int64_t id;     /* pid, prog id, map id; -1 for a module */
    char name[KSCAN_NAME_MAX]; /* comm, module name, aux->name, map name */
    uint32_t source_mask;      /* bit n: source n found it */
    uint32_t flags;
    union {
        struct {
            int64_t tgid;
            uint64_t parent; /* real_parent */
            uint64_t mm, cred, signal;
            uint32_t pf_flags;
        } task;
        struct {
            uint32_t state; /* enum module_state, raw */
            uint64_t text_base, text_size;
            uint32_t nsyms, nsyms_in_text; /* mod->kallsyms: all, and those inside text */
        } module;
        struct {
            uint64_t aux;
            uint32_t type; /* enum bpf_prog_type, raw */
            uint8_t tag[8];
            uint32_t len;  /* instructions */
            uint64_t bpf_func;
            uint64_t ksym_start, ksym_end; /* aux->ksym: the jit image */
            uint32_t used_map_cnt, func_cnt;
            int64_t parent_id; /* SUBPROG: the id of the prog whose func[] holds it, else -1 */
        } prog;
        struct {
            uint32_t type; /* enum bpf_map_type, raw */
            int64_t user_id; /* PROG_USED_MAPS: the id of a prog using it, else -1 */
        } map;
    } u;
} kscan_object_t;

typedef struct {
    kscan_kind_t kind; /* KSCAN_BPF_PROG holds maps too */
    kscan_object_t *objs; /* in the order first found */
    size_t n, cap;
    uint32_t *hash; /* open addressing on (kind, addr): index + 1, 0 is empty */
    size_t hash_cap;

    uint32_t ran_mask;                    /* sources that completed */
    size_t source_count[KSCAN_SOURCES];   /* objects each source found, duplicates included */
    char source_err[KSCAN_SOURCES][256];  /* why a source didn't complete */
    bool bpf_jit_kallsyms;                /* BPF: whether the sysctl is on (progs only get ksyms when it is) */
} kscan_result_t;

#define KSCAN_MAX_OBJECTS (1u << 20)

void kscan_free(kscan_result_t *r);

/* the object at addr, or NULL */
const kscan_object_t *kscan_find(const kscan_result_t *r, kscan_kind_t kind, uint64_t addr);

const char *kscan_source_name(kscan_kind_t kind, unsigned src);

/* each scan runs inside one snapshot window - the caller's if one is open,
 * otherwise its own - so every source sees the same instant. -1 only when
 * nothing could run at all (the window, out of memory); a source failing on
 * its own is reported in the result. */
int kscan_tasks(kwalk_t *w, kscan_result_t *r, char *err, size_t err_len);
int kscan_modules(kwalk_t *w, kscan_result_t *r, char *err, size_t err_len);
int kscan_bpf(kwalk_t *w, kscan_result_t *r, char *err, size_t err_len);

#endif
