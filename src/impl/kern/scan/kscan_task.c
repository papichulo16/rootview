#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "kscan_priv.h"

/* the task cross-view: five ways to reach a task_struct.
 *
 *   TASK_LIST  init_task.tasks, init_task included: thread group leaders
 *   PID_IDR    init_pid_ns.idr -> struct pid -> tasks[PIDTYPE_PID]: every
 *              task with a pid, threads included - what /proc lists
 *   RUNQUEUE   each cpu's rq->curr and rq->idle: whatever is running
 *   CHILDREN   task->children of every task found so far, to a fixed point
 *   THREADS    signal->thread_head of every task found so far, likewise
 *
 * the last two hang off what the first three found, so a task unlinked
 * from the list and the idr is still reached through its parent and its
 * thread group. */

#define PF_KTHREAD 0x00200000u
#define PIDTYPE_PID 0

typedef struct {
    uint64_t tasks, pid_links, children, sibling, thread_node, signal, thread_head;
    kfield_t pid, tgid, comm, real_parent, mm, cred, flags;
} toff_t;

static int resolve(const kwalk_t *w, toff_t *o, char *err, size_t err_len) {
    const btf_t *b = &w->kp->btf;
    kfield_t f;
    if (kscan_off(w, "task_struct", "tasks", &o->tasks, err, err_len) != 0 ||
        kscan_off(w, "task_struct", "children", &o->children, err, err_len) != 0 ||
        kscan_off(w, "task_struct", "sibling", &o->sibling, err, err_len) != 0 ||
        kscan_off(w, "task_struct", "thread_node", &o->thread_node, err, err_len) != 0 ||
        kscan_off(w, "task_struct", "signal", &o->signal, err, err_len) != 0 ||
        kscan_off(w, "signal_struct", "thread_head", &o->thread_head, err, err_len) != 0 ||
        kfield_resolve(b, "task_struct", "pid_links", &f, err, err_len) != 0 ||
        kfield_resolve(b, "task_struct", "pid", &o->pid, err, err_len) != 0 ||
        kfield_resolve(b, "task_struct", "tgid", &o->tgid, err, err_len) != 0 ||
        kfield_resolve(b, "task_struct", "comm", &o->comm, err, err_len) != 0 ||
        kfield_resolve(b, "task_struct", "real_parent", &o->real_parent, err, err_len) != 0 ||
        kfield_resolve(b, "task_struct", "mm", &o->mm, err, err_len) != 0 ||
        kfield_resolve(b, "task_struct", "cred", &o->cred, err, err_len) != 0 ||
        kfield_resolve(b, "task_struct", "flags", &o->flags, err, err_len) != 0)
        return -1;
    /* pid_links[PIDTYPE_PID] is the first element */
    o->pid_links = f.offset + PIDTYPE_PID * 16ull;
    return 0;
}

/* adds each of addrs[0, n) under src; -1 when the table is full */
static int add_all(kscan_result_t *r, const uint64_t *addrs, size_t n, unsigned src) {
    for (size_t i = 0; i < n; i++)
        if (!kscan_add(r, KSCAN_TASK, addrs[i], src, NULL)) return -1;
    return 0;
}

static void src_task_list(kwalk_t *w, kscan_result_t *r, const toff_t *o, uint64_t *buf) {
    char e[256];
    size_t n;
    uint64_t init = w->kp->init_task;
    if (kwalk_list_off(w, init + o->tasks, o->tasks, buf, KSCAN_WALK_MAX, &n, e, sizeof(e)) != 0) {
        kscan_source_failed(r, KSCAN_SRC_TASK_LIST, e);
        return;
    }
    /* the head is init_task's own link, so init_task is on the list too */
    if (!kscan_add(r, KSCAN_TASK, init, KSCAN_SRC_TASK_LIST, NULL) || add_all(r, buf, n, KSCAN_SRC_TASK_LIST) != 0) {
        kscan_source_failed(r, KSCAN_SRC_TASK_LIST, "too many objects");
        return;
    }
    kscan_source_ran(r, KSCAN_SRC_TASK_LIST);
}

static void src_pid_idr(kwalk_t *w, kscan_result_t *r, const toff_t *o, uint64_t *buf) {
    char e[256];
    uint64_t ns, off_idr, off_ptasks;
    if (kscan_sym(w, "init_pid_ns", &ns, e, sizeof(e)) != 0 ||
        kscan_off(w, "pid_namespace", "idr", &off_idr, e, sizeof(e)) != 0 ||
        kscan_off(w, "pid", "tasks", &off_ptasks, e, sizeof(e)) != 0) {
        kscan_source_failed(r, KSCAN_SRC_PID_IDR, e);
        return;
    }
    kwalk_idr_entry_t *ids = malloc(KSCAN_WALK_MAX * sizeof(*ids));
    size_t n;
    if (!ids) {
        kscan_source_failed(r, KSCAN_SRC_PID_IDR, "out of memory");
        return;
    }
    if (kwalk_idr(w, ns + off_idr, ids, KSCAN_WALK_MAX, &n, e, sizeof(e)) != 0) {
        kscan_source_failed(r, KSCAN_SRC_PID_IDR, e);
        free(ids);
        return;
    }
    for (size_t i = 0; i < n; i++) {
        /* a pid can be allocated with no task yet, or one being reaped:
         * an empty hlist is fine, a broken one fails the source */
        size_t m;
        uint64_t head = ids[i].ptr + off_ptasks + PIDTYPE_PID * 8ull;
        if (kwalk_hlist_off(w, head, o->pid_links, buf, 16, &m, e, sizeof(e)) != 0) {
            kscan_source_failf(r, KSCAN_SRC_PID_IDR, "pid %" PRIu64 ": %s", ids[i].id, e);
            free(ids);
            return;
        }
        if (add_all(r, buf, m, KSCAN_SRC_PID_IDR) != 0) {
            kscan_source_failed(r, KSCAN_SRC_PID_IDR, "too many objects");
            free(ids);
            return;
        }
    }
    free(ids);
    kscan_source_ran(r, KSCAN_SRC_PID_IDR);
}

static void src_runqueue(kwalk_t *w, kscan_result_t *r) {
    char e[256];
    unsigned nr;
    uint64_t off_curr, off_idle;
    if (kwalk_nr_cpus(w, &nr, e, sizeof(e)) != 0 || kscan_off(w, "rq", "curr", &off_curr, e, sizeof(e)) != 0 ||
        kscan_off(w, "rq", "idle", &off_idle, e, sizeof(e)) != 0) {
        kscan_source_failed(r, KSCAN_SRC_RUNQUEUE, e);
        return;
    }
    for (unsigned cpu = 0; cpu < nr; cpu++) {
        uint64_t rq, t[2];
        if (kwalk_percpu_addr(w, "runqueues", cpu, &rq, e, sizeof(e)) != 0 ||
            kscan_u64(w, rq + off_curr, &t[0], e, sizeof(e)) != 0 ||
            kscan_u64(w, rq + off_idle, &t[1], e, sizeof(e)) != 0) {
            kscan_source_failf(r, KSCAN_SRC_RUNQUEUE, "cpu %u: %s", cpu, e);
            return;
        }
        for (int k = 0; k < 2; k++) {
            /* a cpu that never came up has no idle task */
            if (!t[k]) continue;
            if (!kwalk_kernel_va(t[k])) {
                kscan_source_failf(r, KSCAN_SRC_RUNQUEUE, "cpu %u: rq->%s is 0x%016" PRIx64, cpu,
                                   k ? "idle" : "curr", t[k]);
                return;
            }
            if (!kscan_add(r, KSCAN_TASK, t[k], KSCAN_SRC_RUNQUEUE, NULL)) {
                kscan_source_failed(r, KSCAN_SRC_RUNQUEUE, "too many objects");
                return;
            }
        }
    }
    kscan_source_ran(r, KSCAN_SRC_RUNQUEUE);
}

/* CHILDREN and THREADS, over every task in the table including the ones
 * these two add, so a whole hidden subtree comes back from one visible
 * ancestor. each signal_struct's thread list is walked once. */
static void src_family(kwalk_t *w, kscan_result_t *r, const toff_t *o, uint64_t *buf) {
    char e[200];
    bool children_err = false, threads_err = false, full = false;
    kscan_set_t signals = {0};
    for (size_t i = 0; i < r->n && !full; i++) {
        uint64_t task = r->objs[i].addr, sig;
        size_t n;
        if (kwalk_list_off(w, task + o->children, o->sibling, buf, KSCAN_WALK_MAX, &n, e, sizeof(e)) != 0) {
            r->objs[i].flags |= KSCAN_TASK_BAD_CHILDREN;
            if (!children_err)
                snprintf(r->source_err[KSCAN_SRC_CHILDREN], sizeof(r->source_err[0]),
                         "task 0x%016" PRIx64 ": %s", task, e);
            children_err = true;
        } else if (add_all(r, buf, n, KSCAN_SRC_CHILDREN) != 0) {
            full = true;
            break;
        }

        if (kscan_u64(w, task + o->signal, &sig, e, sizeof(e)) != 0 || !kwalk_kernel_va(sig)) {
            if (!threads_err)
                snprintf(r->source_err[KSCAN_SRC_THREADS], sizeof(r->source_err[0]),
                         "task 0x%016" PRIx64 ": signal unreadable", task);
            r->objs[i].flags |= KSCAN_TASK_BAD_THREADS;
            threads_err = true;
            continue;
        }
        if (!kscan_set_add(&signals, sig)) continue;
        if (kwalk_list_off(w, sig + o->thread_head, o->thread_node, buf, KSCAN_WALK_MAX, &n, e, sizeof(e)) != 0) {
            r->objs[i].flags |= KSCAN_TASK_BAD_THREADS;
            if (!threads_err)
                snprintf(r->source_err[KSCAN_SRC_THREADS], sizeof(r->source_err[0]),
                         "task 0x%016" PRIx64 ": %s", task, e);
            threads_err = true;
        } else if (add_all(r, buf, n, KSCAN_SRC_THREADS) != 0) {
            full = true;
        }
    }
    kscan_set_free(&signals);
    if (full) {
        kscan_source_failed(r, KSCAN_SRC_CHILDREN, "too many objects");
        kscan_source_failed(r, KSCAN_SRC_THREADS, "too many objects");
        return;
    }
    kscan_source_ran(r, KSCAN_SRC_CHILDREN);
    kscan_source_ran(r, KSCAN_SRC_THREADS);
}

static void decode(kwalk_t *w, kscan_result_t *r, const toff_t *o) {
    for (size_t i = 0; i < r->n; i++) {
        kscan_object_t *t = &r->objs[i];
        int32_t pid = 0, tgid = 0;
        uint32_t flags = 0;
        char comm[16] = "";
        uint64_t parent = 0, mm = 0, cred = 0, signal = 0;
        kwalk_iov_t iov[] = {
            {t->addr + o->pid.offset, &pid, 4, 0},          {t->addr + o->tgid.offset, &tgid, 4, 0},
            {t->addr + o->flags.offset, &flags, 4, 0},      {t->addr + o->comm.offset, comm, sizeof(comm), 0},
            {t->addr + o->real_parent.offset, &parent, 8, 0}, {t->addr + o->mm.offset, &mm, 8, 0},
            {t->addr + o->cred.offset, &cred, 8, 0},        {t->addr + o->signal, &signal, 8, 0},
        };
        if (kwalk_read_many(w, iov, sizeof(iov) / sizeof(iov[0]), NULL, 0) != 0) {
            t->flags |= KSCAN_UNREADABLE;
            continue;
        }
        t->id = pid;
        kscan_name(t->name, sizeof(t->name), comm, sizeof(comm));
        t->u.task.tgid = tgid;
        t->u.task.parent = parent;
        t->u.task.mm = mm;
        t->u.task.cred = cred;
        t->u.task.signal = signal;
        t->u.task.pf_flags = flags;
        if (pid == tgid) t->flags |= KSCAN_TASK_LEADER;
        if (flags & PF_KTHREAD) t->flags |= KSCAN_TASK_KTHREAD;
        if (pid == 0) t->flags |= KSCAN_TASK_IDLE;
        if (!mm) t->flags |= KSCAN_TASK_NO_MM;
    }
}

int kscan_tasks(kwalk_t *w, kscan_result_t *r, char *err, size_t err_len) {
    toff_t o;
    if (resolve(w, &o, err, err_len) != 0) return -1;
    if (kscan_start(r, KSCAN_TASK, err, err_len) != 0) return -1;
    uint64_t *buf = malloc(KSCAN_WALK_MAX * sizeof(*buf));
    if (!buf) {
        kscan_free(r);
        FAIL("out of memory");
    }
    bool own;
    if (kscan_window_begin(w, &own, err, err_len) != 0) {
        free(buf);
        kscan_free(r);
        return -1;
    }
    src_task_list(w, r, &o, buf);
    src_pid_idr(w, r, &o, buf);
    src_runqueue(w, r);
    src_family(w, r, &o, buf);
    decode(w, r, &o);
    free(buf);
    int rc = kscan_window_end(w, own, 0, err, err_len);
    if (rc != 0) kscan_free(r);
    return rc;
}
