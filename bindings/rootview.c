#include "rootview.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hook/hook.h"
#include "kern/kfield.h"
#include "kern/kprof.h"
#include "kern/kwalk.h"
#include "vm/vm_config.h"
#include "vm/vm_state.h"
#include "vm/vm_store.h"
#include "vmi/vmi.h"
#include "vmi/vmi_reg_names.h"

#define API __attribute__((visibility("default")))

_Static_assert((int) RV_U == KF_U && (int) RV_S == KF_S && (int) RV_PTR == KF_PTR && (int) RV_BYTES == KF_BYTES &&
                   (int) RV_CSTR == KF_CSTR && (int) RV_ENUM == KF_ENUM,
               "rv_field kinds mirror kfield_kind_t");
_Static_assert((int) RV_HOOK_REGISTER == HOOK_KIND_REGISTER && (int) RV_HOOK_BREAKPOINT == HOOK_KIND_BREAKPOINT &&
                   (int) RV_HOOK_CPUID == HOOK_KIND_CPUID && (int) RV_HOOK_DESCRIPTOR == HOOK_KIND_DESCRIPTOR &&
                   (int) RV_HOOK_MEM == HOOK_KIND_MEM,
               "rv_event kinds mirror hook_kind_t");
_Static_assert(RV_NAME_MAX == VM_NAME_MAX && RV_NAME_MAX == HOOK_NAME_MAX, "rv names fit vm and hook names");
_Static_assert(RV_WINDOW == HOOK_MEM_WINDOW, "one capture window size");

/* rv_tasks' own cap on the task list */
#define TASKS_MAX 65536

struct rv_handle {
    vmi_session_t session;
    kprof_t kp;
    kwalk_t w; /* every read goes through it, so a snapshot window caches them all */
    hook_manager_t hooks;

    /* the hook event ring: events[(head + i) % RV_EVENTS_MAX] for i < count */
    rv_event_t events[RV_EVENTS_MAX];
    size_t head, count;
    uint64_t seq, dropped;
};

static void set_err(char *err, size_t err_len, const char *msg) {
    if (err && err_len) snprintf(err, err_len, "%s", msg);
}

API void rv_set_base(const char *dir) {
    vm_store_set_base(dir);
}

API int rv_vm_list(rv_vm_t *out, size_t max, size_t *n, char *err, size_t err_len) {
    (void) err, (void) err_len;
    char names[256][VM_NAME_MAX];
    int count = vm_store_list(names, 256);
    for (int i = 0; i < count && (size_t) i < max; i++) {
        vm_config_t cfg = {0};
        vm_runtime_state_t st = {0};
        vm_config_load(names[i], &cfg);
        vm_state_load(names[i], &st);
        bool alive = vm_state_is_alive(&st);
        out[i] = (rv_vm_t) {
            .running = alive, .kvmi = alive && st.kvmi_socket[0], .memory_mb = cfg.memory_mb, .cpus = cfg.cpus};
        memcpy(out[i].name, names[i], sizeof(out[i].name));
    }
    *n = (size_t) count;
    return 0;
}

API rv_handle_t *rv_init(const char *vm_name, char *err, size_t err_len) {
    rv_handle_t *h = calloc(1, sizeof(*h));
    if (!h) {
        set_err(err, err_len, "out of memory");
        return NULL;
    }
    if (vmi_attach(vm_name, &h->session, err, err_len) != 0) {
        free(h);
        return NULL;
    }
    if (kprof_init(&h->kp, &h->session, err, err_len) != 0) {
        vmi_detach(&h->session);
        free(h);
        return NULL;
    }
    kwalk_init(&h->w, &h->kp, 0);
    hook_manager_init(&h->hooks, &h->session);
    return h;
}

API void rv_close(rv_handle_t *h) {
    if (!h) return;
    hook_manager_clear(&h->hooks);
    if (h->w.in_window) kwalk_end(&h->w, NULL, 0);
    kwalk_free(&h->w);
    kprof_free(&h->kp);
    vmi_detach(&h->session);
    free(h);
}

API int rv_info(rv_handle_t *h, rv_info_t *out, char *err, size_t err_len) {
    (void) err, (void) err_len;
    const kprof_t *kp = &h->kp;
    *out = (rv_info_t) {.major = kp->major,
                        .minor = kp->minor,
                        .patch = kp->patch,
                        .image_start = kp->img_start,
                        .image_end = kp->img_end,
                        .nsyms = kp->ksym.n,
                        .btf_types = kp->btf.n,
                        .init_task = kp->init_task};
    snprintf(out->banner, sizeof(out->banner), "%s", kp->banner);
    snprintf(out->release, sizeof(out->release), "%s", kp->release);
    return 0;
}

API int rv_snapshot_begin(rv_handle_t *h, char *err, size_t err_len) {
    return kwalk_begin(&h->w, err, err_len);
}

API int rv_snapshot_end(rv_handle_t *h, char *err, size_t err_len) {
    return kwalk_end(&h->w, err, err_len);
}

API int rv_read(rv_handle_t *h, uint64_t va, void *buf, size_t len, char *err, size_t err_len) {
    return kwalk_read(&h->w, va, buf, len, err, err_len);
}

API int rv_sym(rv_handle_t *h, const char *name, uint64_t *addr, char *err, size_t err_len) {
    const ksym_t *s = ksym_by_name(&h->kp.ksym, name);
    if (!s) {
        if (err) snprintf(err, err_len, "no symbol %s", name);
        return -1;
    }
    *addr = s->addr;
    return 0;
}

API int rv_field(rv_handle_t *h, const char *type, const char *path, rv_field_t *out, char *err, size_t err_len) {
    kfield_t f;
    if (kfield_resolve(&h->kp.btf, type, path, &f, err, err_len) != 0) return -1;
    *out = (rv_field_t) {.offset = f.offset,
                         .size = f.size,
                         .bit_off = f.bit_off,
                         .bit_size = f.bit_size,
                         .kind = (int) f.kind,
                         .type = f.type,
                         .ref = f.ref};
    return 0;
}

API int rv_field_read(rv_handle_t *h, const char *type, const char *path, uint64_t base_va, rv_value_t *out,
                      char *err, size_t err_len) {
    kfield_t f;
    if (kfield_resolve(&h->kp.btf, type, path, &f, err, err_len) != 0) return -1;
    if (f.size > KWALK_MAX_STRUCT) {
        if (err) snprintf(err, err_len, "%s.%s is %u bytes", type, path, f.size);
        return -1;
    }
    unsigned char *buf = malloc(f.size ? f.size : 1);
    if (!buf) {
        set_err(err, err_len, "out of memory");
        return -1;
    }
    kval_t v;
    kfield_t at = f;
    at.offset = 0; /* decode against a base f.offset bytes before buf */
    int rc = kwalk_read(&h->w, base_va + f.offset, buf, f.size, err, err_len);
    if (rc == 0) rc = kfield_decode(&h->kp.btf, &at, buf, f.size, &v, err, err_len);
    free(buf);
    if (rc != 0) return -1;

    memset(out, 0, sizeof(*out));
    out->kind = (int) v.kind;
    out->u = v.u;
    out->s = v.s;
    if (v.enum_name) snprintf(out->enum_name, sizeof(out->enum_name), "%s", v.enum_name);
    if (v.bytes) {
        out->len = v.len;
        size_t keep = v.len < sizeof(out->bytes) ? v.len : sizeof(out->bytes);
        memcpy(out->bytes, v.bytes, keep);
        if (v.kind == KF_CSTR) out->bytes[keep < sizeof(out->bytes) ? keep : sizeof(out->bytes) - 1] = '\0';
    }
    kval_free(&v);
    return 0;
}

API int rv_tasks(rv_handle_t *h, rv_task_t *out, size_t max, size_t *n, char *err, size_t err_len) {
    const kprof_t *kp = &h->kp;
    *n = 0;
    kfield_t f_tasks, f_pid, f_tgid, f_comm;
    if (kfield_resolve(&kp->btf, "task_struct", "tasks", &f_tasks, err, err_len) != 0 ||
        kfield_resolve(&kp->btf, "task_struct", "pid", &f_pid, err, err_len) != 0 ||
        kfield_resolve(&kp->btf, "task_struct", "tgid", &f_tgid, err, err_len) != 0 ||
        kfield_resolve(&kp->btf, "task_struct", "comm", &f_comm, err, err_len) != 0)
        return -1;
    uint64_t *tasks = malloc(TASKS_MAX * sizeof(*tasks));
    if (!tasks) {
        set_err(err, err_len, "out of memory");
        return -1;
    }

    /* the list and every task from one pause window, unless the caller has one open */
    bool own = !h->w.in_window;
    if (own && kwalk_begin(&h->w, err, err_len) != 0) {
        free(tasks);
        return -1;
    }
    size_t count;
    int rc = kwalk_list(&h->w, kp->init_task + f_tasks.offset, "task_struct", "tasks", tasks, TASKS_MAX, &count, err,
                        err_len);
    for (size_t i = 0; rc == 0 && i < count && i < max; i++) {
        int32_t pid = 0, tgid = 0;
        char comm[RV_COMM_MAX + 1] = "";
        kwalk_iov_t iov[3] = {{tasks[i] + f_pid.offset, &pid, sizeof(pid), 0},
                              {tasks[i] + f_tgid.offset, &tgid, sizeof(tgid), 0},
                              {tasks[i] + f_comm.offset, comm, RV_COMM_MAX, 0}};
        if (kwalk_read_many(&h->w, iov, 3, err, err_len) != 0) rc = -1;
        out[i] = (rv_task_t) {.addr = tasks[i], .pid = pid, .tgid = tgid};
        memcpy(out[i].comm, comm, sizeof(out[i].comm));
    }
    if (rc == 0) *n = count;
    /* a resume failure only wins when the walk itself went fine */
    char rerr[256];
    if (own && kwalk_end(&h->w, rerr, sizeof(rerr)) != 0 && rc == 0) {
        set_err(err, err_len, rerr);
        rc = -1;
    }
    free(tasks);
    return rc;
}

API int rv_list(rv_handle_t *h, uint64_t head, const char *type, const char *member, uint64_t *out, size_t max,
                size_t *n, char *err, size_t err_len) {
    return kwalk_list(&h->w, head, type, member, out, max, n, err, err_len);
}

API int rv_hlist(rv_handle_t *h, uint64_t head, const char *type, const char *member, uint64_t *out, size_t max,
                 size_t *n, char *err, size_t err_len) {
    return kwalk_hlist(&h->w, head, type, member, out, max, n, err, err_len);
}

API int rv_nr_cpus(rv_handle_t *h, uint32_t *n, char *err, size_t err_len) {
    unsigned v;
    if (kwalk_nr_cpus(&h->w, &v, err, err_len) != 0) return -1;
    *n = v;
    return 0;
}

API int rv_percpu_addr(rv_handle_t *h, const char *sym, uint32_t cpu, uint64_t *addr, char *err, size_t err_len) {
    return kwalk_percpu_addr(&h->w, sym, cpu, addr, err, err_len);
}

_Static_assert(sizeof(rv_idr_entry_t) == sizeof(kwalk_idr_entry_t), "rv_idr_entry_t is kwalk_idr_entry_t");

API int rv_idr(rv_handle_t *h, uint64_t idr, rv_idr_entry_t *out, size_t max, size_t *n, char *err, size_t err_len) {
    return kwalk_idr(&h->w, idr, (kwalk_idr_entry_t *) out, max, n, err, err_len);
}

API int rv_list_off(rv_handle_t *h, uint64_t head, uint64_t off, uint64_t *out, size_t max, size_t *n, char *err,
                    size_t err_len) {
    return kwalk_list_off(&h->w, head, off, out, max, n, err, err_len);
}

API int rv_hlist_off(rv_handle_t *h, uint64_t head, uint64_t off, uint64_t *out, size_t max, size_t *n, char *err,
                     size_t err_len) {
    return kwalk_hlist_off(&h->w, head, off, out, max, n, err, err_len);
}

API int rv_rbtree(rv_handle_t *h, uint64_t root, uint64_t *out, size_t max, size_t *n, char *err, size_t err_len) {
    return kwalk_rbtree(&h->w, root, out, max, n, err, err_len);
}

/* ---- the raw guest ---- */

API int rv_reg(rv_handle_t *h, const char *name, uint64_t *value, char *err, size_t err_len) {
    reg_t reg;
    if (vmi_reg_lookup(name, &reg) != 0) {
        if (err) snprintf(err, err_len, "unknown register %s", name);
        return -1;
    }
    return vmi_read_reg(&h->session, reg, value, err, err_len);
}

API int rv_translate(rv_handle_t *h, uint64_t va, uint64_t *pa, char *err, size_t err_len) {
    return vmi_translate_virt(&h->session, va, pa, err, err_len);
}

API int rv_read_phys(rv_handle_t *h, uint64_t pa, void *buf, size_t len, char *err, size_t err_len) {
    return vmi_read_phys(&h->session, pa, buf, len, err, err_len);
}

/* ---- kallsyms and BTF ---- */

static void ksym_into(const ksym_t *s, rv_ksym_t *out) {
    *out = (rv_ksym_t) {.addr = s->addr, .type = s->type};
    snprintf(out->name, sizeof(out->name), "%s", s->name);
}

API int rv_sym_at(rv_handle_t *h, uint64_t va, rv_ksym_t *out, char *err, size_t err_len) {
    const kprof_t *kp = &h->kp;
    const ksym_t *s = va >= kp->img_start && va < kp->img_end ? ksym_by_addr(&kp->ksym, va, NULL) : NULL;
    if (!s) {
        if (err) snprintf(err, err_len, "0x%" PRIx64 " isn't inside the kernel image", va);
        return -1;
    }
    ksym_into(s, out);
    return 0;
}

API int rv_ksyms(rv_handle_t *h, size_t first, rv_ksym_t *out, size_t max, size_t *total, char *err,
                 size_t err_len) {
    (void) err, (void) err_len;
    const ksym_table_t *tab = &h->kp.ksym;
    for (size_t i = first; i < tab->n && i - first < max; i++) ksym_into(&tab->syms[i], &out[i - first]);
    *total = tab->n;
    return 0;
}

/* a type name as C spells it, or a bare name tried as each kind in turn */
static uint32_t find_type(const btf_t *b, const char *type) {
    static const struct {
        const char *prefix;
        btf_kind_t kind;
    } prefixed[] = {{"struct ", BTF_KIND_STRUCT}, {"union ", BTF_KIND_UNION}, {"enum ", BTF_KIND_ENUM}};
    static const btf_kind_t bare[] = {BTF_KIND_STRUCT, BTF_KIND_UNION, BTF_KIND_TYPEDEF, BTF_KIND_ENUM,
                                      BTF_KIND_ENUM64, BTF_KIND_INT};
    for (size_t i = 0; i < sizeof(prefixed) / sizeof(prefixed[0]); i++) {
        size_t l = strlen(prefixed[i].prefix);
        if (strncmp(type, prefixed[i].prefix, l) != 0) continue;
        uint32_t id = btf_find(b, type + l, prefixed[i].kind);
        if (!id && prefixed[i].kind == BTF_KIND_ENUM) id = btf_find(b, type + l, BTF_KIND_ENUM64);
        return id;
    }
    for (size_t i = 0; i < sizeof(bare) / sizeof(bare[0]); i++) {
        uint32_t id = btf_find(b, type, bare[i]);
        if (id) return id;
    }
    return 0;
}

API int rv_type_size(rv_handle_t *h, const char *type, uint64_t *size, char *err, size_t err_len) {
    uint32_t id = find_type(&h->kp.btf, type);
    int64_t sz = id ? btf_size(&h->kp.btf, id) : -1;
    if (sz < 0) {
        if (err) snprintf(err, err_len, id ? "%s has no size" : "no type %s in BTF", type);
        return -1;
    }
    *size = (uint64_t) sz;
    return 0;
}

API int rv_enum_value(rv_handle_t *h, const char *enum_type, const char *name, int64_t *value, char *err,
                      size_t err_len) {
    const btf_t *b = &h->kp.btf;
    if (enum_type && enum_type[0]) {
        char spelled[256];
        snprintf(spelled, sizeof(spelled), "enum %s", strncmp(enum_type, "enum ", 5) == 0 ? enum_type + 5 : enum_type);
        uint32_t id = find_type(b, spelled);
        if (!id) id = find_type(b, enum_type); /* a typedef of one */
        if (id && btf_enum_value(b, id, name, value) == 0) return 0;
        if (err) snprintf(err, err_len, id ? "%s has no enumerator %s" : "no enum %s in BTF", enum_type, name);
        return -1;
    }
    for (uint32_t id = 1; id < b->n; id++) {
        btf_type_t t;
        if (btf_type(b, id, &t) != 0 || (t.kind != BTF_KIND_ENUM && t.kind != BTF_KIND_ENUM64)) continue;
        if (btf_enum_value(b, id, name, value) == 0) return 0;
    }
    if (err) snprintf(err, err_len, "no enumerator %s in any enum", name);
    return -1;
}

API int rv_enum_name(rv_handle_t *h, const char *enum_type, int64_t value, char *out, size_t out_len, char *err,
                     size_t err_len) {
    const btf_t *b = &h->kp.btf;
    char spelled[256];
    snprintf(spelled, sizeof(spelled), "enum %s", strncmp(enum_type, "enum ", 5) == 0 ? enum_type + 5 : enum_type);
    uint32_t id = find_type(b, spelled);
    if (!id) id = find_type(b, enum_type);
    const char *name = id ? btf_enum_name(b, id, (uint64_t) value) : NULL;
    if (!name) {
        if (!id && err) snprintf(err, err_len, "no enum %s in BTF", enum_type);
        else if (err) snprintf(err, err_len, "%s has no enumerator with value %lld", enum_type, (long long) value);
        return -1;
    }
    snprintf(out, out_len, "%s", name);
    return 0;
}

/* ---- hooks and the event ring ---- */

static void name_into(const rv_handle_t *h, uint64_t addr, char *out, size_t out_len, uint64_t *off) {
    const kprof_t *kp = &h->kp;
    const ksym_t *s = addr >= kp->img_start && addr < kp->img_end ? ksym_by_addr(&kp->ksym, addr, off) : NULL;
    snprintf(out, out_len, "%s", s ? s->name : "");
    if (!s) *off = 0;
}

/* the next slot in the ring, overwriting the oldest when it's full */
static rv_event_t *ring_slot(rv_handle_t *h) {
    if (h->count == RV_EVENTS_MAX) {
        h->head = (h->head + 1) % RV_EVENTS_MAX;
        h->count--;
        h->dropped++;
    }
    return &h->events[(h->head + h->count++) % RV_EVENTS_MAX];
}

static rv_event_t *push(rv_handle_t *h, const hook_event_t *ev) {
    rv_event_t *e = ring_slot(h);
    *e = (rv_event_t) {.seq = h->seq++,
                       .kind = (int) ev->kind,
                       .vcpu = ev->vcpu_id,
                       .vaddr = ev->vaddr,
                       .old_value = ev->old_value,
                       .new_value = ev->new_value,
                       .cpuid_leaf = ev->cpuid_leaf,
                       .cpuid_subleaf = ev->cpuid_subleaf,
                       .descriptor = (int) ev->descriptor,
                       .desc_is_write = ev->desc_is_write,
                       .mem_gpa = ev->mem_gpa,
                       .mem_access = ev->mem_access,
                       .rip = ev->rip,
                       .captured = ev->mem_captured,
                       .after_ok = ev->mem_after_ok,
                       .window = ev->mem_window};
    snprintf(e->name, sizeof(e->name), "%s", ev->name ? ev->name : "");
    if (ev->kind == HOOK_KIND_MEM) name_into(h, ev->rip, e->rip_sym, sizeof(e->rip_sym), &e->rip_off);
    memcpy(e->before, ev->mem_before, sizeof(e->before));
    memcpy(e->after, ev->mem_after, sizeof(e->after));
    return e;
}

static void push_event(const hook_event_t *ev, void *user_data) {
    push(user_data, ev);
}


/* bp and mem walk the vcpu's page tables to place the hook: pause around
 * that, unless a snapshot window already has the vm paused */
static int pause_for_hook(rv_handle_t *h, char *err, size_t err_len) {
    return h->w.in_window ? 0 : vmi_pause(&h->session, err, err_len);
}

static int resume_after_hook(rv_handle_t *h, int rc, char *err, size_t err_len) {
    char rerr[256];
    if (!h->w.in_window && vmi_resume(&h->session, rerr, sizeof(rerr)) != 0 && rc == 0) {
        set_err(err, err_len, rerr);
        return -1;
    }
    return rc;
}

API int rv_hook_reg(rv_handle_t *h, const char *name, const char *reg, char *err, size_t err_len) {
    return hook_reg_add(&h->hooks, name, reg, push_event, h, err, err_len);
}

API int rv_hook_bp(rv_handle_t *h, const char *name, uint64_t va, char *err, size_t err_len) {
    if (pause_for_hook(h, err, err_len) != 0) return -1;
    return resume_after_hook(h, hook_bp_add(&h->hooks, name, va, push_event, h, err, err_len), err, err_len);
}

API int rv_hook_cpuid(rv_handle_t *h, const char *name, const char *leaf, char *err, size_t err_len) {
    return hook_cpuid_add(&h->hooks, name, leaf, push_event, h, err, err_len);
}

API int rv_hook_desc(rv_handle_t *h, const char *name, const char *table, char *err, size_t err_len) {
    return hook_desc_add(&h->hooks, name, table, push_event, h, err, err_len);
}

API int rv_hook_mem(rv_handle_t *h, const char *name, uint64_t va, const char *access, char *err, size_t err_len) {
    if (pause_for_hook(h, err, err_len) != 0) return -1;
    return resume_after_hook(h, hook_mem_add(&h->hooks, name, va, access, push_event, h, err, err_len), err,
                             err_len);
}

API int rv_hook_mem_gfn(rv_handle_t *h, const char *name, uint64_t gfn, const char *access, int capture, char *err,
                        size_t err_len) {
    return hook_mem_add_gfn(&h->hooks, name, gfn, access, capture != 0, push_event, h, err, err_len);
}

API int rv_hook_remove(rv_handle_t *h, const char *name, char *err, size_t err_len) {
    return hook_remove(&h->hooks, name, err, err_len);
}

API int rv_hook_poll(rv_handle_t *h, uint32_t timeout_ms, char *err, size_t err_len) {
    return hook_poll(&h->hooks, timeout_ms, err, err_len);
}


API int rv_events(rv_handle_t *h, rv_event_t *out, size_t max, size_t *n, uint64_t *dropped, char *err,
                  size_t err_len) {
    (void) err, (void) err_len;
    size_t take = h->count < max ? h->count : max;
    for (size_t i = 0; i < take; i++) out[i] = h->events[(h->head + i) % RV_EVENTS_MAX];
    h->head = (h->head + take) % RV_EVENTS_MAX;
    h->count -= take;
    *n = take;
    *dropped = h->dropped;
    h->dropped = 0;
    return 0;
}
