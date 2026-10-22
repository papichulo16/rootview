#include "rv_priv.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kern/kfield.h"

_Static_assert((int) RV_U == KF_U && (int) RV_S == KF_S && (int) RV_PTR == KF_PTR && (int) RV_BYTES == KF_BYTES &&
                   (int) RV_CSTR == KF_CSTR && (int) RV_ENUM == KF_ENUM,
               "rv_field kinds mirror kfield_kind_t");
_Static_assert(sizeof(rv_idr_entry_t) == sizeof(kwalk_idr_entry_t), "rv_idr_entry_t is kwalk_idr_entry_t");

#define TASKS_MAX 65536

API int rv_info(rv_handle_t *h, rv_info_t *out, char *err, size_t err_len) {
    if (rv_need_prof(h, err, err_len) != 0) return -1;
    const kprof_t *kp = &h->kp;
    *out = (rv_info_t) {.major = kp->major,
                        .minor = kp->minor,
                        .patch = kp->patch,
                        .image_start = kp->img_start,
                        .image_end = kp->img_end,
                        .nsyms = kp->ksym.n,
                        .btf_types = kp->btf.n,
                        .init_task = kp->init_task,
                        .btf_va = kp->btf.va,
                        .btf_by_symbol = kp->btf.by_symbol};
    snprintf(out->banner, sizeof(out->banner), "%s", kp->banner);
    snprintf(out->release, sizeof(out->release), "%s", kp->release);
    return 0;
}

API int rv_snapshot_begin(rv_handle_t *h, char *err, size_t err_len) {
    if (rv_need_prof(h, err, err_len) != 0) return -1;
    return kwalk_begin(&h->w, err, err_len);
}

API int rv_snapshot_end(rv_handle_t *h, char *err, size_t err_len) {
    if (rv_need_prof(h, err, err_len) != 0) return -1;
    return kwalk_end(&h->w, err, err_len);
}

API int rv_read(rv_handle_t *h, uint64_t va, void *buf, size_t len, char *err, size_t err_len) {
    if (rv_need_prof(h, err, err_len) != 0) return -1;
    return kwalk_read(&h->w, va, buf, len, err, err_len);
}

API int rv_sym(rv_handle_t *h, const char *name, uint64_t *addr, char *err, size_t err_len) {
    if (rv_need_prof(h, err, err_len) != 0) return -1;
    const ksym_t *s = ksym_by_name(&h->kp.ksym, name);
    if (!s) {
        if (err) snprintf(err, err_len, "no symbol %s", name);
        return -1;
    }
    *addr = s->addr;
    return 0;
}

API int rv_field(rv_handle_t *h, const char *type, const char *path, rv_field_t *out, char *err, size_t err_len) {
    if (rv_need_prof(h, err, err_len) != 0) return -1;
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
    if (rv_need_prof(h, err, err_len) != 0) return -1;
    kfield_t f;
    if (kfield_resolve(&h->kp.btf, type, path, &f, err, err_len) != 0) return -1;
    if (f.size > KWALK_MAX_STRUCT) {
        if (err) snprintf(err, err_len, "%s.%s is %u bytes", type, path, f.size);
        return -1;
    }
    unsigned char *buf = malloc(f.size ? f.size : 1);
    if (!buf) {
        rv_set_err(err, err_len, "out of memory");
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
    if (rv_need_prof(h, err, err_len) != 0) return -1;
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
        rv_set_err(err, err_len, "out of memory");
        return -1;
    }

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
    char rerr[256];
    if (own && kwalk_end(&h->w, rerr, sizeof(rerr)) != 0 && rc == 0) {
        rv_set_err(err, err_len, rerr);
        rc = -1;
    }
    free(tasks);
    return rc;
}

API int rv_list(rv_handle_t *h, uint64_t head, const char *type, const char *member, uint64_t *out, size_t max,
                size_t *n, char *err, size_t err_len) {
    if (rv_need_prof(h, err, err_len) != 0) return -1;
    return kwalk_list(&h->w, head, type, member, out, max, n, err, err_len);
}

API int rv_hlist(rv_handle_t *h, uint64_t head, const char *type, const char *member, uint64_t *out, size_t max,
                 size_t *n, char *err, size_t err_len) {
    if (rv_need_prof(h, err, err_len) != 0) return -1;
    return kwalk_hlist(&h->w, head, type, member, out, max, n, err, err_len);
}

API int rv_nr_cpus(rv_handle_t *h, uint32_t *n, char *err, size_t err_len) {
    if (rv_need_prof(h, err, err_len) != 0) return -1;
    unsigned v;
    if (kwalk_nr_cpus(&h->w, &v, err, err_len) != 0) return -1;
    *n = v;
    return 0;
}

API int rv_percpu_addr(rv_handle_t *h, const char *sym, uint32_t cpu, uint64_t *addr, char *err, size_t err_len) {
    if (rv_need_prof(h, err, err_len) != 0) return -1;
    return kwalk_percpu_addr(&h->w, sym, cpu, addr, err, err_len);
}

API int rv_idr(rv_handle_t *h, uint64_t idr, rv_idr_entry_t *out, size_t max, size_t *n, char *err, size_t err_len) {
    if (rv_need_prof(h, err, err_len) != 0) return -1;
    return kwalk_idr(&h->w, idr, (kwalk_idr_entry_t *) out, max, n, err, err_len);
}

API int rv_list_off(rv_handle_t *h, uint64_t head, uint64_t off, uint64_t *out, size_t max, size_t *n, char *err,
                    size_t err_len) {
    if (rv_need_prof(h, err, err_len) != 0) return -1;
    return kwalk_list_off(&h->w, head, off, out, max, n, err, err_len);
}

API int rv_hlist_off(rv_handle_t *h, uint64_t head, uint64_t off, uint64_t *out, size_t max, size_t *n, char *err,
                     size_t err_len) {
    if (rv_need_prof(h, err, err_len) != 0) return -1;
    return kwalk_hlist_off(&h->w, head, off, out, max, n, err, err_len);
}

API int rv_rbtree(rv_handle_t *h, uint64_t root, uint64_t *out, size_t max, size_t *n, char *err, size_t err_len) {
    if (rv_need_prof(h, err, err_len) != 0) return -1;
    return kwalk_rbtree(&h->w, root, out, max, n, err, err_len);
}

static void ksym_into(const ksym_t *s, rv_ksym_t *out) {
    *out = (rv_ksym_t) {.addr = s->addr, .type = s->type};
    snprintf(out->name, sizeof(out->name), "%s", s->name);
}

API int rv_sym_at(rv_handle_t *h, uint64_t va, rv_ksym_t *out, char *err, size_t err_len) {
    if (rv_need_prof(h, err, err_len) != 0) return -1;
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
    if (rv_need_prof(h, err, err_len) != 0) return -1;
    const ksym_table_t *tab = &h->kp.ksym;
    for (size_t i = first; i < tab->n && i - first < max; i++) ksym_into(&tab->syms[i], &out[i - first]);
    *total = tab->n;
    return 0;
}

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

API int rv_type(rv_handle_t *h, uint32_t id, rv_type_t *out, char *err, size_t err_len) {
    if (rv_need_prof(h, err, err_len) != 0) return -1;
    btf_type_t t;
    if (btf_type(&h->kp.btf, id, &t) != 0) {
        if (err) snprintf(err, err_len, "no BTF type %u", id);
        return -1;
    }
    snprintf(out->kind, sizeof(out->kind), "%s", btf_kind_name(t.kind));
    snprintf(out->name, sizeof(out->name), "%s", t.name);
    return 0;
}

API int rv_type_size(rv_handle_t *h, const char *type, uint64_t *size, char *err, size_t err_len) {
    if (rv_need_prof(h, err, err_len) != 0) return -1;
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
    if (rv_need_prof(h, err, err_len) != 0) return -1;
    const btf_t *b = &h->kp.btf;
    if (enum_type && enum_type[0]) {
        char spelled[256];
        snprintf(spelled, sizeof(spelled), "enum %s", strncmp(enum_type, "enum ", 5) == 0 ? enum_type + 5 : enum_type);
        uint32_t id = find_type(b, spelled);
        if (!id) id = find_type(b, enum_type);
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
    if (rv_need_prof(h, err, err_len) != 0) return -1;
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
