#ifndef ROOTVIEW_BIND_RV_KERN_H
#define ROOTVIEW_BIND_RV_KERN_H

#include "bind/rv.h"

#define RV_COMM_MAX 16
#define RV_KSYM_NAME_MAX 512

typedef struct {
    char banner[512];
    char release[65];
    uint32_t major, minor, patch;
    uint64_t image_start, image_end;
    uint64_t nsyms;
    uint32_t btf_types;
    uint64_t init_task;
    uint64_t btf_va;
    int btf_by_symbol;
} rv_info_t;

typedef struct {
    uint64_t addr;
    int64_t pid;
    int64_t tgid;
    char comm[RV_COMM_MAX + 1];
} rv_task_t;

enum { RV_U, RV_S, RV_PTR, RV_BYTES, RV_CSTR, RV_ENUM };

typedef struct {
    uint64_t offset;
    uint32_t size;
    uint32_t bit_off, bit_size;
    int kind;
    uint32_t type, ref;
} rv_field_t;

typedef struct {
    int kind;
    uint64_t u;
    int64_t s;
    char enum_name[64];
    size_t len;
    unsigned char bytes[256];
} rv_value_t;

typedef struct {
    char kind[16];
    char name[256];
} rv_type_t;

typedef struct {
    uint64_t id;
    uint64_t ptr;
} rv_idr_entry_t;

typedef struct {
    uint64_t addr;
    char type;
    char name[RV_KSYM_NAME_MAX];
} rv_ksym_t;

int rv_info(rv_handle_t *h, rv_info_t *out, char *err, size_t err_len);

int rv_snapshot_begin(rv_handle_t *h, char *err, size_t err_len);
int rv_snapshot_end(rv_handle_t *h, char *err, size_t err_len);

int rv_read(rv_handle_t *h, uint64_t va, void *buf, size_t len, char *err, size_t err_len);

int rv_sym(rv_handle_t *h, const char *name, uint64_t *addr, char *err, size_t err_len);
int rv_sym_at(rv_handle_t *h, uint64_t va, rv_ksym_t *out, char *err, size_t err_len);
int rv_ksyms(rv_handle_t *h, size_t first, rv_ksym_t *out, size_t max, size_t *total, char *err, size_t err_len);

int rv_field(rv_handle_t *h, const char *type, const char *path, rv_field_t *out, char *err, size_t err_len);
int rv_field_read(rv_handle_t *h, const char *type, const char *path, uint64_t base_va, rv_value_t *out, char *err,
                  size_t err_len);
int rv_type(rv_handle_t *h, uint32_t id, rv_type_t *out, char *err, size_t err_len);
int rv_type_size(rv_handle_t *h, const char *type, uint64_t *size, char *err, size_t err_len);
int rv_enum_value(rv_handle_t *h, const char *enum_type, const char *name, int64_t *value, char *err,
                  size_t err_len);

/* the inverse: the name of enum_type's enumerator with that value */
int rv_enum_name(rv_handle_t *h, const char *enum_type, int64_t value, char *out, size_t out_len, char *err,
                 size_t err_len);

int rv_tasks(rv_handle_t *h, rv_task_t *out, size_t max, size_t *n, char *err, size_t err_len);

int rv_list(rv_handle_t *h, uint64_t head, const char *type, const char *member, uint64_t *out, size_t max, size_t *n,
            char *err, size_t err_len);
int rv_hlist(rv_handle_t *h, uint64_t head, const char *type, const char *member, uint64_t *out, size_t max,
             size_t *n, char *err, size_t err_len);
int rv_list_off(rv_handle_t *h, uint64_t head, uint64_t off, uint64_t *out, size_t max, size_t *n, char *err,
                size_t err_len);
int rv_hlist_off(rv_handle_t *h, uint64_t head, uint64_t off, uint64_t *out, size_t max, size_t *n, char *err,
                 size_t err_len);
int rv_rbtree(rv_handle_t *h, uint64_t root, uint64_t *out, size_t max, size_t *n, char *err, size_t err_len);
int rv_idr(rv_handle_t *h, uint64_t idr, rv_idr_entry_t *out, size_t max, size_t *n, char *err, size_t err_len);

int rv_nr_cpus(rv_handle_t *h, uint32_t *n, char *err, size_t err_len);
int rv_percpu_addr(rv_handle_t *h, const char *sym, uint32_t cpu, uint64_t *addr, char *err, size_t err_len);

#endif
