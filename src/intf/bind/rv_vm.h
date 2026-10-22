#ifndef ROOTVIEW_BIND_RV_VM_H
#define ROOTVIEW_BIND_RV_VM_H

#include "bind/rv.h"

typedef struct {
    char name[RV_NAME_MAX];
    int memory_mb;
    int cpus;
    char disk_image[RV_PATH_MAX];
    char cdrom[RV_PATH_MAX];
    char network[8];
    char display[8];
    int use_kvm;
    int kvmi_enabled;
    char extra_args[512];
} rv_vm_config_t;

typedef struct {
    rv_vm_config_t config;
    int running;
    int kvmi;
    int pid;
    int64_t started_at;
    char qmp_socket[RV_PATH_MAX];
    char monitor_socket[RV_PATH_MAX];
    char kvmi_socket[RV_PATH_MAX];
    char log_path[RV_PATH_MAX];
} rv_vm_t;

int rv_vm_list(rv_vm_t *out, size_t max, size_t *n, char *err, size_t err_len);
int rv_vm_inspect(const char *name, rv_vm_t *out, char *err, size_t err_len);

void rv_vm_defaults(const char *name, rv_vm_config_t *out);
int rv_vm_config_file(const char *path, rv_vm_config_t *cfg, char *err, size_t err_len);
int rv_vm_create(const rv_vm_config_t *cfg, char *err, size_t err_len);

int rv_vm_start(const char *name, char *err, size_t err_len);
int rv_vm_stop(const char *name, char *err, size_t err_len);
int rv_vm_restart(const char *name, char *err, size_t err_len);
int rv_vm_destroy(const char *name, int force, char *err, size_t err_len);

#endif
