#ifndef ROOTVIEW_VM_TYPES_H
#define ROOTVIEW_VM_TYPES_H

#include <limits.h>
#include <stdbool.h>
#include <sys/types.h>
#include <time.h>

#define VM_NAME_MAX 64

typedef enum {
    VM_NET_NONE,
    VM_NET_USER,
    VM_NET_TAP,
} vm_net_mode_t;

typedef enum {
    VM_DISPLAY_NONE,
    VM_DISPLAY_GTK,
    VM_DISPLAY_VNC,
} vm_display_mode_t;

typedef enum {
    VM_STATUS_STOPPED,
    VM_STATUS_RUNNING,
} vm_status_t;

typedef struct {
    char name[VM_NAME_MAX];
    int memory_mb;
    int cpus;
    char disk_image[PATH_MAX];
    char cdrom[PATH_MAX];
    vm_net_mode_t network;
    vm_display_mode_t display;
    bool use_kvm;
    bool kvmi_enabled; /* exposes a kvmi introspection socket for the vmi module to attach to */
    char extra_args[512]; /* raw passthrough, space separated */
} vm_config_t;

typedef struct {
    vm_status_t status;
    pid_t pid;
    char qmp_socket[PATH_MAX];
    char monitor_socket[PATH_MAX];
    char kvmi_socket[PATH_MAX]; /* empty when kvmi_enabled was off at start */
    time_t started_at;
} vm_runtime_state_t;

const char *vm_net_mode_str(vm_net_mode_t mode);
vm_net_mode_t vm_net_mode_parse(const char *s);
const char *vm_display_mode_str(vm_display_mode_t mode);
vm_display_mode_t vm_display_mode_parse(const char *s);
const char *vm_status_str(vm_status_t status);

#endif
