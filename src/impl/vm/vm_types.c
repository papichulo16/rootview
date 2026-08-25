#include "vm/vm_types.h"

#include <string.h>

const char *vm_net_mode_str(vm_net_mode_t mode) {
    switch (mode) {
        case VM_NET_NONE: return "none";
        case VM_NET_USER: return "user";
        case VM_NET_TAP: return "tap";
    }
    return "unknown";
}

vm_net_mode_t vm_net_mode_parse(const char *s) {
    if (!s) return VM_NET_USER;
    if (strcmp(s, "none") == 0) return VM_NET_NONE;
    if (strcmp(s, "tap") == 0) return VM_NET_TAP;
    return VM_NET_USER;
}

const char *vm_display_mode_str(vm_display_mode_t mode) {
    switch (mode) {
        case VM_DISPLAY_NONE: return "none";
        case VM_DISPLAY_GTK: return "gtk";
        case VM_DISPLAY_VNC: return "vnc";
    }
    return "unknown";
}

vm_display_mode_t vm_display_mode_parse(const char *s) {
    if (!s) return VM_DISPLAY_NONE;
    if (strcmp(s, "gtk") == 0) return VM_DISPLAY_GTK;
    if (strcmp(s, "vnc") == 0) return VM_DISPLAY_VNC;
    return VM_DISPLAY_NONE;
}

const char *vm_status_str(vm_status_t status) {
    return status == VM_STATUS_RUNNING ? "running" : "stopped";
}
