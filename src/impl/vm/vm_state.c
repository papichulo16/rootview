#include "vm/vm_state.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "util/json.h"
#include "vm/vm_store.h"

int vm_state_load(const char *name, vm_runtime_state_t *st) {
    memset(st, 0, sizeof(*st));
    st->status = VM_STATUS_STOPPED;

    char path[PATH_MAX];
    vm_store_state_path(name, path);

    json_value_t *root = json_parse_file(path, NULL, 0);
    if (!root) return -1;

    const char *status = json_get_string(root, "status", "stopped");
    st->status = strcmp(status, "running") == 0 ? VM_STATUS_RUNNING : VM_STATUS_STOPPED;
    st->pid = (pid_t) json_get_int(root, "pid", 0);
    st->started_at = (time_t) json_get_int(root, "started_at", 0);

    const char *qmp = json_get_string(root, "qmp_socket", NULL);
    if (qmp) snprintf(st->qmp_socket, sizeof(st->qmp_socket), "%s", qmp);
    const char *mon = json_get_string(root, "monitor_socket", NULL);
    if (mon) snprintf(st->monitor_socket, sizeof(st->monitor_socket), "%s", mon);

    json_free(root);
    return 0;
}

int vm_state_save(const char *name, const vm_runtime_state_t *st) {
    json_value_t *root = json_new_object();
    json_object_set_string(root, "status", vm_status_str(st->status));
    json_object_set_int(root, "pid", st->pid);
    json_object_set_int(root, "started_at", (long) st->started_at);
    json_object_set_string(root, "qmp_socket", st->qmp_socket);
    json_object_set_string(root, "monitor_socket", st->monitor_socket);

    char path[PATH_MAX];
    vm_store_state_path(name, path);
    int rc = json_write_file(root, path);
    json_free(root);
    return rc;
}

bool vm_state_is_alive(const vm_runtime_state_t *st) {
    if (st->status != VM_STATUS_RUNNING || st->pid <= 0) return false;
    return kill(st->pid, 0) == 0;
}
