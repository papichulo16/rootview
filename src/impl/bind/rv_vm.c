#include "rv_priv.h"

#include <stdio.h>
#include <string.h>

#include "vm/vm.h"
#include "vm/vm_config.h"
#include "vm/vm_state.h"
#include "vm/vm_store.h"

#define VMS_MAX 256

_Static_assert(RV_NAME_MAX == VM_NAME_MAX, "rv names fit vm names");

static void config_out(const vm_config_t *in, rv_vm_config_t *out) {
    *out = (rv_vm_config_t) {.memory_mb = in->memory_mb,
                             .cpus = in->cpus,
                             .use_kvm = in->use_kvm,
                             .kvmi_enabled = in->kvmi_enabled};
    snprintf(out->name, sizeof(out->name), "%s", in->name);
    snprintf(out->disk_image, sizeof(out->disk_image), "%s", in->disk_image);
    snprintf(out->cdrom, sizeof(out->cdrom), "%s", in->cdrom);
    snprintf(out->network, sizeof(out->network), "%s", vm_net_mode_str(in->network));
    snprintf(out->display, sizeof(out->display), "%s", vm_display_mode_str(in->display));
    snprintf(out->extra_args, sizeof(out->extra_args), "%s", in->extra_args);
}

static int config_in(const rv_vm_config_t *in, vm_config_t *out, char *err, size_t err_len) {
    vm_net_mode_t net = vm_net_mode_parse(in->network);
    vm_display_mode_t display = vm_display_mode_parse(in->display);
    if (strcmp(vm_net_mode_str(net), in->network) != 0) {
        if (err) snprintf(err, err_len, "unknown network '%s' (none, user, tap)", in->network);
        return -1;
    }
    if (strcmp(vm_display_mode_str(display), in->display) != 0) {
        if (err) snprintf(err, err_len, "unknown display '%s' (none, gtk, vnc)", in->display);
        return -1;
    }
    *out = (vm_config_t) {.memory_mb = in->memory_mb,
                          .cpus = in->cpus,
                          .network = net,
                          .display = display,
                          .use_kvm = in->use_kvm != 0,
                          .kvmi_enabled = in->kvmi_enabled != 0};
    snprintf(out->name, sizeof(out->name), "%s", in->name);
    snprintf(out->disk_image, sizeof(out->disk_image), "%s", in->disk_image);
    snprintf(out->cdrom, sizeof(out->cdrom), "%s", in->cdrom);
    snprintf(out->extra_args, sizeof(out->extra_args), "%s", in->extra_args);
    return 0;
}

static void vm_out(const char *name, rv_vm_t *out) {
    vm_config_t cfg;
    vm_runtime_state_t st = {0};
    vm_config_load(name, &cfg);
    vm_state_load(name, &st);
    bool alive = vm_state_is_alive(&st);

    memset(out, 0, sizeof(*out));
    config_out(&cfg, &out->config);
    char log[PATH_MAX];
    vm_store_log_path(name, log);
    snprintf(out->log_path, sizeof(out->log_path), "%s", log);
    if (!alive) return;

    out->running = 1;
    out->kvmi = st.kvmi_socket[0] != '\0';
    out->pid = (int) st.pid;
    out->started_at = (int64_t) st.started_at;
    snprintf(out->qmp_socket, sizeof(out->qmp_socket), "%s", st.qmp_socket);
    snprintf(out->monitor_socket, sizeof(out->monitor_socket), "%s", st.monitor_socket);
    snprintf(out->kvmi_socket, sizeof(out->kvmi_socket), "%s", st.kvmi_socket);
}

API int rv_vm_list(rv_vm_t *out, size_t max, size_t *n, char *err, size_t err_len) {
    (void) err, (void) err_len;
    char names[VMS_MAX][VM_NAME_MAX];
    int count = vm_store_list(names, VMS_MAX);
    for (int i = 0; i < count && (size_t) i < max; i++) vm_out(names[i], &out[i]);
    *n = (size_t) count;
    return 0;
}

API int rv_vm_inspect(const char *name, rv_vm_t *out, char *err, size_t err_len) {
    if (!vm_store_exists(name)) {
        if (err) snprintf(err, err_len, "vm '%s' does not exist", name);
        return -1;
    }
    vm_out(name, out);
    return 0;
}

API void rv_vm_defaults(const char *name, rv_vm_config_t *out) {
    vm_config_t cfg;
    vm_config_default(&cfg, name);
    config_out(&cfg, out);
}

API int rv_vm_config_file(const char *path, rv_vm_config_t *cfg, char *err, size_t err_len) {
    vm_config_t c;
    if (config_in(cfg, &c, err, err_len) != 0) return -1;
    char name[VM_NAME_MAX];
    snprintf(name, sizeof(name), "%s", c.name);
    if (vm_config_from_json_file(path, &c, err, err_len) != 0) return -1;
    snprintf(c.name, sizeof(c.name), "%s", name);
    config_out(&c, cfg);
    return 0;
}

API int rv_vm_create(const rv_vm_config_t *cfg, char *err, size_t err_len) {
    vm_config_t c;
    if (config_in(cfg, &c, err, err_len) != 0) return -1;
    return vm_create(&c, err, err_len);
}

API int rv_vm_start(const char *name, char *err, size_t err_len) {
    return vm_start(name, err, err_len);
}

API int rv_vm_stop(const char *name, char *err, size_t err_len) {
    return vm_stop(name, err, err_len);
}

API int rv_vm_restart(const char *name, char *err, size_t err_len) {
    return vm_restart(name, err, err_len);
}

API int rv_vm_destroy(const char *name, int force, char *err, size_t err_len) {
    return vm_destroy(name, force != 0, err, err_len);
}
