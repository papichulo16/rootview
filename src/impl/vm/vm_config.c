#include "vm/vm_config.h"

#include <stdio.h>
#include <string.h>

#include "util/json.h"
#include "vm/vm_store.h"

void vm_config_default(vm_config_t *cfg, const char *name) {
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->name, sizeof(cfg->name), "%s", name);
    cfg->memory_mb = 1024;
    cfg->cpus = 1;
    cfg->network = VM_NET_USER;
    cfg->display = VM_DISPLAY_NONE;
    cfg->use_kvm = true;
}

int vm_config_from_json_file(const char *path, vm_config_t *cfg, char *err, size_t err_len) {
    char parse_err[256];
    json_value_t *root = json_parse_file(path, parse_err, sizeof(parse_err));
    if (!root) {
        if (err) snprintf(err, err_len, "%s", parse_err);
        return -1;
    }

    const char *name = json_get_string(root, "name", NULL);
    if (name) snprintf(cfg->name, sizeof(cfg->name), "%s", name);

    cfg->memory_mb = (int) json_get_int(root, "memory_mb", cfg->memory_mb);
    cfg->cpus = (int) json_get_int(root, "cpus", cfg->cpus);
    cfg->use_kvm = json_get_bool(root, "kvm", cfg->use_kvm);

    const char *disk = json_get_string(root, "disk_image", NULL);
    if (disk) snprintf(cfg->disk_image, sizeof(cfg->disk_image), "%s", disk);

    const char *cdrom = json_get_string(root, "cdrom", NULL);
    if (cdrom) snprintf(cfg->cdrom, sizeof(cfg->cdrom), "%s", cdrom);

    const char *net = json_get_string(root, "network", NULL);
    if (net) cfg->network = vm_net_mode_parse(net);

    const char *display = json_get_string(root, "display", NULL);
    if (display) cfg->display = vm_display_mode_parse(display);

    const char *extra = json_get_string(root, "extra_args", NULL);
    if (extra) snprintf(cfg->extra_args, sizeof(cfg->extra_args), "%s", extra);

    json_free(root);
    return 0;
}

int vm_config_load(const char *name, vm_config_t *cfg) {
    char path[PATH_MAX];
    vm_store_config_path(name, path);
    vm_config_default(cfg, name);
    return vm_config_from_json_file(path, cfg, NULL, 0);
}

int vm_config_save(const vm_config_t *cfg) {
    json_value_t *root = json_new_object();
    json_object_set_string(root, "name", cfg->name);
    json_object_set_int(root, "memory_mb", cfg->memory_mb);
    json_object_set_int(root, "cpus", cfg->cpus);
    json_object_set_bool(root, "kvm", cfg->use_kvm);
    json_object_set_string(root, "disk_image", cfg->disk_image);
    json_object_set_string(root, "cdrom", cfg->cdrom);
    json_object_set_string(root, "network", vm_net_mode_str(cfg->network));
    json_object_set_string(root, "display", vm_display_mode_str(cfg->display));
    json_object_set_string(root, "extra_args", cfg->extra_args);

    char path[PATH_MAX];
    vm_store_config_path(cfg->name, path);
    int rc = json_write_file(root, path);
    json_free(root);
    return rc;
}
