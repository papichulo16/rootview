#include "vm/vm_store.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char base[PATH_MAX] = ".rootview";
static char root[PATH_MAX] = ".rootview/vms";

void vm_store_set_base(const char *dir) {
    snprintf(base, sizeof(base), "%s/.rootview", dir);
    snprintf(root, sizeof(root), "%s/vms", base);
}

const char *vm_store_root(void) {
    struct stat st;
    if (stat(base, &st) != 0) mkdir(base, 0755);
    if (stat(root, &st) != 0) mkdir(root, 0755);
    return root;
}

void vm_store_dir(const char *name, char out[PATH_MAX]) {
    snprintf(out, PATH_MAX, "%s/%s", vm_store_root(), name);
}

void vm_store_config_path(const char *name, char out[PATH_MAX]) {
    char dir[PATH_MAX];
    vm_store_dir(name, dir);
    snprintf(out, PATH_MAX, "%s/config.json", dir);
}

void vm_store_state_path(const char *name, char out[PATH_MAX]) {
    char dir[PATH_MAX];
    vm_store_dir(name, dir);
    snprintf(out, PATH_MAX, "%s/state.json", dir);
}

void vm_store_log_path(const char *name, char out[PATH_MAX]) {
    char dir[PATH_MAX];
    vm_store_dir(name, dir);
    snprintf(out, PATH_MAX, "%s/console.log", dir);
}

bool vm_store_exists(const char *name) {
    char dir[PATH_MAX];
    vm_store_dir(name, dir);
    struct stat st;
    return stat(dir, &st) == 0;
}

int vm_store_make_dir(const char *name) {
    char dir[PATH_MAX];
    vm_store_dir(name, dir);
    return mkdir(dir, 0755);
}

int vm_store_remove_dir(const char *name) {
    char dir[PATH_MAX];
    vm_store_dir(name, dir);

    DIR *d = opendir(dir);
    if (!d) return -1;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        remove(path);
    }
    closedir(d);
    return rmdir(dir);
}

int vm_store_list(char names[][VM_NAME_MAX], int max) {
    DIR *d = opendir(vm_store_root());
    if (!d) return 0;
    int count = 0;
    struct dirent *ent;
    while (count < max && (ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char dir[PATH_MAX];
        vm_store_dir(ent->d_name, dir);
        struct stat st;
        if (stat(dir, &st) == 0 && S_ISDIR(st.st_mode)) {
            snprintf(names[count], VM_NAME_MAX, "%s", ent->d_name);
            count++;
        }
    }
    closedir(d);
    return count;
}
