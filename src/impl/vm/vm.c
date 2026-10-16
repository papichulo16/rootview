#include "vm/vm.h"

#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "vm/vm_config.h"
#include "vm/vm_qemu.h"
#include "vm/vm_state.h"
#include "vm/vm_store.h"

int vm_create(const vm_config_t *cfg, char *err, size_t err_len) {
    if (cfg->name[0] == '\0') {
        if (err) snprintf(err, err_len, "vm name must not be empty");
        return -1;
    }
    if (vm_store_exists(cfg->name)) {
        if (err) snprintf(err, err_len, "vm '%s' already exists", cfg->name);
        return -1;
    }
    if (vm_store_make_dir(cfg->name) != 0) {
        if (err) snprintf(err, err_len, "failed to create store directory for '%s'", cfg->name);
        return -1;
    }
    if (vm_config_save(cfg) != 0) {
        if (err) snprintf(err, err_len, "failed to write config for '%s'", cfg->name);
        return -1;
    }

    vm_runtime_state_t st = {0};
    st.status = VM_STATUS_STOPPED;
    vm_state_save(cfg->name, &st);
    return 0;
}

int vm_start(const char *name, char *err, size_t err_len) {
    if (!vm_store_exists(name)) {
        if (err) snprintf(err, err_len, "vm '%s' does not exist", name);
        return -1;
    }

    vm_config_t cfg;
    vm_config_load(name, &cfg);

    vm_runtime_state_t st;
    vm_state_load(name, &st);
    if (vm_state_is_alive(&st)) {
        if (err) snprintf(err, err_len, "vm '%s' is already running (pid %d)", name, st.pid);
        return -1;
    }

    char dir[PATH_MAX], qmp[PATH_MAX], mon[PATH_MAX], kvmi[PATH_MAX] = "", log[PATH_MAX];
    vm_store_dir(name, dir);
    snprintf(qmp, sizeof(qmp), "%s/qmp.sock", dir);
    snprintf(mon, sizeof(mon), "%s/monitor.sock", dir);
    if (cfg.kvmi_enabled) snprintf(kvmi, sizeof(kvmi), "%s/kvmi.sock", dir);
    vm_store_log_path(name, log);

    pid_t pid;
    if (qemu_spawn(&cfg, qmp, mon, kvmi, log, &pid) != 0) {
        if (err) snprintf(err, err_len, "qemu failed to start, see %s", log);
        return -1;
    }

    memset(&st, 0, sizeof(st));
    st.status = VM_STATUS_RUNNING;
    st.pid = pid;
    st.started_at = time(NULL);
    snprintf(st.qmp_socket, sizeof(st.qmp_socket), "%s", qmp);
    snprintf(st.monitor_socket, sizeof(st.monitor_socket), "%s", mon);
    snprintf(st.kvmi_socket, sizeof(st.kvmi_socket), "%s", kvmi);
    vm_state_save(name, &st);
    return 0;
}

int vm_stop(const char *name, char *err, size_t err_len) {
    if (!vm_store_exists(name)) {
        if (err) snprintf(err, err_len, "vm '%s' does not exist", name);
        return -1;
    }

    vm_runtime_state_t st;
    vm_state_load(name, &st);
    if (!vm_state_is_alive(&st)) {
        if (err) snprintf(err, err_len, "vm '%s' is not running", name);
        return -1;
    }

    qemu_stop(st.pid);

    memset(&st, 0, sizeof(st));
    st.status = VM_STATUS_STOPPED;
    vm_state_save(name, &st);
    return 0;
}

int vm_restart(const char *name, char *err, size_t err_len) {
    vm_stop(name, NULL, 0); /* best effort, ok if it wasn't running */
    return vm_start(name, err, err_len);
}

int vm_destroy(const char *name, bool force, char *err, size_t err_len) {
    if (!vm_store_exists(name)) {
        if (err) snprintf(err, err_len, "vm '%s' does not exist", name);
        return -1;
    }

    vm_runtime_state_t st;
    vm_state_load(name, &st);
    if (vm_state_is_alive(&st)) {
        if (!force) {
            if (err) snprintf(err, err_len, "vm '%s' is running, stop it first or pass --force", name);
            return -1;
        }
        qemu_stop(st.pid);
    }

    if (vm_store_remove_dir(name) != 0) {
        if (err) snprintf(err, err_len, "failed to remove store directory for '%s'", name);
        return -1;
    }
    return 0;
}

void vm_inspect(const char *name) {
    if (!vm_store_exists(name)) {
        printf("vm '%s' does not exist\n", name);
        return;
    }

    vm_config_t cfg;
    vm_config_load(name, &cfg);
    vm_runtime_state_t st;
    vm_state_load(name, &st);
    bool alive = vm_state_is_alive(&st);

    printf("name:        %s\n", cfg.name);
    printf("status:      %s\n", alive ? "running" : "stopped");
    if (alive) {
        printf("pid:         %d\n", st.pid);
        printf("uptime:      %lds\n", (long) (time(NULL) - st.started_at));
        printf("qmp socket:  %s\n", st.qmp_socket);
        printf("monitor:     %s\n", st.monitor_socket);
        printf("kvmi socket: %s\n", st.kvmi_socket[0] ? st.kvmi_socket : "(none)");
    }
    printf("memory:      %d MB\n", cfg.memory_mb);
    printf("cpus:        %d\n", cfg.cpus);
    printf("kvm:         %s\n", cfg.use_kvm ? "yes" : "no");
    printf("disk:        %s\n", cfg.disk_image[0] ? cfg.disk_image : "(none)");
    printf("cdrom:       %s\n", cfg.cdrom[0] ? cfg.cdrom : "(none)");
    printf("network:     %s\n", vm_net_mode_str(cfg.network));
    printf("display:     %s\n", vm_display_mode_str(cfg.display));
    if (cfg.extra_args[0]) printf("extra args:  %s\n", cfg.extra_args);
}

void vm_list(void) {
    char names[256][VM_NAME_MAX];
    int count = vm_store_list(names, 256);

    if (count == 0) {
        printf("no vms found (create one with `rv vm create <name>`)\n");
        return;
    }

    printf("%-20s %-10s %-8s %-6s %-6s\n", "NAME", "STATUS", "PID", "MEM", "CPUS");
    for (int i = 0; i < count; i++) {
        vm_config_t cfg;
        vm_config_load(names[i], &cfg);
        vm_runtime_state_t st;
        vm_state_load(names[i], &st);
        bool alive = vm_state_is_alive(&st);

        char pid_buf[16] = "-";
        if (alive) snprintf(pid_buf, sizeof(pid_buf), "%d", st.pid);

        printf("%-20s %-10s %-8s %-6d %-6d\n", names[i], alive ? "running" : "stopped", pid_buf,
               cfg.memory_mb, cfg.cpus);
    }
}

static int connect_unix_socket(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int vm_console(const char *name, char *err, size_t err_len) {
    if (!vm_store_exists(name)) {
        if (err) snprintf(err, err_len, "vm '%s' does not exist", name);
        return -1;
    }

    vm_runtime_state_t st;
    vm_state_load(name, &st);
    if (!vm_state_is_alive(&st)) {
        if (err) snprintf(err, err_len, "vm '%s' is not running", name);
        return -1;
    }

    int fd = connect_unix_socket(st.monitor_socket);
    if (fd < 0) {
        if (err) snprintf(err, err_len, "failed to connect to monitor socket %s", st.monitor_socket);
        return -1;
    }

    printf("connected to '%s' monitor (qemu prompt). ctrl-d to detach.\n", name);
    char buf[4096];
    while (true) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(fd, &fds);
        int maxfd = fd > STDIN_FILENO ? fd : STDIN_FILENO;

        if (select(maxfd + 1, &fds, NULL, NULL, NULL) < 0) break;

        if (FD_ISSET(fd, &fds)) {
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n <= 0) break;
            fwrite(buf, 1, (size_t) n, stdout);
            fflush(stdout);
        }
        if (FD_ISSET(STDIN_FILENO, &fds)) {
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0) break;
            if (write(fd, buf, (size_t) n) < 0) break;
        }
    }

    close(fd);
    printf("\ndetached from '%s'\n", name);
    return 0;
}
