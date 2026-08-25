#include "vm/vm_qemu.h"

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void split_extra_args(char *buf, char **argv, int *argc, int max) {
    char *tok = strtok(buf, " \t");
    while (tok && *argc < max - 1) {
        argv[(*argc)++] = tok;
        tok = strtok(NULL, " \t");
    }
}

static int build_argv(const vm_config_t *cfg, const char *qmp_socket, const char *monitor_socket,
                       const char *kvmi_socket, char *argv[], int max_args) {
    static char mem_arg[32];
    static char smp_arg[32];
    static char drive_arg[PATH_MAX + 32];
    static char qmp_arg[PATH_MAX + 32];
    static char mon_arg[PATH_MAX + 32];
    static char kvmi_arg[PATH_MAX + 32];
    static char extra_buf[512];

    int argc = 0;
    argv[argc++] = "qemu-system-x86_64";
    argv[argc++] = "-name";
    argv[argc++] = (char *) cfg->name;

    snprintf(mem_arg, sizeof(mem_arg), "%d", cfg->memory_mb);
    argv[argc++] = "-m";
    argv[argc++] = mem_arg;

    snprintf(smp_arg, sizeof(smp_arg), "%d", cfg->cpus);
    argv[argc++] = "-smp";
    argv[argc++] = smp_arg;

    if (cfg->use_kvm) argv[argc++] = "-enable-kvm";

    if (cfg->disk_image[0]) {
        snprintf(drive_arg, sizeof(drive_arg), "file=%s,if=virtio", cfg->disk_image);
        argv[argc++] = "-drive";
        argv[argc++] = drive_arg;
    }

    if (cfg->cdrom[0]) {
        argv[argc++] = "-cdrom";
        argv[argc++] = (char *) cfg->cdrom;
    }

    switch (cfg->network) {
        case VM_NET_NONE:
            argv[argc++] = "-nic";
            argv[argc++] = "none";
            break;
        case VM_NET_TAP:
            argv[argc++] = "-nic";
            argv[argc++] = "tap,model=virtio-net-pci";
            break;
        case VM_NET_USER:
        default:
            argv[argc++] = "-nic";
            argv[argc++] = "user,model=virtio-net-pci";
            break;
    }

    argv[argc++] = "-display";
    argv[argc++] = (char *) vm_display_mode_str(cfg->display);

    snprintf(qmp_arg, sizeof(qmp_arg), "unix:%s,server,nowait", qmp_socket);
    argv[argc++] = "-qmp";
    argv[argc++] = qmp_arg;

    snprintf(mon_arg, sizeof(mon_arg), "unix:%s,server,nowait", monitor_socket);
    argv[argc++] = "-monitor";
    argv[argc++] = mon_arg;

    /* qemu connects out to the vmi module's listening socket, retrying
     * until something's there to accept it - see vmi_attach(). */
    if (kvmi_socket && kvmi_socket[0]) {
        snprintf(kvmi_arg, sizeof(kvmi_arg), "socket,path=%s,id=kvmi_chardev,reconnect-ms=10000", kvmi_socket);
        argv[argc++] = "-chardev";
        argv[argc++] = kvmi_arg;
        argv[argc++] = "-object";
        argv[argc++] = "introspection,id=kvmi,chardev=kvmi_chardev";
    }

    snprintf(extra_buf, sizeof(extra_buf), "%s", cfg->extra_args);
    split_extra_args(extra_buf, argv, &argc, max_args);

    argv[argc] = NULL;
    return argc;
}

int qemu_spawn(const vm_config_t *cfg, const char *qmp_socket, const char *monitor_socket,
               const char *kvmi_socket, const char *log_path, pid_t *out_pid) {
    char *argv[64];
    build_argv(cfg, qmp_socket, monitor_socket, kvmi_socket, argv, 64);

    pid_t pid = fork();
    if (pid < 0) return -1;

    if (pid == 0) {
        setsid();
        int fd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            close(devnull);
        }
        execvp("qemu-system-x86_64", argv);
        _exit(127);
    }

    /* give qemu a moment to fail fast on bad args before we report success */
    usleep(200000);
    int status;
    if (waitpid(pid, &status, WNOHANG) == pid) return -1;

    *out_pid = pid;
    return 0;
}

int qemu_stop(pid_t pid) {
    if (pid <= 0) return -1;
    if (kill(pid, SIGTERM) != 0) return -1;

    for (int i = 0; i < 50; i++) {
        if (kill(pid, 0) != 0) return 0;
        usleep(100000);
    }
    kill(pid, SIGKILL);
    usleep(100000);
    return 0;
}
