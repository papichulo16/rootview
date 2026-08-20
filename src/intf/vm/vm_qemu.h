#ifndef ROOTVIEW_VM_QEMU_H
#define ROOTVIEW_VM_QEMU_H

#include <sys/types.h>

#include "vm/vm_types.h"

/* launches qemu detached, writes back the child pid. returns 0 on success. */
int qemu_spawn(const vm_config_t *cfg, const char *qmp_socket, const char *monitor_socket,
               const char *log_path, pid_t *out_pid);

/* SIGTERM then SIGKILL after a short grace period */
int qemu_stop(pid_t pid);

#endif
