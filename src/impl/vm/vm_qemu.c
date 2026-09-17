#include "vm/vm_qemu.h"

#include <libvirt/libvirt.h>
#include <libvirt/virterror.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* libvmi's KVM/KVMI driver resolves a vm name to a running instance through
 * libvirt (qemu:///system), not through the qemu process directly - there is
 * no supported way to hand libvirt an externally-forked qemu process after
 * the fact (virDomainQemuAttach was removed from the qemu driver). so qemu
 * has to be launched *by* libvirt, as a transient domain built from cfg. */

#define XML_MAX 8192

static void xml_append(char *xml, size_t *len, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    *len += (size_t) vsnprintf(xml + *len, XML_MAX - *len, fmt, ap);
    va_end(ap);
}

/* qemu.conf paths (qmp/monitor/kvmi sockets, the log file) come from the
 * vm module's store dir, which is relative to rv's cwd on purpose. libvirtd
 * runs elsewhere, so anything handed to it has to be absolute. */
static void to_abs_path(const char *in, char *out, size_t out_len) {
    if (!in[0] || in[0] == '/') {
        snprintf(out, out_len, "%s", in);
        return;
    }
    char cwd[PATH_MAX - 1];
    if (!getcwd(cwd, sizeof(cwd))) {
        snprintf(out, out_len, "%s", in);
        return;
    }
    snprintf(out, out_len, "%s/%s", cwd, in);
}

static void build_domain_xml(const vm_config_t *cfg, const char *qmp_abs, const char *mon_abs,
                              const char *kvmi_abs, char *xml, size_t xml_size) {
    size_t len = 0;
    (void) xml_size;

    xml_append(xml, &len, "<domain type='%s' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>\n",
               cfg->use_kvm ? "kvm" : "qemu");
    xml_append(xml, &len, "  <name>%s</name>\n", cfg->name);
    xml_append(xml, &len, "  <memory unit='MiB'>%d</memory>\n", cfg->memory_mb);
    xml_append(xml, &len, "  <currentMemory unit='MiB'>%d</currentMemory>\n", cfg->memory_mb);
    xml_append(xml, &len, "  <vcpu placement='static'>%d</vcpu>\n", cfg->cpus);
    xml_append(xml, &len, "  <os><type arch='x86_64' machine='pc-i440fx-4.2'>hvm</type><boot dev='hd'/></os>\n");
    xml_append(xml, &len, "  <features><acpi/><apic/></features>\n");
    xml_append(xml, &len, "  <cpu mode='host-passthrough' check='none' migratable='on'/>\n");
    xml_append(xml, &len,
               "  <on_poweroff>destroy</on_poweroff><on_reboot>restart</on_reboot><on_crash>destroy</on_crash>\n");

    /* disk/socket paths live under the invoking user's home dir, which the
     * dynamically-allocated per-domain uid libvirt would otherwise pick
     * can't even traverse (mode 750). run as that same uid/gid instead of
     * relabeling, and skip apparmor - its auto-generated profile only
     * covers <disk>/<source> paths, not the commandline-passthrough
     * qmp/monitor/kvmi sockets below. */
    xml_append(xml, &len, "  <seclabel type='static' model='dac' relabel='no'><label>%d:%d</label></seclabel>\n",
               getuid(), getgid());
    xml_append(xml, &len, "  <seclabel type='none' model='apparmor'/>\n");

    xml_append(xml, &len, "  <devices>\n");
    xml_append(xml, &len, "    <emulator>/usr/local/bin/qemu-system-x86_64</emulator>\n");

    if (cfg->disk_image[0]) {
        xml_append(xml, &len,
                   "    <disk type='file' device='disk'>\n"
                   "      <driver name='qemu' type='qcow2'/>\n"
                   "      <source file='%s'/>\n"
                   "      <target dev='vda' bus='virtio'/>\n"
                   "    </disk>\n",
                   cfg->disk_image);
    }

    if (cfg->cdrom[0]) {
        xml_append(xml, &len,
                   "    <disk type='file' device='cdrom'>\n"
                   "      <driver name='qemu' type='raw'/>\n"
                   "      <source file='%s'/>\n"
                   "      <target dev='sda' bus='sata'/>\n"
                   "      <readonly/>\n"
                   "    </disk>\n",
                   cfg->cdrom);
    }

    switch (cfg->network) {
        case VM_NET_USER:
            xml_append(xml, &len, "    <interface type='user'><model type='virtio-net-pci'/></interface>\n");
            break;
        case VM_NET_TAP:
            xml_append(
                xml, &len,
                "    <interface type='network'><source network='default'/><model type='virtio-net-pci'/></interface>\n");
            break;
        case VM_NET_NONE:
        default:
            break;
    }

    if (cfg->display == VM_DISPLAY_VNC || cfg->display == VM_DISPLAY_GTK) {
        xml_append(xml, &len, "    <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'/>\n");
    }

    xml_append(xml, &len, "  </devices>\n");

    /* qmp/monitor go through commandline passthrough (rather than libvirt's
     * own channels) so vm_console() can keep talking to a plain qemu HMP
     * socket exactly like it did when rv forked qemu itself. */
    xml_append(xml, &len, "  <qemu:commandline>\n");
    xml_append(xml, &len, "    <qemu:arg value='-qmp'/>\n    <qemu:arg value='unix:%s,server,nowait'/>\n", qmp_abs);
    xml_append(xml, &len, "    <qemu:arg value='-monitor'/>\n    <qemu:arg value='unix:%s,server,nowait'/>\n",
               mon_abs);

    if (kvmi_abs && kvmi_abs[0]) {
        xml_append(xml, &len,
                   "    <qemu:arg value='-chardev'/>\n"
                   "    <qemu:arg value='socket,path=%s,id=kvmi_chardev,reconnect=10'/>\n"
                   "    <qemu:arg value='-object'/>\n"
                   "    <qemu:arg value='introspection,id=kvmi,chardev=kvmi_chardev'/>\n",
                   kvmi_abs);
    }

    if (cfg->extra_args[0]) {
        char buf[512];
        snprintf(buf, sizeof(buf), "%s", cfg->extra_args);
        char *tok = strtok(buf, " \t");
        while (tok) {
            xml_append(xml, &len, "    <qemu:arg value='%s'/>\n", tok);
            tok = strtok(NULL, " \t");
        }
    }

    xml_append(xml, &len, "  </qemu:commandline>\n");
    xml_append(xml, &len, "</domain>\n");
}

static int read_pidfile(const char *name, pid_t *out_pid) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/run/libvirt/qemu/%s.pid", name);

    FILE *f = fopen(path, "r");
    if (!f) return -1;
    int rc = fscanf(f, "%d", out_pid) == 1 ? 0 : -1;
    fclose(f);
    return rc;
}

static void write_log(const char *log_path, const char *fmt, ...) {
    FILE *f = fopen(log_path, "w");
    if (!f) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fclose(f);
}

int qemu_spawn(const vm_config_t *cfg, const char *qmp_socket, const char *monitor_socket,
               const char *kvmi_socket, const char *log_path, pid_t *out_pid) {
    char qmp_abs[PATH_MAX], mon_abs[PATH_MAX], kvmi_abs[PATH_MAX];
    to_abs_path(qmp_socket, qmp_abs, sizeof(qmp_abs));
    to_abs_path(monitor_socket, mon_abs, sizeof(mon_abs));
    to_abs_path(kvmi_socket, kvmi_abs, sizeof(kvmi_abs));

    char xml[XML_MAX];
    build_domain_xml(cfg, qmp_abs, mon_abs, kvmi_abs, xml, sizeof(xml));

    virConnectPtr conn = virConnectOpen("qemu:///system");
    if (!conn) {
        write_log(log_path, "failed to connect to qemu:///system\n");
        return -1;
    }

    virDomainPtr dom = virDomainCreateXML(conn, xml, 0);
    if (!dom) {
        virErrorPtr err = virGetLastError();
        write_log(log_path, "virDomainCreateXML failed: %s\n", err ? err->message : "unknown error");
        virConnectClose(conn);
        return -1;
    }

    /* libvirt writes the pidfile just after fork, slightly before the
     * domain is fully "running" - a few retries covers the gap. */
    pid_t pid = -1;
    for (int i = 0; i < 20 && pid <= 0; i++) {
        if (read_pidfile(cfg->name, &pid) == 0) break;
        usleep(100000);
    }

    virDomainFree(dom);
    virConnectClose(conn);

    if (pid <= 0) {
        write_log(log_path, "started via libvirt but never found its pidfile\n");
        return -1;
    }

    write_log(log_path, "launched via libvirt (qemu:///system), pid %d\nfull qemu log: /var/log/libvirt/qemu/%s.log\n",
              pid, cfg->name);
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
