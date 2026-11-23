# KVMI on Linux 7.3

KVM introspection (KVMI) ported from KVM-VMI's `kvmi-v7` for kernel 5.4 to kernel 7.3. This allows a host to run current Ubuntu instead of using kernel 5.4.24-kvmi+ on an older version.

Kernel: patched `kvm.ko`, `kvm-amd.ko` and `kvm-intel.ko` for the stock Ubuntu 26.10 kernel, installed under `/lib/modules/<release>/updates`.
QEMU 11.0.3: kvmi-v7's `introspection` object, forward-ported and installed to `/usr/local/bin`.
libkvmi / LibVMI: Just one fix for LibVMI

## Status

| | AMD (SVM) | Intel (VMX) |
|---|---|---|
| hook / unhook, pause, registers, physical memory | yes | builds, untested |
| CR0/CR4, MSR, CPUID, XSETBV, hypercall, trap events | yes | builds, untested |
| CR3-write, breakpoint, descriptor-table events | yes | no |
| single-step | yes (new) | no |
| page access events (w, x, rw) | yes | builds, untested |
| EPT views, #VE, SPP, remote mapping | no | no |

Tested on Ubuntu 26.10 using nested virtualization, on a Zen 4 machine.
Also tested using the rootview tests.
This includes the breakpoint and memory-capture hooks. Single stepping is also new for AMD devices since this feature was missing.

## Install

On Ubuntu 26.10 with no VMs running:

```sh
./kvmi/install.sh
```

The script does the following:

`build-modules.sh`: patches `linux-source` for the running kernel and installs the KVM modules to `updates/kvmi`.
`build-qemu.sh`: builds the patched QEMU into `/usr/local`. Also makes it so that libvirtd can use our compiled QEMU.
`build-libs.sh`: builds libkvmi and the patched LibVMI into `/usr/local`.
`load-modules.sh`: swaps in the new KVM modules without a reboot.

After a kernel update, rerun `build-modules.sh` and `load-modules.sh`.

## Design notes

Changes are only in the KVM modules.
Access restrictions are a per-VM xarray keyed by gfn. Restricted accesses are emulated and reported before they occur.
AMD has no monitor trap flag, so single-step uses RFLAGS.TF and the #DB intercept, like KVM's `nmi_singlestep`. TF is hidden from the guest and event injection is held off while stepping.
`patches/qemu/0002` fixes QEMU aborting when using `reconnect-ms` as a result of the server being down
`patches/libvmi/0001` replies to page faults whose hook was removed in flight, which LibVMI used to drop, leaving the vCPU stuck.

## Known limitations

TF single-step: Instructions clearing TF ends the step without a #DB, `PUSHF` sees TF, and exceptions the CPU delivers directly can run their handler mid-step.
On AMD, page faults raised after an emulation failure have `gva` = 0.
Tool writes to guest memory reach the dirty bitmap but not the dirty ring.
LibVMI refuses read-only restrictions since it assumes EPT is there.

## License

The patches and scripts are GPL-2.0, like the Bitdefender KVMI patches and
KVM-VMI QEMU they derive from.
