# rootview architecture

rootview introspects a running kernel from outside it, with no agent in it:
a KVM guest from the host (kvm-vmi), or an Android phone's own kernel from
EL2 (pkvm-vmi). It reads the kernel by name: symbols from kallsyms, struct
layouts from BTF.

```
kvmi-vm host kernel (KVMI)          exposes a guest's vcpus and memory
libvmi                              talks KVMI
pkvmi-mod on the phone              EL2 module + CLI: physical pages, EL1/EL2 registers
src/impl/vm      (C)                creates and starts guests (libvirt)
src/impl/vmi     (C)                vmi.h: one set of primitives, sent to the attached backend
src/impl/kvmi    (C)                kvm-vmi backend. vmi/: libvmi memory, registers, pause
                                    hook/: register, breakpoint, cpuid, memory hooks
src/impl/pkvmi   (C)                pkvm-vmi backend: the CLI over adb, arm64 page walks
src/impl/kern    (C)                kallsyms + BTF from the kernel image; field reads, walks
bind/            (C)                librootview.so: flat rv_* API over the above
rootview.rvprim  (Python)           ctypes wrapper over rv_*: the VMI primitives
rootview.rvtools (Python)           tooling for a detection engine: enumerate, decode
examples/, web server, CLI          consumers
```

- **Primitives** answer "what is in the guest": a field, a symbol, a list.
- **rvtools** answers "show me all of X, every way it can be reached". No verdicts.
- **Detection** (future) decides what is malicious, on top of rvtools.
- **Backends** only differ in the primitives (`vmi_ops.h`). kern, bind and
  Python are one copy for both. What a backend can't do (pkvm-vmi: writes,
  hooks, x86 registers) fails with an error saying so.
- `rv` is the C command line: `rv vm ...` manages guests, `rv kvmi attach` opens a shell.
