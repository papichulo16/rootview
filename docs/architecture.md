# rootview architecture

rootview introspects a running KVM guest from the host, with no agent in the
guest. It reads the guest kernel by name: symbols from kallsyms, struct
layouts from BTF.

```
kvmi-vm host kernel (KVMI)          exposes a guest's vcpus and memory
libvmi                              talks KVMI
src/impl/vm      (C)                creates and starts guests (libvirt)
src/impl/kvmi    (C)                vmi/: read/write memory and registers, pause
                                    hook/: register, breakpoint, cpuid, memory hooks
src/impl/kern    (C)                kallsyms + BTF from the guest image; field reads, walks
bind/            (C)                librootview.so: flat rv_* API over the above
rootview.rvprimitives (Python)      ctypes wrapper over rv_*: the VMI primitives
rootview.rvtools      (Python)      tooling for a detection engine: enumerate, decode
examples/, web server, CLI          consumers
```

- **Primitives** answer "what is in the guest": a field, a symbol, a list.
- **rvtools** answers "show me all of X, every way it can be reached". No verdicts.
- **Detection** (future) decides what is malicious, on top of rvtools.
- `rv` is the C command line: `rv vm ...` manages guests, `rv kvmi attach` opens a shell.
