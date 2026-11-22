# Layout

| Path | What |
|---|---|
| `src/intf/` | C headers, one dir per module |
| `src/impl/vm/` | guest lifecycle through libvirt |
| `src/impl/vmi/` | `vmi.h` dispatch: every primitive goes to the attached backend's `vmi_ops_t` |
| `src/impl/kvmi/vmi/` | kvm-vmi backend: memory, registers, pause; the only libvmi user besides hooks |
| `src/impl/pkvmi/` | pkvm-vmi backend: `pkvmi_adb.c` drives the phone's CLI, `pkvmi_walk.c` walks arm64 page tables |
| `src/impl/kvmi/hook/` | hooks and the event loop |
| `src/impl/kvmi/kvmi_shell.c` | `rv kvmi attach` shell |
| `src/impl/kern/` | kallsyms, BTF, fields, walks (see its README) |
| `bind/` | `librootview.so` and its `rv_*` API (`rootview.h`) |
| `src/rootview/` | the Python package: `rvprim.py`, `rvtools/` |
| `src/ui/dynamic/` | the web server |
| `examples/` | scripts using rvtools |
