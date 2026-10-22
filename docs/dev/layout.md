# Layout

| Path | What |
|---|---|
| `src/intf/` | C headers, one dir per module |
| `src/impl/vm/` | guest lifecycle through libvirt |
| `src/impl/kvmi/vmi/` | memory, registers, pause: the only libvmi user besides hooks |
| `src/impl/kvmi/hook/` | hooks and the event loop |
| `src/impl/kvmi/kvmi_shell.c` | `rv kvmi attach` shell |
| `src/impl/kern/` | kallsyms, BTF, fields, walks (see its README) |
| `bind/` | `librootview.so` and its `rv_*` API (`rootview.h`) |
| `src/rootview/` | the Python package: `rvprim.py`, `rvtools/` |
| `src/ui/dynamic/` | the web server |
| `examples/` | scripts using rvtools |
