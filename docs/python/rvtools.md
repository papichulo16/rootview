# rootview.rvtools

Tooling for a detection engine. Each tool enumerates or decodes; none decides
what is malicious.

| Tool | Gives you |
|---|---|
| `attach(vm=None)` | a `Guest`, defaulting to the first running kvmi guest |
| `Layout(g, type, *paths)` | read a struct once (`read`), decode fields from the buffer (`get`) |
| `Symbols(g)` | kallsyms by range: `at(va)`, `next_after(va)`, `in_text(va)`, `name(va)` |
| `Tasks(g)` | task_structs per source: `task_list`, `pid_idr`, `runqueues`, `children`, `threads`; `sources()` runs all; `info(addr)` |
| `Modules(g)` | modules per source: `module_list`, `mod_tree(i)`, `carve()`; `sources(carve=False)`; `info(addr)` incl. own symbols in text |
| `Tables(g, modules)` | `syscall_table()`, `idt()`, `idt_frames()`, `lstar()`, `place(addr)` (text / module / symbol) |
| `Ftrace(g)` | `records()`: dyn_ftrace records, their flags and call-site bytes |
| `pagehash` | `hash_range`, `hash_kernel` (text + rodata), `compare(before, after)` |
| `MemWatch(g, name, start, length, slot_size)` | write-watch a range; `poll()` returns writes decoded to slot, before, after, rip |

`sources()` returns `(addr -> set of sources, source -> error)`. Run it,
then judge the differences in the detection layer.
