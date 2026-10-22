# rootview.rvprim

`Guest(vm)` attaches to a running kvmi guest and builds its kernel profile
(pauses it ~1s). Use it as a context manager.

| Area | Calls |
|---|---|
| guests | `list_vms()`, `set_base(dir)`, `Guest(name)`, `close()` |
| kernel | `info()`: release, image bounds, symbol and type counts, `init_task` |
| consistency | `with g.snapshot():` pauses the guest and caches reads until the block ends |
| memory | `read(va, n)`, `read_phys(pa, n)`, `translate(va)` |
| symbols | `sym(name)`, `sym_at(va)`, `symbols()` |
| BTF | `field(type, path)`, `read_field(type, path, va)`, `type_size(type)`, `enum_value(name, enum=None)`, `enum_name(enum, value)` |
| walks | `list`/`hlist(head, type, member)`, `list_off`/`hlist_off(head, off)`, `rbtree(root)`, `idr(idr)`, `tasks()` |
| per-cpu | `nr_cpus()`, `percpu_addr(sym, cpu)` |
| registers | `reg(name)` (vcpu 0: `cr3`, `idtr_base`, `msr_lstar`, ...) |
| hooks | `hook_reg`, `hook_bp`, `hook_cpuid`, `hook_desc`, `hook_mem(name, va, access)`, `hook_mem_gfn(name, gfn, access, capture)`, `hook_remove` |
| events | `poll(ms)` pumps hooks into a ring, `events()` drains it |

Notes:
- Paths are dotted through embedded structs (`se.vruntime`), not pointers.
- Walks fail on cycles, wild pointers or more than `max` nodes.
- `sym_at` only names addresses inside the core kernel image.
