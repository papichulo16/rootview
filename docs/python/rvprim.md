# rootview.rvprim

`Rootview(backend, target=None)` attaches and builds the kernel profile. Use
it as a context manager. Every call below is the same on both backends.

| Backend | target | Notes |
|---|---|---|
| `"kvm-vmi"` | vm name, default the first running kvmi guest | pauses the guest ~1s to profile |
| `"pkvm-vmi"` | adb serial, default adb's device | the phone's own kernel; ~25s to profile, every uncached page is an adb round trip |

`Guest(vm)` is `Rootview("kvm-vmi", vm)`.

| Area | Calls |
|---|---|
| guests | `list_vms()`, `set_base(dir)`, `Rootview(backend, target)`, `Guest(name)`, `close()` |
| phones | `list_phones()`, `inspect_phone(serial)`: every adb device, its state, and `pkvmi` (ready for pkvm-vmi) |
| kernel | `info()`: release, image bounds, symbol and type counts, `init_task` |
| consistency | `with g.snapshot():` pauses the guest and caches reads until the block ends |
| memory | `read(va, n)`, `read_phys(pa, n)`, `translate(va)` |
| symbols | `sym(name)`, `sym_at(va)`, `symbols()` |
| BTF | `field(type, path)`, `read_field(type, path, va)`, `type_size(type)`, `enum_value(name, enum=None)`, `enum_name(enum, value)` |
| walks | `list`/`hlist(head, type, member)`, `list_off`/`hlist_off(head, off)`, `rbtree(root)`, `idr(idr)`, `tasks()` |
| per-cpu | `nr_cpus()`, `percpu_addr(sym, cpu)` |
| registers | `reg(name)` (kvm-vmi vcpu 0: `cr3`, `idtr_base`, `msr_lstar`, ...; pkvm-vmi: `ttbr1_el1`, `vbar_el1`, `hcr_el2`, ...), `regs()` (x86 only) |
| hooks | `hook_reg`, `hook_bp`, `hook_cpuid`, `hook_desc`, `hook_mem(name, va, access)`, `hook_mem_gfn(name, gfn, access, capture)`, `hook_remove` |
| events | `poll(ms)` pumps hooks into a ring, `events()` drains it |

Notes:
- Paths are dotted through embedded structs (`se.vruntime`), not pointers.
- Walks fail on cycles, wild pointers or more than `max` nodes.
- `sym_at` only names addresses inside the core kernel image.
- pkvm-vmi can't stop the phone: `pause()`/`snapshot()` there only freeze its
  page-table cache. Writes, `set_reg`, `regs()` and hooks raise on pkvm-vmi.
