# kern

Reads a live guest's kernel by name: symbol addresses from kallsyms, struct
layouts from BTF. Both are decoded out of guest memory, so no symbol files
are needed. All guest access goes through the vmi module (`vmi/vmi.h`).
Headers are in `src/intf/kern/`.

## Files

| File | What it does |
|---|---|
| `kprof.c` | Entry point. `kprof_init` pauses the vm, copies the image, decodes kallsyms and BTF, checks that `init_task.comm` reads `swapper/0`, and resumes. The resulting `kprof_t` is what everything else takes. |
| `kimg.c` | Copies the kernel image out of the guest once, so kallsyms and BTF can be found by scanning its bytes. Finds the image from `MSR_LSTAR` with `vmi_translate_virt` and reads it with `vmi_read_virt`. |
| `ksym.c` | Finds and decodes kallsyms in the copied image. The table layout depends on the kernel version, read from the `Linux version` banner. Lookups go by name (`ksym_by_name`) or by address (`ksym_by_addr`). |
| `btf.c` | Finds and parses the kernel's `.BTF` section. Looks up types, sizes, struct members (dotted paths like `se.vruntime`) and enum values. |
| `kfield.c` | Struct fields by name on top of BTF. `kfield_resolve` gives a field's offset, size and kind; `kfield_read` reads and decodes it from a struct in guest memory. |
| `kwalk.c` | Walks kernel data structures: `list_head`, `hlist`, rb-trees, idr/xarray and per-cpu variables. Every pointer is treated as hostile (cycle checks, node caps, time budget). A snapshot window pauses the vm and caches pages so a walk sees one consistent state. |

## Order

`kprof_init` runs `kimg` → `ksym` → `btf` → `kfield`, then frees the image
copy. `kwalk` takes the finished `kprof_t`.

## Used by

- `kvmi/kvmi_shell.c`: the `prof`, `sym`, `field` and `tasks` commands.
- `bind/rootview.c`: the `rv_*` API that `rootview.rvprimitives` wraps.
  Nothing here is rootkit-specific; that lives in Python above
  `rootview.rvtools`.
