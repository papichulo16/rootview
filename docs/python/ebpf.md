# rootview.rvtools.ebpf

Loaded eBPF programs and maps, read out of the guest: what each program is,
what it calls, which maps it uses, where it is attached, and its code. Facts
only; deciding what is malicious belongs to the detection layer.

```python
from rootview.rvtools import attach
from rootview.rvtools.ebpf import Progs, Resolver, analyze, attachments

with attach("ebpf-target") as g:
    progs, res = Progs(g), Resolver(g)
    with g.snapshot():
        programs = [analyze(progs, res, p) for p in progs.prog_idr()]
        maps = [res.maps.info(m) for m in res.maps.map_idr()]
        found, errors = attachments(g)

for p in programs:
    print(p.info.id, p.info.type, p.info.name, p.helpers)
    print("\n".join(p.listing()))  # what bpftool prog dump xlated prints
```

`python examples/ebpf.py [vm] [--dump]` prints all of it.

| Call | Gives you |
|---|---|
| `Progs(g)` | `prog_idr()`: each program's `struct bpf_prog`; `info(addr)`: a `ProgInfo`; `insns(info)`: its raw instructions |
| `Maps(g)` | `map_idr()`: each `struct bpf_map`; `info(addr)`: a `MapInfo` |
| `attachments(g)` | `(attachments, source -> error)` from every source, `cgroup` and `link` |
| `Cgroups(g)`, `Links(g)` | one source each: `walk()`, `path(cgroup)`, `attachments(cgroup)`; `link_idr()`, `attachment(link)`; both `all()` |
| `Resolver(g)` | `symbol(call_target(imm))` names a call, `map_refs(refs, maps)` matches map pointers; `res.maps` is its `Maps` |
| `analyze(progs, res, addr)` | a `Program` |

| Type | Fields |
|---|---|
| `ProgInfo` | `id`, `name`, `type`, `attach_type`, `tag`, `len` (slots), `jited`, `jited_len`, `bpf_func`, `ksym`, `gpl`, `kprobe_override`, `stack_depth`, `load_time` (ns since boot), `loaded_at` (UTC datetime), `uid`, `attach_func`, `maps` and `funcs` (addresses) |
| `MapInfo` | `id`, `name`, `type`, `key_size`, `value_size`, `max_entries`, `flags`, `frozen`, `data` (a global-data array's value range) |
| `Attachment` | `prog` (address), `source`, `attach_type`, `target` (cgroup path, tracepoint, function, interface), `link`, `link_type`, `flags` |
| `Program` | `info`, `insns`, `calls` (kind and name), `maps`, `map_refs`, `refs`, `cfg`, `helpers`, `listing()` |
| `Cfg` | `blocks`, `entries` (one per subprogram), `back_edges` (loops), `unreachable`, `bad_targets`, `subprog_of(slot)` |

Without a guest, `ebpf.isa` (`decode`, `line`, `listing`) and `ebpf.analysis`
(`calls`, `refs`, `build`) work on raw instruction bytes.

Notes:
- The instructions are what the verifier left, not what was loaded. A helper
  call holds an address, named through kallsyms, so map helpers show as the
  map type's own function (`htab_map_update_elem`). A map load holds a
  `struct bpf_map` pointer, and a tail call has its own opcode. `listing()`
  undoes the same rewrites bpftool's dump does.
- `analyze()` and `attachments()` don't pause the guest; run them inside `g.snapshot()`.
- Decoded link targets: raw tracepoint, tracing (fentry, fexit, fmod_ret, LSM,
  freplace), cgroup and XDP. Other link types have an empty `target`.
- Not read yet: kprobes and tracepoints attached without a link, XDP and tc
  attached without one, loader pid and comm, pinned paths.
- `guest/progs.py` and `guest/maps.py` are minimal readers; `kern/obj` readers
  can replace them behind `ProgInfo` and `MapInfo`.
- Checked on Ubuntu 5.15 guests: listings, cgroup attachments and links match bpftool.
- Attaching XDP in the guest patches `bpf_dispatcher_xdp_func`, which
  `test_ftrace_records` reports as a modified site.
