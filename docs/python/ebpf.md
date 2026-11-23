# rootview.rvtools.ebpf

Loaded eBPF programs and maps, read out of the guest: what each program is,
what it calls, which maps it uses, where it is attached, which processes hold
it, and its code. Facts only; deciding what is malicious belongs to the
detection layer.

```python
from rootview.rvtools import attach
from rootview.rvtools.ebpf import Fds, Holders, Progs, Resolver, analyze, attachments

with attach("ebpf-target") as g:
    progs, res = Progs(g), Resolver(g)
    with g.snapshot():
        programs = [analyze(progs, res, p) for p in progs.prog_idr()]
        maps = [res.maps.info(m) for m in res.maps.map_idr()]
        fds, unread = Fds(g).all()
        found, errors = attachments(g, fds)
        held = Holders(g).index(fds)

for p in programs:
    print(p.info.id, p.info.type, p.info.name, p.helpers)
    print("\n".join(p.listing()))  # what bpftool prog dump xlated prints
```

`python examples/ebpf.py [vm] [--dump]` prints all of it.

| Call | Gives you |
|---|---|
| `Progs(g)` | `prog_idr()`: each program's `struct bpf_prog`; `info(addr)`: a `ProgInfo`; `insns(info)`: its raw instructions |
| `Maps(g)` | `map_idr()`: each `struct bpf_map`; `info(addr)`: a `MapInfo` |
| `attachments(g, fds=None)` | `(attachments, source -> error)` from every source: `cgroup`, `link`, `event`, `perf` |
| `Cgroups(g)`, `Links(g)` | `walk()`, `path(cgroup)`, `attachments(cgroup)`; `link_idr()`, `attachment(link)`; both `all()` |
| `Events(g)`, `Perf(g)` | `calls()`, `name(call)` (`system:event`), `progs(call)`, `all()`; `target(perf_event)`, `attachments(fds)` |
| `Fds(g)` | `all()`: `(fds, pid -> error)`, every process's prog, link, map and perf fds; `of(files)`: one fd table |
| `Holders(g)` | `index(fds)`: each `struct bpf_prog` or `bpf_map` -> its `Holder`s, by pid |
| `Resolver(g)` | `symbol(call_target(imm))` names a call, `map_refs(refs, maps)` matches map pointers; `res.maps` is its `Maps` |
| `analyze(progs, res, addr)` | a `Program` |

| Type | Fields |
|---|---|
| `ProgInfo` | `id`, `name`, `type`, `attach_type`, `tag`, `len` (slots), `jited`, `jited_len`, `bpf_func`, `ksym`, `gpl`, `kprobe_override`, `stack_depth`, `load_time` (ns since boot), `loaded_at` (UTC datetime), `uid`, `attach_func`, `maps` and `funcs` (addresses) |
| `MapInfo` | `id`, `name`, `type`, `key_size`, `value_size`, `max_entries`, `flags`, `frozen`, `data` (a global-data array's value range) |
| `Attachment` | `prog` (address), `source`, `attach_type`, `target` (cgroup path, tracepoint, `system:event`, function, interface), `link`, `link_type`, `flags` |
| `Fd` | `pid` (tgid), `comm`, `fd`, `kind` (`prog`, `link`, `map`, `perf`), `obj` (the file's object) |
| `Holder` | `pid`, `comm`, `fd`, `via` (the fd's kind) |
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
  freplace), cgroup, XDP and perf event. Other link types have an empty `target`.
- A tracepoint, or a probe made through tracefs, is on `ftrace_events` and found
  by `event`. A kprobe or uprobe made through its PMU (libbpf's way) isn't: it
  shows up through `perf` while a process holds the event, or its perf link.
  `perf` is what `bpftool perf` lists.
- The kernel doesn't record who loaded a program. A holder is a process that
  has it open now, by its own fd, a link's or a perf event's; bpftool's `pids`
  are the holders by a prog or map fd.
- Not read yet: XDP and tc attached without a link, pinned paths.
- `guest/progs.py` and `guest/maps.py` are minimal readers; `kern/obj` readers
  can replace them behind `ProgInfo` and `MapInfo`.
- Checked on Ubuntu 5.15 guests: listings, cgroup attachments, links and perf
  attachments match bpftool; fds and holders match `/proc/<pid>/fdinfo`.
- Attaching XDP in the guest patches `bpf_dispatcher_xdp_func`, which
  `test_ftrace_records` reports as a modified site.
