"""Every loaded eBPF program: what it is, what it calls, where it is attached;
then every map.

    python examples/ebpf.py [vm] [--dump]
"""

import sys
from collections import defaultdict

from rootview.rvtools import attach
from rootview.rvtools.ebpf import Progs, Resolver, analyze, attachments

args = [a for a in sys.argv[1:] if not a.startswith("--")]
dump = "--dump" in sys.argv
with attach(args[0] if args else None) as g:
    progs, res = Progs(g), Resolver(g)
    with g.snapshot():
        programs = sorted((analyze(progs, res, p) for p in progs.prog_idr()), key=lambda p: p.info.id)
        maps = sorted((res.maps.info(m) for m in res.maps.map_idr()), key=lambda m: m.id)
        found, errors = attachments(g)

where = defaultdict(list)
for a in found:
    where[a.prog].append(a)

print(f"{'ID':>5} {'TYPE':<22} {'NAME':<16} {'TAG':<16} {'INSNS':>5} {'BLOCKS':>6} {'LOOPS':>5}  CALLS / MAPS")
for p in programs:
    i = p.info
    kind = i.type.removeprefix("BPF_PROG_TYPE_").lower()
    uses = p.helpers + [f"map:{m.name or m.id}" for m in p.maps]
    print(f"{i.id:>5} {kind:<22} {i.name or '-':<16} {i.tag:<16} {i.len:>5} {len(p.cfg.blocks):>6} "
          f"{len(p.cfg.back_edges):>5}  {', '.join(uses) or '-'}")
    for a in where.pop(i.addr, []):
        via = a.source if a.link is None else f"{a.source} (link {a.link})"
        print(f"{'':6}{via:<16} {a.attach_type or a.link_type:<30} {a.target or '-'}")
    if dump:
        print("\n".join(p.listing()) + "\n")
print(f"\n{len(programs)} programs, {len(found)} attachments")
for prog, rest in where.items():
    print(f"attached but not in prog_idr: {prog:#x} {[(a.source, a.target) for a in rest]}")

print(f"\n{'ID':>5} {'TYPE':<26} {'NAME':<16} {'KEY':>4} {'VALUE':>6} {'ENTRIES':>8} {'FLAGS':>6}")
for m in maps:
    kind = m.type.removeprefix("BPF_MAP_TYPE_").lower()
    print(f"{m.id:>5} {kind:<26} {m.name or '-':<16} {m.key_size:>4} {m.value_size:>6} {m.max_entries:>8} "
          f"{m.flags:>#6x}{' frozen' if m.frozen else ''}")
print(f"\n{len(maps)} maps")
for source, err in errors.items():
    print(f"{source} failed: {err}")
