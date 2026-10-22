"""One loaded program, read out of the guest and analyzed: its instructions,
calls, map references and control-flow graph, with names resolved.

    progs, res = Progs(g), Resolver(g)
    with g.snapshot():
        programs = [analyze(progs, res, addr) for addr in progs.prog_idr()]
"""

from __future__ import annotations

from dataclasses import dataclass

from rootview.rvtools.ebpf.analysis.calls import HELPER, KFUNC, SUBPROG, TAIL_CALL, Call, calls
from rootview.rvtools.ebpf.analysis.cfg import Cfg, build
from rootview.rvtools.ebpf.analysis.refs import Ref, refs
from rootview.rvtools.ebpf.guest.maps import MapInfo
from rootview.rvtools.ebpf.guest.progs import ProgInfo, Progs
from rootview.rvtools.ebpf.guest.resolve import MapRef, Resolver
from rootview.rvtools.ebpf.isa.disasm import listing
from rootview.rvtools.ebpf.isa.insn import Insn, decode


@dataclass(frozen=True)
class CallSite:
    call: Call
    name: str  # helper or kfunc symbol, subprogram ksym, bpf_tail_call; an address if unnamed


@dataclass(frozen=True)
class Program:
    info: ProgInfo
    insns: tuple[Insn, ...]
    calls: tuple[CallSite, ...]
    maps: tuple[MapInfo, ...]  # aux->used_maps
    map_refs: tuple[MapRef, ...]
    refs: tuple[Ref, ...]  # every ld_imm64
    cfg: Cfg

    @property
    def helpers(self) -> list[str]:
        """Each helper and kfunc called, by name, once."""
        return sorted({c.name for c in self.calls if c.call.kind in (HELPER, KFUNC)})

    def listing(self) -> list[str]:
        """The instructions as ``bpftool prog dump xlated`` prints them."""
        sites = {c.call.idx: c for c in self.calls}
        maps = {r.idx: r for r in self.map_refs}

        def call_name(i: Insn) -> str | None:
            site = sites.get(i.idx)
            if site is None:
                return None
            if site.call.kind == SUBPROG:
                return f"{i.off:+d}#{site.name}" if self.info.funcs else f"{i.off:+d}"
            return site.name

        def imm_name(i: Insn) -> str | None:
            r = maps.get(i.idx)
            if r is None:
                return None
            return f"map[id:{r.map.id}]" if r.off is None else f"map[id:{r.map.id}][0]+{r.off}"

        return listing(self.insns, call_name, imm_name)


def analyze(progs: Progs, res: Resolver, addr: int) -> Program:
    """The program at addr, a struct bpf_prog. Run it inside g.snapshot()."""
    info = progs.info(addr)
    insns = tuple(decode(progs.insns(info)))
    found = calls(insns, info.jited)
    funcs = [progs.ksym(f) for f in info.funcs] if any(c.kind == SUBPROG for c in found) else []
    sites = tuple(CallSite(c, _call_name(c, res, funcs)) for c in found)
    maps = tuple(res.maps.info(m) for m in info.maps)
    ld = tuple(refs(insns))
    return Program(info, insns, sites, maps, tuple(res.map_refs(ld, maps)), ld, build(insns, info.jited))


def _call_name(c: Call, res: Resolver, funcs: list[str]) -> str:
    if c.kind == TAIL_CALL:
        return "bpf_tail_call"
    if c.kind == SUBPROG:
        return funcs[c.imm] if 0 <= c.imm < len(funcs) else f"subprog@{c.target}"
    addr = res.call_target(c.imm)
    return res.symbol(addr) or f"{addr:#x}"
