"""Names for what a loaded program points at: call targets through
__bpf_call_base and kallsyms, map pointers through struct bpf_map.

A map pointer is matched the way the kernel's bpf_map_from_imm does it: the
map's own address, or an address inside a single-entry array's value
(global .data, .rodata and .bss).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from rootview.rvprim import Guest
from rootview.rvtools.common import Symbols
from rootview.rvtools.ebpf.analysis.refs import Ref
from rootview.rvtools.ebpf.guest.maps import MapInfo, Maps

_U64 = (1 << 64) - 1


@dataclass(frozen=True)
class MapRef:
    idx: int  # the ld_imm64's slot
    map: MapInfo
    off: int | None  # into the map's value; None for the map itself


class Resolver:
    def __init__(self, g: Guest, syms: Symbols | None = None, maps: Maps | None = None) -> None:
        self.g = g
        self.syms = syms or Symbols(g)
        self.maps = maps or Maps(g)
        self.call_base = g.sym("__bpf_call_base")

    def call_target(self, imm: int) -> int:
        """A helper or kfunc call's target, from its imm."""
        return (self.call_base + imm) & _U64

    def symbol(self, addr: int) -> str | None:
        """The kallsyms name that starts exactly at addr."""
        s, off = self.syms.at(addr)
        return s.name if s and not off else None

    def map_refs(self, refs: Iterable[Ref], maps: Iterable[MapInfo]) -> list[MapRef]:
        """The refs that point at one of maps, or into one's value."""
        maps = list(maps)
        by_addr = {m.addr: m for m in maps}
        out = []
        for r in refs:
            if r.kind != "imm":
                continue
            if r.value in by_addr:
                out.append(MapRef(r.idx, by_addr[r.value], None))
                continue
            m = next((m for m in maps if m.data and m.data[0] <= r.value < m.data[1]), None)
            if m:
                out.append(MapRef(r.idx, m, r.value - m.data[0]))
        return out
