"""Loaded eBPF maps, read out of the guest: each struct bpf_map, whether or
not a program uses it."""

from __future__ import annotations

from dataclasses import dataclass

from rootview.rvprim import Guest
from rootview.rvtools.common import Layout, read_u32

ARRAY = "BPF_MAP_TYPE_ARRAY"


@dataclass(frozen=True)
class MapInfo:
    addr: int  # the struct bpf_map
    id: int
    name: str
    type: str  # enum bpf_map_type, e.g. BPF_MAP_TYPE_HASH
    key_size: int
    value_size: int
    max_entries: int
    flags: int  # BPF_F_*
    frozen: bool  # no more writes from user space
    data: tuple[int, int] | None  # a single-entry array's value, [start, end): global data


class Maps:
    def __init__(self, g: Guest) -> None:
        self.g = g
        self.map = Layout(g, "bpf_map", "id", "name", "key_size", "value_size", "max_entries", "map_flags",
                          "frozen")
        self.array_value = g.field("bpf_array", "value").offset
        self.array_elem = g.field("bpf_array", "elem_size").offset

    def map_idr(self) -> list[int]:
        """Every map with an ID: what bpftool map list walks."""
        return [m for _, m in self.g.idr("map_idr")]

    def info(self, addr: int) -> MapInfo:
        g, lo = self.g, self.map
        buf = lo.read(g, addr)
        v = g.read_field("bpf_map", "map_type", addr)
        kind = v.enum_name or str(v.value)
        data = None
        if kind == ARRAY and lo.get(buf, "max_entries") == 1:
            start = addr + self.array_value
            data = (start, start + read_u32(g, addr + self.array_elem))
        return MapInfo(addr, lo.get(buf, "id"), lo.get(buf, "name"), kind, lo.get(buf, "key_size"),
                       lo.get(buf, "value_size"), lo.get(buf, "max_entries"), lo.get(buf, "map_flags"),
                       bool(lo.get(buf, "frozen")), data)
