"""Loaded eBPF programs and maps, through prog_idr and map_idr."""

from __future__ import annotations

from dataclasses import dataclass

from rootview.rvprim import Guest, RootviewError
from rootview.rvtools.bpf_attach import Attachments, cstr
from rootview.rvtools.bpf_helpers import Helpers
from rootview.rvtools.common import Layout, qwords, read_u32


@dataclass(frozen=True)
class Prog:
    addr: int
    id: int
    name: str
    type: str  # bpf_prog_type's enumerator, e.g. BPF_PROG_TYPE_KPROBE
    tag: bytes
    jited: bool
    insns: int
    jited_len: int
    map_ids: tuple[int, ...]
    helpers: tuple[str, ...] = ()
    attach: tuple[str, ...] = ()
    uid: int | None = None
    holders: tuple[tuple[int, str], ...] = ()


@dataclass(frozen=True)
class Map:
    addr: int
    id: int
    name: str
    type: str
    key_size: int
    value_size: int
    max_entries: int


class Bpf:
    def __init__(self, g: Guest) -> None:
        self.g = g
        self.prog = Layout(g, "bpf_prog", "tag", "jited", "len", "jited_len", "aux")
        self.aux = Layout(g, "bpf_prog_aux", "id", "name", "used_map_cnt", "used_maps", "user")
        self.uid = g.field("user_struct", "uid.val").offset
        try:
            self.attach_func = g.field("bpf_prog_aux", "attach_func_name").offset
        except RootviewError:
            self.attach_func = None
        self.map = Layout(g, "bpf_map", "id", "name", "key_size", "value_size", "max_entries")

    def programs(self) -> list[Prog]:
        progs = self.g.idr("prog_idr")
        if not progs:
            return []
        attach = Attachments(self.g)
        events = attach.trace_events()
        held, perf = attach.holders()
        helpers = Helpers(self.g)
        return [self._prog(addr, helpers, events[addr] + perf[addr], held[addr]) for _, addr in progs]

    def maps(self) -> list[Map]:
        return [self._map(addr) for _, addr in self.g.idr("map_idr")]

    def _prog(self, addr: int, helpers: Helpers, attach: list[str], held: list[tuple[int, str]]) -> Prog:
        g, prog, aux = self.g, self.prog, self.aux
        p = prog.read(g, addr)
        aux_va = prog.get(p, "aux")
        a = aux.read(g, aux_va)
        user = aux.get(a, "user")
        if self.attach_func is not None:
            func = cstr(g, int.from_bytes(g.read(aux_va + self.attach_func, 8), "little"))
            attach = attach + [func] if func else attach
        cnt = aux.get(a, "used_map_cnt")
        used = qwords(g.read(aux.get(a, "used_maps"), 8 * cnt)) if cnt else ()
        return Prog(
            addr=addr,
            id=aux.get(a, "id"),
            name=aux.get(a, "name"),
            type=g.read_field("bpf_prog", "type", addr).enum_name or "",
            tag=prog.get(p, "tag"),
            jited=bool(prog.get(p, "jited")),
            insns=prog.get(p, "len"),
            jited_len=prog.get(p, "jited_len"),
            map_ids=tuple(g.read_field("bpf_map", "id", m).value for m in used),
            helpers=helpers.of(addr, prog.get(p, "len")),
            attach=tuple(dict.fromkeys(attach)),
            uid=read_u32(g, user + self.uid) if user else None,
            holders=tuple(sorted(held)),
        )

    def _map(self, addr: int) -> Map:
        g, layout = self.g, self.map
        m = layout.read(g, addr)
        return Map(
            addr=addr,
            id=layout.get(m, "id"),
            name=layout.get(m, "name"),
            type=g.read_field("bpf_map", "map_type", addr).enum_name or "",
            key_size=layout.get(m, "key_size"),
            value_size=layout.get(m, "value_size"),
            max_entries=layout.get(m, "max_entries"),
        )
