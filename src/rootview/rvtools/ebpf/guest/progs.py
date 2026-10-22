"""Loaded eBPF programs, read out of the guest: each struct bpf_prog, its
bpf_prog_aux, and its instructions as the verifier left them.

A minimal reader on top of rvprim's walks and BTF fields; kern/obj's
readers can take its place behind the same ProgInfo.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from rootview.rvprim import Guest, RootviewError
from rootview.rvtools.clock import Clock
from rootview.rvtools.common import Layout, is_kernel_va, printable, qwords, read_cstr, read_u32, read_u64
from rootview.rvtools.ebpf.isa.insn import SLOT

# the kernel's own caps: BPF_COMPLEXITY_LIMIT_INSNS, MAX_USED_MAPS, BPF_MAX_SUBPROGS
MAX_INSNS = 1_000_000
MAX_MAPS = 64
MAX_FUNCS = 256


@dataclass(frozen=True)
class ProgInfo:
    addr: int  # the struct bpf_prog
    aux: int
    id: int
    name: str
    type: str  # enum bpf_prog_type, e.g. BPF_PROG_TYPE_KPROBE
    attach_type: str  # enum bpf_attach_type
    tag: str  # hex
    len: int  # instruction slots
    jited: bool
    jited_len: int
    bpf_func: int  # the JIT image's entry
    ksym: str  # the JIT image's kallsyms name, "" if not JITed
    gpl: bool
    kprobe_override: bool  # it calls bpf_override_return
    stack_depth: int
    load_time: int  # ns since boot
    loaded_at: datetime | None  # load_time by the guest's wall clock, UTC
    uid: int | None  # the loader's
    attach_func: str | None  # a tracing or LSM program's target
    maps: tuple[int, ...]  # aux->used_maps: struct bpf_map addresses
    funcs: tuple[int, ...]  # aux->func: each subprogram's own struct bpf_prog


class Progs:
    def __init__(self, g: Guest) -> None:
        self.g = g
        self.prog = Layout(g, "bpf_prog", "jited", "gpl_compatible", "kprobe_override", "type",
                           "expected_attach_type", "len", "jited_len", "tag", "bpf_func", "aux")
        self.aux = Layout(g, "bpf_prog_aux", "id", "name", "used_map_cnt", "used_maps", "func_cnt", "func",
                          "stack_depth", "load_time", "attach_func_name", "user", "ksym.name")
        self.insns_off = g.field("bpf_prog", "insnsi").offset
        self.uid_off = g.field("user_struct", "uid.val").offset
        self.clock: Clock | None = None

    def prog_idr(self) -> list[int]:
        """Every program with an ID: what bpftool prog list walks."""
        return [p for _, p in self.g.idr("prog_idr")]

    def info(self, addr: int) -> ProgInfo:
        g, p, a = self.g, self.prog, self.aux
        pb = p.read(g, addr)
        aux = p.get(pb, "aux")
        if not is_kernel_va(aux):
            raise RootviewError(f"bpf_prog {addr:#x}: aux is {aux:#x}")
        n = p.get(pb, "len")
        if n > MAX_INSNS:
            raise RootviewError(f"bpf_prog {addr:#x}: {n} instructions")
        ab = a.read(g, aux)
        return ProgInfo(
            addr=addr,
            aux=aux,
            id=a.get(ab, "id"),
            name=a.get(ab, "name"),
            type=self._enum("type", addr),
            attach_type=self._enum("expected_attach_type", addr),
            tag=p.get(pb, "tag").hex(),
            len=n,
            jited=bool(p.get(pb, "jited")),
            jited_len=p.get(pb, "jited_len"),
            bpf_func=p.get(pb, "bpf_func"),
            ksym=a.get(ab, "ksym.name"),
            gpl=bool(p.get(pb, "gpl_compatible")),
            kprobe_override=bool(p.get(pb, "kprobe_override")),
            stack_depth=a.get(ab, "stack_depth"),
            load_time=a.get(ab, "load_time"),
            loaded_at=self._loaded_at(a.get(ab, "load_time")),
            uid=self._uid(a.get(ab, "user")),
            attach_func=self._string(a.get(ab, "attach_func_name")),
            maps=self._array(a.get(ab, "used_maps"), a.get(ab, "used_map_cnt"), MAX_MAPS, "used_maps"),
            funcs=self._array(a.get(ab, "func"), a.get(ab, "func_cnt"), MAX_FUNCS, "func"),
        )

    def insns(self, info: ProgInfo) -> bytes:
        return self.g.read(info.addr + self.insns_off, SLOT * info.len)

    def ksym(self, prog: int) -> str:
        """A program's or subprogram's JIT image name, as kallsyms shows it."""
        aux = read_u64(self.g, prog + self.prog.off("aux"))
        if not is_kernel_va(aux):
            raise RootviewError(f"bpf_prog {prog:#x}: aux is {aux:#x}")
        f = self.aux.fields["ksym.name"]
        return printable(self.g.read(aux + f.offset, f.size))

    def _enum(self, path: str, addr: int) -> str:
        v = self.g.read_field("bpf_prog", path, addr)
        return v.enum_name or str(v.value)

    def _array(self, ptr: int, count: int, cap: int, what: str) -> tuple[int, ...]:
        if not count:
            return ()
        if count > cap or not is_kernel_va(ptr):
            raise RootviewError(f"{what}: {count} entries at {ptr:#x}")
        return qwords(self.g.read(ptr, 8 * count))

    def _loaded_at(self, ns: int) -> datetime | None:
        try:
            self.clock = self.clock or Clock(self.g)
            return self.clock.from_boot(ns)
        except RootviewError:
            return None

    def _uid(self, user: int) -> int | None:
        if not is_kernel_va(user):
            return None
        try:
            return read_u32(self.g, user + self.uid_off)
        except RootviewError:
            return None

    def _string(self, ptr: int) -> str | None:
        if not is_kernel_va(ptr):
            return None
        try:
            return read_cstr(self.g, ptr)
        except RootviewError:
            return None
