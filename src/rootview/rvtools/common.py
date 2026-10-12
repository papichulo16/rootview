"""Small building blocks the other tools share: attaching, struct decoding,
symbol lookups by range, and reading raw values."""

from __future__ import annotations

import bisect
import struct

from rootview.rvprimitives import Guest, RootviewError, Symbol, list_vms

# what list_del leaves in next/prev: ILLEGAL_POINTER_VALUE + 0x100 / + 0x122
LIST_POISON1 = 0xDEAD000000000100
LIST_POISON2 = 0xDEAD000000000122


def attach(vm: str | None = None) -> Guest:
    """A Guest for vm, or for the first running guest started with kvmi."""
    if vm is None:
        vm = next((v.name for v in list_vms() if v.running and v.kvmi), None)
        if vm is None:
            raise RootviewError("no running kvmi guest")
    return Guest(vm)


def is_kernel_va(va: int) -> bool:
    """A canonical upper-half address under 4-level paging."""
    return va >> 47 == 0x1FFFF


def read_u64(g: Guest, va: int) -> int:
    return int.from_bytes(g.read(va, 8), "little")


def read_u32(g: Guest, va: int) -> int:
    return int.from_bytes(g.read(va, 4), "little")


def qwords(buf: bytes) -> tuple[int, ...]:
    return struct.unpack(f"<{len(buf) // 8}Q", buf[: len(buf) // 8 * 8])


def printable(raw: bytes) -> str:
    """A C string out of raw bytes: cut at the NUL, non-printables as '?'."""
    raw = raw.split(b"\0", 1)[0]
    return "".join(chr(c) if 0x20 <= c < 0x7F else "?" for c in raw)


class Layout:
    """One struct's fields, resolved once through BTF and decoded from bytes.

    Read the whole struct once with ``g.read(addr, layout.size)``, then pull
    fields out of the buffer: one guest read per struct, not per field.
    """

    def __init__(self, g: Guest, type: str, *paths: str) -> None:
        self.type = type
        self.size = g.type_size(type)
        self.fields = {p: g.field(type, p) for p in paths}

    def off(self, path: str) -> int:
        return self.fields[path].offset

    def read(self, g: Guest, addr: int) -> bytes:
        return g.read(addr, self.size)

    def get(self, buf: bytes, path: str) -> int | str | bytes:
        f = self.fields[path]
        raw = buf[f.offset : f.offset + f.size]
        if f.kind == "cstr":
            return printable(raw)
        if f.kind == "bytes":
            return raw
        v = int.from_bytes(raw, "little")
        if f.bit_size:
            v = (v >> f.bit_off) & ((1 << f.bit_size) - 1)
        bits = f.bit_size or 8 * f.size
        if f.kind == "s" and v >> (bits - 1):
            v -= 1 << bits
        return v


class Symbols:
    """kallsyms with bisection, for range questions sym()/sym_at() don't answer."""

    def __init__(self, g: Guest) -> None:
        self.syms = g.symbols()
        self.addrs = [s.addr for s in self.syms]
        self.image = g.info().image
        self.stext, self.etext = g.sym("_stext"), g.sym("_etext")

    def at(self, va: int) -> tuple[Symbol | None, int]:
        """The last symbol at or below va, inside the core image only."""
        if not self.image[0] <= va < self.image[1]:
            return None, 0
        i = bisect.bisect_right(self.addrs, va)
        return (self.syms[i - 1], va - self.addrs[i - 1]) if i else (None, 0)

    def next_after(self, va: int) -> int:
        """The first symbol address above va, or 0."""
        i = bisect.bisect_right(self.addrs, va)
        return self.addrs[i] if i < len(self.addrs) else 0

    def in_text(self, va: int) -> bool:
        return self.stext <= va < self.etext

    def name(self, va: int) -> str:
        """``symbol+off`` for printing, or ``""`` outside the image."""
        s, off = self.at(va)
        return "" if not s else f"{s.name}+{off:#x}" if off else s.name
