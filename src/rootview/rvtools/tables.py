"""The kernel's dispatch tables, decoded: sys_call_table, the IDT, MSR_LSTAR,
and where any pointer lands (kernel text, a module, a symbol)."""

from __future__ import annotations

from dataclasses import dataclass

from rootview.rvprim import Guest
from rootview.rvtools.common import Symbols, qwords

TEXT_TYPES = "TtWw"  # kallsyms types of code symbols


@dataclass(frozen=True)
class Place:
    """Where an address points."""

    addr: int
    in_text: bool  # inside [_stext, _etext)
    symbol: str | None  # the core-kernel symbol it falls in
    offset: int  # into that symbol
    code_symbol: bool  # that symbol is a code symbol (T/t/W/w)
    module: str | None  # the module whose text holds it, when modules were given


@dataclass(frozen=True)
class Gate:
    """One present IDT gate."""

    vector: int
    va: int  # the descriptor's own address
    handler: int
    selector: int
    type: int  # 0xe interrupt gate, 0xf trap gate
    dpl: int
    ist: int


class Tables:
    def __init__(self, g: Guest, modules: dict[str, tuple[int, int]] | None = None) -> None:
        """modules: name -> (text base, text size), e.g. from rvtools.modules,
        for naming addresses that land in a module."""
        self.g = g
        self.syms = Symbols(g)
        self.modules = modules or {}

    def place(self, addr: int) -> Place:
        s, off = self.syms.at(addr)
        module = next((n for n, (b, sz) in self.modules.items() if b <= addr < b + sz), None)
        return Place(addr, self.syms.in_text(addr), s.name if s else None, off,
                     bool(s and s.type in TEXT_TYPES), module)

    def syscall_table(self) -> list[int]:
        """sys_call_table's entries, up to the first NULL. The table has no
        length in kallsyms or BTF, so it's capped by the next symbol."""
        sct = self.g.sym("sys_call_table")
        nxt = self.syms.next_after(sct)
        cap = min((nxt - sct) // 8, 1024) if nxt else 1024
        out = []
        for target in qwords(self.g.read(sct, 8 * cap)):
            if not target:
                break
            out.append(target)
        return out

    def idt(self) -> list[Gate]:
        """The present gates of the IDT vcpu 0's IDTR points at."""
        base = self.g.reg("idtr_base")
        raw = self.g.read(base, 256 * 16)
        out = []
        for v in range(256):
            d = raw[16 * v:16 * v + 16]
            if not d[5] & 0x80:
                continue
            handler = (int.from_bytes(d[0:2], "little") | int.from_bytes(d[6:8], "little") << 16
                       | int.from_bytes(d[8:12], "little") << 32)
            out.append(Gate(v, base + 16 * v, handler, int.from_bytes(d[2:4], "little"), d[5] & 0xF,
                            (d[5] >> 5) & 3, d[4] & 7))
        return out

    def idt_frames(self) -> tuple[int, int]:
        """The physical frames of IDTR's table and of idt_table. IDTR normally
        points at the cpu entry area's read-only alias of idt_table."""
        g = self.g
        return g.translate(g.reg("idtr_base")) >> 12, g.translate(g.sym("idt_table")) >> 12

    def lstar(self) -> int:
        """MSR_LSTAR on vcpu 0: the syscall entry point."""
        return self.g.reg("msr_lstar")
