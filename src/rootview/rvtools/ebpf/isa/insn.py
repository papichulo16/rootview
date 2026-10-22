"""struct bpf_insn, decoded. Each is one 8-byte slot except ld_imm64, which
takes two; jump offsets count slots, so every Insn keeps its slot index."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from rootview.rvtools.ebpf.isa import opcodes as op

SLOT = 8
_U32 = 0xFFFFFFFF


@dataclass(frozen=True)
class Insn:
    idx: int  # slot index
    code: int
    dst: int
    src: int
    off: int
    imm: int
    imm2: int = 0  # ld_imm64: the second slot's imm

    @property
    def cls(self) -> int:
        return self.code & 0x07

    @property
    def op(self) -> int:
        return self.code & 0xF0

    @property
    def x(self) -> bool:
        return bool(self.code & op.X)

    @property
    def size(self) -> int:
        return self.code & 0x18

    @property
    def mode(self) -> int:
        return self.code & 0xE0

    @property
    def slots(self) -> int:
        return 2 if self.code == op.LD_IMM64 else 1

    @property
    def imm64(self) -> int:
        return (self.imm2 & _U32) << 32 | (self.imm & _U32)


def decode(raw: bytes) -> list[Insn]:
    """Every instruction in raw, a whole number of slots."""
    if len(raw) % SLOT:
        raise ValueError(f"{len(raw)} bytes is not a whole number of {SLOT}-byte slots")
    slots = list(struct.iter_unpack("<BBhi", raw))
    out, i = [], 0
    while i < len(slots):
        code, regs, off, imm = slots[i]
        if code == op.LD_IMM64:
            if i + 1 == len(slots):
                raise ValueError(f"ld_imm64 at slot {i} has no second slot")
            out.append(Insn(i, code, regs & 0xF, regs >> 4, off, imm, slots[i + 1][3]))
            i += 2
        else:
            out.append(Insn(i, code, regs & 0xF, regs >> 4, off, imm))
            i += 1
    return out
