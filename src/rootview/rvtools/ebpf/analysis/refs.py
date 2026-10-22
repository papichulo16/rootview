"""ld_imm64 sites: the 64-bit values a program loads, which is where its maps,
map values, kernel variables and function pointers show up.

A loaded program's map and map-value loads have had src cleared and hold a
kernel address, so they read as plain ``imm`` here; telling them from
constants takes the program's used_maps (guest/resolve.py).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from rootview.rvtools.ebpf.isa import opcodes as op
from rootview.rvtools.ebpf.isa.insn import Insn

KINDS = {
    0: "imm",
    op.PSEUDO_MAP_FD: "map_fd",
    op.PSEUDO_MAP_VALUE: "map_value",
    op.PSEUDO_BTF_ID: "btf_id",
    op.PSEUDO_FUNC: "func",
    op.PSEUDO_MAP_IDX: "map_idx",
    op.PSEUDO_MAP_IDX_VALUE: "map_idx_value",
}


@dataclass(frozen=True)
class Ref:
    idx: int
    dst: int
    kind: str
    value: int  # the full 64-bit immediate


def refs(insns: Iterable[Insn]) -> list[Ref]:
    return [Ref(i.idx, i.dst, KINDS.get(i.src, f"src{i.src}"), i.imm64) for i in insns if i.code == op.LD_IMM64]
