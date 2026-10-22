"""Call sites: helpers, kfuncs, BPF-to-BPF calls and tail calls.

In a loaded program a helper or kfunc call's imm is its target's address
minus __bpf_call_base, and a tail call has its own opcode. A BPF-to-BPF call
keeps its relative offset in off once the program is JITed (imm is then the
callee's subprogram index), in imm if it was left to the interpreter.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from rootview.rvtools.ebpf.isa import opcodes as op
from rootview.rvtools.ebpf.isa.insn import Insn

HELPER, KFUNC, SUBPROG, TAIL_CALL = "helper", "kfunc", "subprog", "tail_call"


@dataclass(frozen=True)
class Call:
    idx: int
    kind: str
    imm: int
    target: int | None = None  # SUBPROG: the callee's first slot


def calls(insns: Iterable[Insn], jited: bool = True) -> list[Call]:
    out = []
    for i in insns:
        if i.code == op.JMP | op.TAIL_CALL:
            out.append(Call(i.idx, TAIL_CALL, i.imm))
        elif i.code == op.JMP | op.CALL_ARGS:
            out.append(Call(i.idx, SUBPROG, i.imm, i.idx + 1 + i.off))
        elif i.code == op.JMP | op.CALL:
            if i.src == op.PSEUDO_CALL:
                out.append(Call(i.idx, SUBPROG, i.imm, i.idx + 1 + (i.off if jited else i.imm)))
            else:
                out.append(Call(i.idx, KFUNC if i.src == op.PSEUDO_KFUNC_CALL else HELPER, i.imm))
    return out
