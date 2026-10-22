"""Instructions as text, in the kernel's own syntax (kernel/bpf/disasm.c),
which is what ``bpftool prog dump xlated`` prints.

The kernel hands bpftool its programs with the internal opcodes turned back
into public ones (bpf_insn_prepare_dump); ``public()`` does the same here.
``call_name`` and ``imm_name`` stand in for disasm.c's callbacks: given an
instruction they name a call's target or an ld_imm64's value, or return None.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import replace

from rootview.rvtools.ebpf.isa import opcodes as op
from rootview.rvtools.ebpf.isa.insn import Insn

Namer = Callable[[Insn], str | None]

FUNC_TAIL_CALL = 12  # BPF_FUNC_tail_call
_U32 = 0xFFFFFFFF


def _none(_: Insn) -> None:
    return None


def public(i: Insn) -> Insn:
    """i as bpftool would receive it: tail calls, interpreted calls and
    PROBE_MEM loads in their public form."""
    if i.code == op.JMP | op.TAIL_CALL:
        return replace(i, code=op.JMP | op.CALL, imm=FUNC_TAIL_CALL)
    if i.code == op.JMP | op.CALL_ARGS:
        return replace(i, code=op.JMP | op.CALL)
    if i.cls == op.LDX and i.mode == op.PROBE_MEM:
        return replace(i, code=op.LDX | i.size | op.MEM)
    return i


def line(i: Insn, call_name: Namer = _none, imm_name: Namer = _none) -> str:
    i = public(i)
    c = f"({i.code:02x})"
    if i.cls in (op.ALU, op.ALU64):
        return f"{c} {_alu(i)}"
    if i.cls == op.STX:
        s = _stx(i)
        return f"{c} {s}" if s else f"BUG_{i.code:02x}"
    if i.cls == op.ST:
        if i.mode == op.MEM:
            return f"{c} *({op.SIZE_NAMES[i.size]} *)(r{i.dst} {i.off:+d}) = {i.imm}"
        return f"{c} nospec" if i.mode == op.NOSPEC else f"BUG_st_{i.code:02x}"
    if i.cls == op.LDX:
        names = {op.MEM: op.SIZE_NAMES, op.MEMSX: op.SIZE_NAMES_SX}.get(i.mode)
        if names is None:
            return f"BUG_ldx_{i.code:02x}"
        return f"{c} r{i.dst} = *({names.get(i.size, '?')} *)(r{i.src} {i.off:+d})"
    if i.cls == op.LD:
        if i.mode == op.ABS:
            return f"{c} r0 = *({op.SIZE_NAMES[i.size]} *)skb[{i.imm}]"
        if i.mode == op.IND:
            return f"{c} r0 = *({op.SIZE_NAMES[i.size]} *)skb[r{i.src} + {i.imm}]"
        if i.code == op.LD_IMM64:
            return f"{c} r{i.dst} = {imm_name(i) or _imm(i)}"
        return f"BUG_ld_{i.code:02x}"
    return f"{c} {_jmp(i, call_name)}"


def listing(insns: Iterable[Insn], call_name: Namer = _none, imm_name: Namer = _none) -> list[str]:
    """``bpftool prog dump xlated``, less line info: ``idx: text`` per instruction."""
    return [f"{i.idx:4d}: {line(i, call_name, imm_name)}" for i in insns]


def _alu(i: Insn) -> str:
    r = "w" if i.cls == op.ALU else "r"
    if i.op == op.END:
        if i.cls == op.ALU64:
            return f"r{i.dst} = bswap{i.imm} r{i.dst}"
        return f"r{i.dst} = {'be' if i.x else 'le'}{i.imm} r{i.dst}"
    if i.op == op.NEG:
        return f"{r}{i.dst} = -{r}{i.dst}"
    if i.code == op.ALU64 | op.MOV | op.X and i.off == op.ADDR_SPACE_CAST:
        return f"r{i.dst} = addr_space_cast(r{i.src}, {(i.imm & _U32) >> 16}, {i.imm & 0xFFFF})"
    if i.code == op.ALU64 | op.MOV | op.X and i.off == op.ADDR_PERCPU:
        return f"r{i.dst} = &(void __percpu *)(r{i.src})"
    sym = (i.off == 1 and op.ALU_SIGNED_OPS.get(i.op)) or op.ALU_OPS.get(i.op, "?")
    if i.x:
        sx = op.MOVSX.get(i.off, "") if i.op == op.MOV else ""
        return f"{r}{i.dst} {sym} {sx}{r}{i.src}"
    return f"{r}{i.dst} {sym} {i.imm}"


def _stx(i: Insn) -> str | None:
    at = f"({op.SIZE_NAMES[i.size]} *)(r{i.dst} {i.off:+d})"
    if i.mode == op.MEM:
        return f"*{at} = r{i.src}"
    if i.mode != op.ATOMIC:
        return None
    w = "64" if i.size == op.DW else ""
    if i.imm in op.ATOMIC_OPS:
        return f"lock *{at} {op.ALU_OPS[i.imm]} r{i.src}"
    if i.imm & op.FETCH and (i.imm & ~op.FETCH) in op.ATOMIC_OPS:
        return f"r{i.src} = atomic{w}_fetch_{op.ATOMIC_OPS[i.imm & ~op.FETCH]}({at}, r{i.src})"
    if i.imm == op.CMPXCHG:
        return f"r0 = atomic{w}_cmpxchg({at}, r0, r{i.src})"
    if i.imm == op.XCHG:
        return f"r{i.src} = atomic{w}_xchg({at}, r{i.src})"
    return None


def _imm(i: Insn) -> str:
    if i.src == op.PSEUDO_MAP_FD:
        return f"map[id:{i.imm & _U32}]"
    if i.src == op.PSEUDO_MAP_VALUE:
        return f"map[id:{i.imm & _U32}][0]+{i.imm2 & _U32}"
    if i.src == op.PSEUDO_MAP_IDX_VALUE:
        return f"map[idx:{i.imm & _U32}]+{i.imm2 & _U32}"
    if i.src == op.PSEUDO_FUNC:
        return f"subprog[{i.imm:+d}]"
    return f"{i.imm64:#x}"


def _jmp(i: Insn, call_name: Namer) -> str:
    r = "w" if i.cls == op.JMP32 else "r"
    if i.op == op.CALL:
        if i.src == op.PSEUDO_CALL:
            return f"call pc{call_name(i) or f'{i.imm:+d}'}"
        if i.src == op.PSEUDO_KFUNC_CALL:
            default = "kernel-function"
        else:
            default = "bpf_tail_call" if i.imm == FUNC_TAIL_CALL else "unknown"
        return f"call {call_name(i) or default}#{i.imm}"
    if i.code == op.JMP | op.JA:
        return f"goto pc{i.off:+d}"
    if i.code == op.JMP32 | op.JA:
        return f"gotol pc{i.imm:+d}"
    if i.code == op.JMP | op.EXIT:
        return "exit"
    sym = op.JMP_OPS.get(i.op, "?")
    if i.x:
        return f"if {r}{i.dst} {sym} {r}{i.src} goto pc{i.off:+d}"
    return f"if {r}{i.dst} {sym} {i.imm & _U32:#x} goto pc{i.off:+d}"
