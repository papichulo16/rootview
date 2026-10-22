"""A program's control-flow graph: basic blocks, edges, back edges (loops) and
blocks nothing reaches. Every subprogram a call enters is an entry of its
own, and calls stay inside a block.

Built from the instructions alone, so it holds for any program, verified or
not: a jump or call to a slot that isn't an instruction's first is kept as a
bad target instead of an edge.
"""

from __future__ import annotations

import bisect
from collections.abc import Sequence
from dataclasses import dataclass

from rootview.rvtools.ebpf.analysis.calls import SUBPROG, calls
from rootview.rvtools.ebpf.isa import opcodes as op
from rootview.rvtools.ebpf.isa.insn import Insn


@dataclass(frozen=True)
class Block:
    start: int  # first slot
    end: int  # one past the last slot
    succs: tuple[int, ...]  # successors' starts


@dataclass(frozen=True)
class Cfg:
    blocks: dict[int, Block]  # by start, in order
    entries: tuple[int, ...]  # slot 0 and each subprogram's first slot
    back_edges: tuple[tuple[int, int], ...]  # (block, the block it jumps back to)
    unreachable: tuple[int, ...]  # blocks no entry reaches
    bad_targets: tuple[tuple[int, int], ...]  # (jump or call slot, where it points)

    def subprog_of(self, slot: int) -> int:
        """The entry of the subprogram slot belongs to."""
        return self.entries[max(bisect.bisect_right(self.entries, slot) - 1, 0)]


def flow(i: Insn) -> tuple[int | None, bool]:
    """Where i can jump, and whether it can go on to the next instruction."""
    if i.cls == op.JMP:
        if i.op == op.JA:
            return i.idx + 1 + i.off, False
        if i.op == op.EXIT:
            return None, False
        if i.op in (op.CALL, op.CALL_ARGS, op.TAIL_CALL):
            return None, True
        return i.idx + 1 + i.off, True
    if i.cls == op.JMP32:
        if i.op == op.JA:
            return i.idx + 1 + i.imm, False
        return i.idx + 1 + i.off, True
    return None, True


def build(insns: Sequence[Insn], jited: bool = True) -> Cfg:
    if not insns:
        return Cfg({}, (), (), (), ())
    starts = {i.idx for i in insns}
    bad = []
    entries = {insns[0].idx}
    for c in calls(insns, jited):
        if c.kind == SUBPROG:
            if c.target in starts:
                entries.add(c.target)
            else:
                bad.append((c.idx, c.target))
    leaders = set(entries)
    for n, i in enumerate(insns):
        target, falls = flow(i)
        if target is not None:
            if target in starts:
                leaders.add(target)
            else:
                bad.append((i.idx, target))
        if (target is not None or not falls) and n + 1 < len(insns):
            leaders.add(insns[n + 1].idx)

    blocks: dict[int, Block] = {}
    first = 0
    for n, i in enumerate(insns):
        last = n + 1 == len(insns)
        target, falls = flow(i)
        if last or insns[n + 1].idx in leaders:
            succs = [target] if target in starts else []
            if falls and not last:
                succs.append(insns[n + 1].idx)
            start = insns[first].idx
            blocks[start] = Block(start, i.idx + i.slots, tuple(dict.fromkeys(succs)))
            first = n + 1

    seen, back = _walk(blocks, sorted(entries))
    return Cfg(blocks, tuple(sorted(entries)), tuple(back), tuple(s for s in blocks if s not in seen),
               tuple(sorted(bad)))


def _walk(blocks: dict[int, Block], entries: list[int]) -> tuple[set[int], list[tuple[int, int]]]:
    """Depth-first from each entry: the blocks reached, and the edges that
    lead back to a block still on the path."""
    state: dict[int, bool] = {}  # True while on the path
    back = []
    for e in entries:
        if e in state:
            continue
        state[e] = True
        path = [(e, iter(blocks[e].succs))]
        while path:
            node, succs = path[-1]
            nxt = next(succs, None)
            if nxt is None:
                state[node] = False
                path.pop()
            elif nxt not in state:
                state[nxt] = True
                path.append((nxt, iter(blocks[nxt].succs)))
            elif state[nxt]:
                back.append((node, nxt))
    return set(state), back
