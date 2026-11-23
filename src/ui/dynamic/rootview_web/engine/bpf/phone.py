"""Phones, through rvtools.Bpf: every read is an adb round trip, so they skip
rvtools.ebpf's cgroup walk."""

from __future__ import annotations

from typing import Any

from rootview_web.engine.bpf.schema import bpf_map, kind
from rootview_web.schemas import AttachPoint, BpfMap, BpfProgram, BpfProgType

try:
    from rootview.rvtools import Bpf
except ImportError:
    Bpf = None


def program(p: Any) -> BpfProgram:
    prog_type = kind(BpfProgType, p.type, "BPF_PROG_TYPE_")
    holder = p.holders[0] if p.holders else (None, None)
    return BpfProgram(
        prog_id=p.id,
        name=p.name,
        prog_type=prog_type,
        helpers=list(p.helpers),
        attach_points=[AttachPoint(kind=prog_type, target=t) for t in p.attach],
        loader_uid=p.uid,
        loader_pid=holder[0],
        loader_comm=holder[1],
        tag=p.tag.hex(),
        jited=p.jited,
        bytes_xlated=p.insns * 8,
        bytes_jited=p.jited_len,
        map_ids=list(p.map_ids),
    )


def read(g: Any) -> tuple[list[BpfProgram], list[BpfMap]]:
    bpf = Bpf(g)
    with g.snapshot():
        progs, maps = bpf.programs(), bpf.maps()
    return [program(p) for p in progs], [bpf_map(m) for m in maps]
