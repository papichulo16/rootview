"""rvtools' eBPF records as the dashboard's schemas."""

from __future__ import annotations

from enum import Enum
from typing import Any, TypeVar

from rootview_web.backends.base import BackendError
from rootview_web.schemas import AttachPoint, BpfMap, BpfMapType, BpfProgram, BpfProgType

try:
    from rootview.rvtools import Bpf
except ImportError:
    Bpf = None

E = TypeVar("E", bound=Enum)


def _kind(enum: type[E], name: str, prefix: str) -> E:
    try:
        return enum(name.removeprefix(prefix).lower())
    except ValueError:
        return enum("unknown")


def program(p: Any) -> BpfProgram:
    prog_type = _kind(BpfProgType, p.type, "BPF_PROG_TYPE_")
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


def bpf_map(m: Any) -> BpfMap:
    return BpfMap(
        map_id=m.id,
        name=m.name,
        map_type=_kind(BpfMapType, m.type, "BPF_MAP_TYPE_"),
        key_size=m.key_size,
        value_size=m.value_size,
        max_entries=m.max_entries,
    )


def read(g: Any, profile_error: str | None) -> tuple[list[BpfProgram], list[BpfMap]]:
    if not g.profiled:
        raise BackendError(f"no kernel profile for {g.name}: {profile_error or 'unknown error'}")
    bpf = Bpf(g)
    with g.snapshot():
        progs, maps = bpf.programs(), bpf.maps()
    return [program(p) for p in progs], [bpf_map(m) for m in maps]
