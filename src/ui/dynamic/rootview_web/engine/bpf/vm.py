"""VMs, through rvtools.ebpf: every attachment source and every holder."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from rootview_web.engine.bpf.schema import bpf_map, kind
from rootview_web.schemas import AttachPoint, BpfMap, BpfProgram, BpfProgType

try:
    from rootview.rvtools.ebpf import Fds, Holders, Progs, Resolver, analyze, attachments
except ImportError:
    Progs = None

log = logging.getLogger(__name__)


def collect(g: Any) -> tuple[list, list, list, dict[int, list]]:
    """Programs, maps, attachments and holders, read in one pause."""
    progs, res = Progs(g), Resolver(g)
    with g.snapshot():
        programs = [analyze(progs, res, addr) for addr in progs.prog_idr()]
        maps = [res.maps.info(addr) for addr in res.maps.map_idr()]
        fds, unread = Fds(g).all()
        found, errors = attachments(g, fds)
        held = Holders(g).index(fds)
    for source, why in errors.items():
        log.warning("%s: %s attachments not read: %s", g.name, source, why)
    for pid, why in unread.items():
        log.warning("%s: pid %d's fds not read: %s", g.name, pid, why)
    return programs, maps, found, held


def target(a: Any) -> str:
    if a.target:
        return a.target
    if a.link_type:
        return f"{a.link_type.removeprefix('BPF_LINK_TYPE_').lower()} link {a.link}"
    return f"{a.source} event"


def program(p: Any, attached: list, held: list) -> BpfProgram:
    i = p.info
    prog_type = kind(BpfProgType, i.type, "BPF_PROG_TYPE_")
    holder = held[0] if held else None
    return BpfProgram(
        prog_id=i.id,
        name=i.name,
        prog_type=prog_type,
        tag=i.tag,
        loaded_at=i.loaded_at,
        loader_uid=i.uid,
        loader_pid=holder.pid if holder else None,
        loader_comm=holder.comm if holder else None,
        attach_points=[AttachPoint(kind=prog_type, target=t) for t in dict.fromkeys(map(target, attached))],
        map_ids=[m.id for m in p.maps],
        helpers=list(p.helpers),
        jited=i.jited,
        bytes_xlated=i.len * 8,
        bytes_jited=i.jited_len,
    )


def read(g: Any) -> tuple[list[BpfProgram], list[BpfMap]]:
    programs, maps, found, held = collect(g)
    where = defaultdict(list)
    for a in found:
        where[a.prog].append(a)
    progs = [program(p, where[p.info.addr], held.get(p.info.addr, [])) for p in programs]
    return progs, [bpf_map(m) for m in maps]
