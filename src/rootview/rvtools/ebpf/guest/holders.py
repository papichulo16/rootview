"""Which processes hold each eBPF program or map: by an fd to it, to a link
holding the program, or to a perf event the program is attached to.

The kernel keeps no record of who loaded a program; a holder is only who has
it open now. bpftool's pids are the holders by a prog or map fd.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from rootview.rvprim import Guest
from rootview.rvtools.common import is_kernel_va, read_u64
from rootview.rvtools.ebpf.guest.fds import LINK, PERF, Fd


@dataclass(frozen=True)
class Holder:
    pid: int
    comm: str
    fd: int  # the first fd the process holds it by
    via: str  # what that fd is: prog, link, map or perf


class Holders:
    def __init__(self, g: Guest) -> None:
        self.g = g
        self.link_prog = g.field("bpf_link", "prog").offset
        self.perf_prog = g.field("perf_event", "prog").offset

    def index(self, fds: Iterable[Fd]) -> dict[int, list[Holder]]:
        """struct bpf_prog or bpf_map -> the processes holding it, by pid."""
        found: dict[int, dict[int, Holder]] = defaultdict(dict)
        for f in fds:
            obj = self.held(f)
            if is_kernel_va(obj):
                found[obj].setdefault(f.pid, Holder(f.pid, f.comm, f.fd, f.kind))
        return {obj: sorted(by_pid.values(), key=lambda h: h.pid) for obj, by_pid in found.items()}

    def held(self, f: Fd) -> int:
        """The program or map an fd keeps loaded, 0 for none."""
        if f.kind == LINK:
            return read_u64(self.g, f.obj + self.link_prog)
        if f.kind == PERF:
            return read_u64(self.g, f.obj + self.perf_prog)
        return f.obj
