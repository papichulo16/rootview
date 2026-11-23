"""Programs attached to perf events a process holds open: what
PERF_EVENT_IOC_SET_BPF leaves, and what bpftool perf lists. A kprobe or uprobe
made through its PMU, as libbpf does, and not held by a link is only found
here."""

from __future__ import annotations

from collections.abc import Iterable

from rootview.rvprim import Guest
from rootview.rvtools.common import is_kernel_va, read_u64
from rootview.rvtools.ebpf.guest.attach.attachment import Attachment
from rootview.rvtools.ebpf.guest.attach.events import Events
from rootview.rvtools.ebpf.guest.fds import PERF, Fd


class Perf:
    def __init__(self, g: Guest, events: Events | None = None) -> None:
        self.g = g
        self.events = events or Events(g)
        self.prog = g.field("perf_event", "prog").offset
        self.tp_event = g.field("perf_event", "tp_event").offset

    def target(self, event: int) -> str:
        """The trace event a perf event is, "" for any other kind."""
        call = read_u64(self.g, event + self.tp_event)
        return self.events.name(call) if is_kernel_va(call) else ""

    def attachments(self, fds: Iterable[Fd]) -> list[Attachment]:
        """The programs on the perf events among fds, each event once."""
        out, seen = [], set()
        for f in fds:
            if f.kind != PERF or f.obj in seen:
                continue
            seen.add(f.obj)
            prog = read_u64(self.g, f.obj + self.prog)
            if is_kernel_va(prog):
                out.append(Attachment(prog, "perf", "", self.target(f.obj)))
        return out
