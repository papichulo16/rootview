"""Programs attached to trace events: each trace_event_call on ftrace_events
keeps its programs in prog_array. Tracepoints and kprobe_events or
uprobe_events probes get there through a perf event, by
PERF_EVENT_IOC_SET_BPF or a perf link.

A kprobe or uprobe made through its PMU is never put on ftrace_events; perf
and the perf link decoder find those.
"""

from __future__ import annotations

from rootview.rvprim import Guest, RootviewError
from rootview.rvtools.common import Layout, is_kernel_va, read_cstr, read_u64
from rootview.rvtools.ebpf.guest.attach.attachment import Attachment

MAX_PROGS = 64  # BPF_TRACE_MAX_PROGS


class Events:
    def __init__(self, g: Guest) -> None:
        self.g = g
        self.call = Layout(g, "trace_event_call", "class", "name", "flags", "prog_array")
        self.system = g.field("trace_event_class", "system").offset
        self.tp_name = g.field("tracepoint", "name").offset
        self.tp_flag = g.enum_value("TRACE_EVENT_FL_TRACEPOINT")
        self.items = g.field("bpf_prog_array", "items").offset
        self.item = g.type_size("bpf_prog_array_item")
        try:
            self.dummy = g.sym("dummy_bpf_prog")
        except RootviewError:
            self.dummy = None

    def calls(self) -> list[int]:
        """Every registered trace event: what tracefs lists under events/."""
        return self.g.list(self.g.sym("ftrace_events"), "trace_event_call", "list")

    def name(self, call: int) -> str:
        """A trace event's system:event name."""
        g, lo = self.g, self.call
        buf = lo.read(g, call)
        name = lo.get(buf, "name")
        if lo.get(buf, "flags") & self.tp_flag:
            name = read_u64(g, name + self.tp_name)
        system = read_u64(g, lo.get(buf, "class") + self.system)
        return f"{self._str(system)}:{self._str(name)}"

    def progs(self, call: int) -> list[int]:
        """The programs on one event's prog_array."""
        g = self.g
        array = read_u64(g, call + self.call.off("prog_array"))
        out = []
        for i in range(MAX_PROGS if is_kernel_va(array) else 0):
            prog = read_u64(g, array + self.items + i * self.item)
            if not prog:
                break
            if prog != self.dummy:
                out.append(prog)
        return out

    def _str(self, ptr: int) -> str:
        return read_cstr(self.g, ptr) if is_kernel_va(ptr) else ""

    def all(self) -> list[Attachment]:
        out = []
        for call in self.calls():
            progs = self.progs(call)
            target = self.name(call) if progs else ""
            out += [Attachment(prog, "event", "", target) for prog in progs]
        return out
