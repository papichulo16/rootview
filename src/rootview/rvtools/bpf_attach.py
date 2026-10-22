"""Where eBPF programs are attached, and which processes hold them."""

from __future__ import annotations

from collections import defaultdict

from rootview.rvprim import Guest, RootviewError
from rootview.rvtools.common import printable, qwords, read_u32, read_u64

ARRAY_MAX = 64
FDS_MAX = 4096


def cstr(g: Guest, va: int, n: int = 128) -> str:
    if not va:
        return ""
    try:
        return printable(g.read(va, n))
    except RootviewError:
        return printable(g.read(va, 0x1000 - (va & 0xFFF)))


class Attachments:
    def __init__(self, g: Guest) -> None:
        self.g = g
        off = lambda t, p: g.field(t, p).offset
        self.ev_class, self.ev_name = off("trace_event_call", "class"), off("trace_event_call", "name")
        self.ev_flags, self.ev_progs = off("trace_event_call", "flags"), off("trace_event_call", "prog_array")
        self.class_system, self.tp_name = off("trace_event_class", "system"), off("tracepoint", "name")
        self.items, self.item_size = off("bpf_prog_array", "items"), g.type_size("bpf_prog_array_item")
        self.tp_flag = g.enum_value("TRACE_EVENT_FL_TRACEPOINT")
        self.files, self.fdt = off("task_struct", "files"), off("files_struct", "fdt")
        self.max_fds, self.fd = off("fdtable", "max_fds"), off("fdtable", "fd")
        self.f_op, self.private = off("file", "f_op"), off("file", "private_data")
        self.link_prog = off("bpf_link", "prog")
        self.perf_prog, self.perf_event = off("perf_event", "prog"), off("perf_event", "tp_event")
        self.fops = {g.sym("bpf_prog_fops"): "prog", g.sym("bpf_link_fops"): "link", g.sym("perf_fops"): "perf"}

    def event_name(self, ev: int) -> str:
        g = self.g
        name = read_u64(g, ev + self.ev_name)
        if read_u32(g, ev + self.ev_flags) & self.tp_flag:
            name = read_u64(g, name + self.tp_name)
        system = cstr(g, read_u64(g, read_u64(g, ev + self.ev_class) + self.class_system))
        return f"{system}:{cstr(g, name)}"

    def trace_events(self) -> dict[int, list[str]]:
        g, out = self.g, defaultdict(list)
        for ev in g.list(g.sym("ftrace_events"), "trace_event_call", "list"):
            array = read_u64(g, ev + self.ev_progs)
            if not array:
                continue
            for i in range(ARRAY_MAX):
                prog = read_u64(g, array + self.items + i * self.item_size)
                if not prog:
                    break
                out[prog].append(self.event_name(ev))
        return out

    def holders(self) -> tuple[dict[int, list[tuple[int, str]]], dict[int, list[str]]]:
        held, attached, seen = defaultdict(list), defaultdict(list), set()
        for t in self.g.tasks():
            try:
                files = read_u64(self.g, t.addr + self.files)
                if not files or files in seen:
                    continue
                seen.add(files)
                for prog, event in self._fds(files):
                    if (t.pid, t.comm) not in held[prog]:
                        held[prog].append((t.pid, t.comm))
                    if event:
                        attached[prog].append(self.event_name(event))
            except RootviewError:
                continue
        return held, attached

    def _fds(self, files: int):
        g = self.g
        fdt = read_u64(g, files + self.fdt)
        count = min(read_u32(g, fdt + self.max_fds), FDS_MAX)
        for file in qwords(g.read(read_u64(g, fdt + self.fd), 8 * count)):
            kind = self.fops.get(read_u64(g, file + self.f_op)) if file else None
            if kind is None:
                continue
            private = read_u64(g, file + self.private)
            if kind == "prog":
                yield private, 0
            elif kind == "link":
                yield read_u64(g, private + self.link_prog), 0
            elif prog := read_u64(g, private + self.perf_prog):
                yield prog, read_u64(g, private + self.perf_event)
