"""The open files that are eBPF objects or perf events, read from every
process's fd table and told apart by their file_operations."""

from __future__ import annotations

from dataclasses import dataclass

from rootview.rvprim import Guest, RootviewError
from rootview.rvtools.common import Layout, is_kernel_va, qwords, read_u64
from rootview.rvtools.tasks import Tasks

PROG, LINK, MAP, PERF = "prog", "link", "map", "perf"
FOPS = {"bpf_prog_fops": PROG, "bpf_link_fops": LINK, "bpf_link_fops_poll": LINK, "bpf_map_fops": MAP,
        "perf_fops": PERF}
MAX_FDS = 1 << 20  # fs.nr_open's default


@dataclass(frozen=True)
class Fd:
    pid: int  # the process's tgid
    comm: str  # its group leader's
    fd: int
    kind: str  # prog, link, map or perf
    obj: int  # file->private_data: the struct bpf_prog, bpf_link, bpf_map or perf_event


class Fds:
    def __init__(self, g: Guest, tasks: Tasks | None = None) -> None:
        self.g = g
        self.tasks = tasks or Tasks(g)
        self.files = g.field("task_struct", "files").offset
        self.fdt = g.field("files_struct", "fdt").offset
        self.table = Layout(g, "fdtable", "max_fds", "fd")
        self.f_op = g.field("file", "f_op").offset
        self.private = g.field("file", "private_data").offset
        self.fops = {}
        for sym, kind in FOPS.items():
            try:
                self.fops[g.sym(sym)] = kind
            except RootviewError:
                pass

    def all(self) -> tuple[list[Fd], dict[int, str]]:
        """Every process's eBPF and perf fds, each fd table once, and pid ->
        why its table couldn't be read. Run it inside g.snapshot()."""
        out: list[Fd] = []
        errors: dict[int, str] = {}
        seen: set[int] = set()
        for t in self.g.tasks():
            try:
                for thread in self.tasks.threads(t.addr):
                    files = read_u64(self.g, thread + self.files)
                    if is_kernel_va(files) and files not in seen:
                        seen.add(files)
                        out += [Fd(t.tgid, t.comm, fd, kind, obj) for fd, kind, obj in self.of(files)]
            except RootviewError as e:
                errors[t.tgid] = str(e)
        return out, errors

    def of(self, files: int) -> list[tuple[int, str, int]]:
        """One struct files_struct's eBPF and perf fds: (fd, kind, object)."""
        g, lo = self.g, self.table
        fdt = read_u64(g, files + self.fdt)
        buf = lo.read(g, fdt)
        n = lo.get(buf, "max_fds")
        if n > MAX_FDS:
            raise RootviewError(f"fdtable {fdt:#x}: max_fds {n}")
        out = []
        for fd, file in enumerate(qwords(g.read(lo.get(buf, "fd"), 8 * n))):
            kind = self.fops.get(read_u64(g, file + self.f_op)) if is_kernel_va(file) else None
            if kind:
                out.append((fd, kind, read_u64(g, file + self.private)))
        return out
