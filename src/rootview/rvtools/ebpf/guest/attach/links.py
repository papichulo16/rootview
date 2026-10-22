"""bpf_link objects: every link in link_idr, the program it holds, and what
it attaches that program to.

Each link type embeds struct bpf_link at the start of its own struct, which
says where the program is attached. Raw tracepoint, tracing (fentry, fexit,
fmod_ret, LSM, freplace), cgroup and XDP links are decoded; any other type
is reported with an empty target.
"""

from __future__ import annotations

from collections.abc import Callable

from rootview.rvprim import Guest
from rootview.rvtools.common import Layout, is_kernel_va, read_cstr, read_u64
from rootview.rvtools.ebpf.guest.attach.attachment import Attachment
from rootview.rvtools.ebpf.guest.attach.cgroups import Cgroups


class Links:
    def __init__(self, g: Guest, cgroups: Cgroups | None = None) -> None:
        self.g = g
        self.cgroups = cgroups
        self.link = Layout(g, "bpf_link", "id", "prog")
        self._offs: dict[tuple[str, str], int] = {}
        self.decoders: dict[str, Callable[[int, int], tuple[str, str]]] = {
            "BPF_LINK_TYPE_RAW_TRACEPOINT": self._raw_tp,
            "BPF_LINK_TYPE_TRACING": self._tracing,
            "BPF_LINK_TYPE_CGROUP": self._cgroup,
            "BPF_LINK_TYPE_XDP": self._xdp,
        }

    def link_idr(self) -> list[int]:
        """Every link with an ID: what bpftool link list walks."""
        return [link for _, link in self.g.idr("link_idr")]

    def attachment(self, link: int) -> Attachment:
        buf = self.link.read(self.g, link)
        prog = self.link.get(buf, "prog")
        v = self.g.read_field("bpf_link", "type", link)
        kind = v.enum_name or str(v.value)
        decode = self.decoders.get(kind)
        attach_type, target = decode(link, prog) if decode else ("", "")
        return Attachment(prog, "link", attach_type, target, self.link.get(buf, "id"), kind)

    def all(self) -> list[Attachment]:
        return [self.attachment(link) for link in self.link_idr()]

    def _off(self, type: str, path: str) -> int:
        if (type, path) not in self._offs:
            self._offs[type, path] = self.g.field(type, path).offset
        return self._offs[type, path]

    def _ptr(self, base: int, type: str, path: str) -> int:
        return read_u64(self.g, base + self._off(type, path))

    def _raw_tp(self, link: int, prog: int) -> tuple[str, str]:
        btp = self._ptr(link, "bpf_raw_tp_link", "btp")
        tp = self._ptr(btp, "bpf_raw_event_map", "tp")
        return "", read_cstr(self.g, self._ptr(tp, "tracepoint", "name"))

    def _tracing(self, link: int, prog: int) -> tuple[str, str]:
        v = self.g.read_field("bpf_tracing_link", "attach_type", link)
        name = self._ptr(self._ptr(prog, "bpf_prog", "aux"), "bpf_prog_aux", "attach_func_name")
        return v.enum_name or str(v.value), read_cstr(self.g, name) if is_kernel_va(name) else ""

    def _cgroup(self, link: int, prog: int) -> tuple[str, str]:
        v = self.g.read_field("bpf_cgroup_link", "type", link)
        cgroup = self._ptr(link, "bpf_cgroup_link", "cgroup")
        self.cgroups = self.cgroups or Cgroups(self.g)
        return v.enum_name or str(v.value), self.cgroups.path(cgroup) if is_kernel_va(cgroup) else ""

    def _xdp(self, link: int, prog: int) -> tuple[str, str]:
        dev = self._ptr(link, "bpf_xdp_link", "dev")
        return "BPF_XDP", str(self.g.read_field("net_device", "name", dev).value) if is_kernel_va(dev) else ""
