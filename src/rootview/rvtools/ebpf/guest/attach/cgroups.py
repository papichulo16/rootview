"""Programs attached to cgroups: each cgroup on the default hierarchy keeps
its attached programs in bpf.progs, one list per attach type.

A program attached through a bpf_cgroup_link sits on the same list with
prog NULL and the link set, so it is found here and in link_idr both.
"""

from __future__ import annotations

from rootview.rvprim import Guest, RootviewError
from rootview.rvtools.common import Layout, is_kernel_va, qwords, read_cstr, read_u32, read_u64
from rootview.rvtools.ebpf.guest.attach.attachment import Attachment

MAX_CGROUPS = 65536
MAX_DEPTH = 64


class Cgroups:
    def __init__(self, g: Guest) -> None:
        self.g = g
        self.root = g.sym("cgrp_dfl_root") + g.field("cgroup_root", "cgrp").offset
        self.cg = Layout(g, "cgroup", "self.children", "self.sibling", "kn", "bpf.progs", "bpf.flags")
        self.kn = Layout(g, "kernfs_node", "name", "parent")
        self.pl = Layout(g, "bpf_prog_list", "node", "prog", "link")
        self.link_id = g.field("bpf_link", "id").offset
        self.link_prog = g.field("bpf_link", "prog").offset
        progs, flags = self.cg.fields["bpf.progs"], self.cg.fields["bpf.flags"]
        self.types = flags.size // 4
        self.head = progs.size // self.types  # 16 for a list_head, 8 for the hlist_head of 6.x
        self._names: dict[int, str] = {}

    def walk(self) -> list[int]:
        """Every cgroup on the default hierarchy, root first."""
        g, cg = self.g, self.cg
        out, todo = [], [self.root]
        while todo:
            c = todo.pop()
            out.append(c)
            if len(out) > MAX_CGROUPS:
                raise RootviewError(f"more than {MAX_CGROUPS} cgroups")
            todo += reversed(g.list_off(c + cg.off("self.children"), cg.off("self.sibling")))
        return out

    def path(self, cgroup: int) -> str:
        """The cgroup's path below the cgroup2 mount, "/" for the root."""
        g, kn = self.g, self.kn
        names = []
        node = read_u64(g, cgroup + self.cg.off("kn"))
        for _ in range(MAX_DEPTH):
            if not is_kernel_va(node):
                break
            buf = kn.read(g, node)
            parent = kn.get(buf, "parent")
            if is_kernel_va(parent):
                names.append(read_cstr(g, kn.get(buf, "name")))
            node = parent
        return "/" + "/".join(reversed(names))

    def attachments(self, cgroup: int) -> list[Attachment]:
        """The programs attached to one cgroup."""
        g, cg, pl = self.g, self.cg, self.pl
        base = cgroup + cg.off("bpf.progs")
        firsts = qwords(g.read(base, self.types * self.head))[:: self.head // 8]
        flags = g.read(cgroup + cg.off("bpf.flags"), 4 * self.types)
        walk = g.list_off if self.head == 16 else g.hlist_off
        out, path = [], None
        for i, first in enumerate(firsts):
            head = base + i * self.head
            if first in (0, head):
                continue
            path = path or self.path(cgroup)
            for node in walk(head, pl.off("node")):
                buf = pl.read(g, node)
                prog, link = pl.get(buf, "prog"), pl.get(buf, "link")
                link_id = link_type = None
                if is_kernel_va(link):
                    prog = prog or read_u64(g, link + self.link_prog)
                    link_id, link_type = read_u32(g, link + self.link_id), "BPF_LINK_TYPE_CGROUP"
                out.append(Attachment(prog, "cgroup", self._type(i), path, link_id, link_type,
                                      int.from_bytes(flags[4 * i:4 * i + 4], "little")))
        return out

    def all(self) -> list[Attachment]:
        return [a for c in self.walk() for a in self.attachments(c)]

    def _type(self, i: int) -> str:
        """bpf.progs[i]'s attach type: cgroup_bpf_attach_type since 5.15, which
        is enum bpf_attach_type's name less its BPF_ prefix."""
        if i not in self._names:
            try:
                self._names[i] = "BPF_" + self.g.enum_name("cgroup_bpf_attach_type", i)
            except RootviewError:
                try:
                    self._names[i] = self.g.enum_name("bpf_attach_type", i)
                except RootviewError:
                    self._names[i] = str(i)
        return self._names[i]
