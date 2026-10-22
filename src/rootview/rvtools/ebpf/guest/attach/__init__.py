"""Where loaded programs are attached, read from each structure that records it.

  attachment   Attachment: one program attached somewhere
  cgroups      Cgroups: each cgroup's attached programs, per attach type
  links        Links: link_idr, and what each bpf_link attaches to

``attachments()`` runs every source; a program attached through a cgroup
link is reported by both.
"""

from __future__ import annotations

from rootview.rvprim import Guest, RootviewError
from rootview.rvtools.ebpf.guest.attach.attachment import Attachment
from rootview.rvtools.ebpf.guest.attach.cgroups import Cgroups
from rootview.rvtools.ebpf.guest.attach.links import Links

SOURCES = ("cgroup", "link")


def attachments(g: Guest) -> tuple[list[Attachment], dict[str, str]]:
    """Every attachment each source finds, and source -> why it failed.
    Run it inside g.snapshot()."""
    found: list[Attachment] = []
    errors: dict[str, str] = {}
    cgroups = None
    try:
        cgroups = Cgroups(g)
        found += cgroups.all()
    except RootviewError as e:
        errors["cgroup"] = str(e)
    try:
        found += Links(g, cgroups).all()
    except RootviewError as e:
        errors["link"] = str(e)
    return found, errors


__all__ = ["SOURCES", "Attachment", "Cgroups", "Links", "attachments"]
