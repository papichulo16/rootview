"""Where loaded programs are attached, read from each structure that records it.

  attachment   Attachment: one program attached somewhere
  cgroups      Cgroups: each cgroup's attached programs, per attach type
  links        Links: link_idr, and what each bpf_link attaches to
  events       Events: each trace event's prog_array, and its system:event name
  perf         Perf: the programs on perf events processes hold open

``attachments()`` runs every source; a program found through more than one
(a cgroup link, a tracepoint's perf event) is reported by each.
"""

from __future__ import annotations

from rootview.rvprim import Guest, RootviewError
from rootview.rvtools.ebpf.guest.attach.attachment import Attachment
from rootview.rvtools.ebpf.guest.attach.cgroups import Cgroups
from rootview.rvtools.ebpf.guest.attach.events import Events
from rootview.rvtools.ebpf.guest.attach.links import Links
from rootview.rvtools.ebpf.guest.attach.perf import Perf
from rootview.rvtools.ebpf.guest.fds import Fd, Fds

SOURCES = ("cgroup", "link", "event", "perf")


def attachments(g: Guest, fds: list[Fd] | None = None) -> tuple[list[Attachment], dict[str, str]]:
    """Every attachment each source finds, and source -> why it failed.
    fds is what Fds(g).all() found, walked here when not given. Run it
    inside g.snapshot()."""
    found: list[Attachment] = []
    errors: dict[str, str] = {}
    cgroups = events = perf = None
    try:
        cgroups = Cgroups(g)
        found += cgroups.all()
    except RootviewError as e:
        errors["cgroup"] = str(e)
    try:
        events = Events(g)
        found += events.all()
    except RootviewError as e:
        errors["event"] = str(e)
    try:
        perf = Perf(g, events)
        if fds is None:
            fds, unread = Fds(g).all()
            if unread:
                pid, why = next(iter(unread.items()))
                errors["perf"] = f"{len(unread)} fd tables unread, pid {pid}: {why}"
        found += perf.attachments(fds)
    except RootviewError as e:
        errors["perf"] = str(e)
    try:
        found += Links(g, cgroups, perf).all()
    except RootviewError as e:
        errors["link"] = str(e)
    return found, errors


__all__ = ["SOURCES", "Attachment", "Cgroups", "Events", "Links", "Perf", "attachments"]
