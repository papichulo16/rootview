"""One program attached somewhere, as one source records it."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Attachment:
    prog: int  # the struct bpf_prog
    source: str  # the structure it was found through: "cgroup" or "link"
    attach_type: str  # enum bpf_attach_type, "" when it has none
    target: str  # cgroup path, tracepoint, kernel function, interface; "" if not decoded
    link: int | None = None  # the bpf_link's id, when attached through one
    link_type: str | None = None  # enum bpf_link_type
    flags: int = 0  # a cgroup attachment's BPF_F_ALLOW_OVERRIDE / BPF_F_ALLOW_MULTI
