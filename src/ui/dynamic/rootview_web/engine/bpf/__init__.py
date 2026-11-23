"""rvtools' eBPF records as the dashboard's schemas.

  schema   enum names and maps, shared by both readers
  vm       VMs, through rvtools.ebpf
  phone    phones, through rvtools.Bpf
"""

from __future__ import annotations

from typing import Any

from rootview_web.backends.base import BackendError
from rootview_web.engine.bpf import phone, vm
from rootview_web.schemas import BpfMap, BpfProgram


def read(g: Any, profile_error: str | None, is_phone: bool = False) -> tuple[list[BpfProgram], list[BpfMap]]:
    if not g.profiled:
        raise BackendError(f"no kernel profile for {g.name}: {profile_error or 'unknown error'}")
    return (phone if is_phone else vm).read(g)
