"""What both readers share: kernel enum names as the dashboard's, and maps."""

from __future__ import annotations

from enum import Enum
from typing import Any, TypeVar

from rootview_web.schemas import BpfMap, BpfMapType

E = TypeVar("E", bound=Enum)


def kind(enum: type[E], name: str, prefix: str) -> E:
    try:
        return enum(name.removeprefix(prefix).lower())
    except ValueError:
        return enum("unknown")


def bpf_map(m: Any) -> BpfMap:
    return BpfMap(
        map_id=m.id,
        name=m.name,
        map_type=kind(BpfMapType, m.type, "BPF_MAP_TYPE_"),
        key_size=m.key_size,
        value_size=m.value_size,
        max_entries=m.max_entries,
    )
