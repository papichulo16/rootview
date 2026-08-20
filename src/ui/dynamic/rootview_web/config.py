"""Runtime configuration, read from the environment.

Kept to plain stdlib so the scaffold has no settings library to install. Every
value is overridable with a ``ROOTVIEW_``-prefixed environment variable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    """Web server settings."""

    #: Which introspection backend to use. "none" until an engine is connected;
    #: the interface then reports that it is not reading any guest.
    backend: str = "none"

    #: Seconds between detection passes over each guest. VMI reads are not free
    #: and the guest keeps running while we walk its memory, so this trades
    #: detection latency against overhead on the host.
    scan_interval: float = 5.0

    host: str = "127.0.0.1"
    port: int = 8000

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            backend=os.environ.get("ROOTVIEW_BACKEND", cls.backend),
            scan_interval=_env_float("ROOTVIEW_SCAN_INTERVAL", cls.scan_interval),
            host=os.environ.get("ROOTVIEW_HOST", cls.host),
            port=int(os.environ.get("ROOTVIEW_PORT", cls.port)),
        )
