"""The guest's clocks, as its timekeeper keeps them: CLOCK_BOOTTIME readings
(what the kernel stamps on objects) turned into the guest's wall-clock time.

The wall-clock time of boot is offs_real - offs_boot, read from
shadow_timekeeper: tk_core is an anonymous struct BTF can't lay out, and
the shadow copy is kept in step with it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from rootview.rvprim import Guest
from rootview.rvtools.common import Layout


class Clock:
    def __init__(self, g: Guest) -> None:
        self.g = g
        self.tk = g.sym("shadow_timekeeper")
        self.layout = Layout(g, "timekeeper", "offs_real", "offs_boot")

    def boot_ns(self) -> int:
        """When the guest booted, in ns since the epoch by its own clock."""
        buf = self.layout.read(self.g, self.tk)
        return self.layout.get(buf, "offs_real") - self.layout.get(buf, "offs_boot")

    def from_boot(self, ns: int) -> datetime:
        """A CLOCK_BOOTTIME reading as the guest's wall-clock time, in UTC."""
        sec, nsec = divmod(self.boot_ns() + ns, 10**9)
        return datetime.fromtimestamp(sec, timezone.utc) + timedelta(microseconds=nsec // 1000)
