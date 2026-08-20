"""The polling loop that drives the live dashboard.

VMI is pull-based: nothing in the guest tells us a program was loaded, so
RootView scans on an interval and reports what changed. This service owns that
loop, remembers which findings have already been reported, and publishes only
new ones to the event bus.
"""

from __future__ import annotations

import asyncio
import logging

from rootview_web.backends.base import BackendError, IntrospectionBackend
from rootview_web.events import Event, EventBus
from rootview_web.schemas import Detection, ScanResult, VMState

log = logging.getLogger(__name__)


class ScannerService:
    """Scans every running guest on an interval and publishes new detections."""

    def __init__(
        self,
        backend: IntrospectionBackend,
        bus: EventBus,
        interval: float = 5.0,
    ) -> None:
        self.backend = backend
        self.bus = bus
        self.interval = interval
        # Detection ids already announced, so a finding that persists across
        # scans does not re-alert every interval. Detection ids are
        # deterministic (see rootview_web.detection) which is what makes this
        # work.
        self._reported: set[str] = set()
        self._latest: dict[str, ScanResult] = {}
        self._task: asyncio.Task[None] | None = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def has_results(self) -> bool:
        """Whether any scan has completed since startup.

        The interface needs this to avoid showing an all-clear before anything
        has actually been examined.
        """
        return bool(self._latest)

    def latest(self, vm_id: str) -> ScanResult | None:
        """Most recent scan result for a guest, if one has completed."""
        return self._latest.get(vm_id)

    def all_detections(self) -> list[Detection]:
        """Every currently-standing detection across all guests."""
        out: list[Detection] = []
        for result in self._latest.values():
            out.extend(result.detections)
        return out

    def forget(self) -> None:
        """Drop remembered results so standing findings alert again.

        Used when the backend is swapped out, and by tests.
        """
        self._reported.clear()
        self._latest.clear()

    async def scan_once(self) -> list[ScanResult]:
        """Run one pass over every running guest, publishing what is new."""
        results = []
        try:
            vms = await self.backend.list_vms()
        except (BackendError, NotImplementedError) as exc:
            # NotImplementedError is expected while a backend is still being
            # written: the server stays up and says so instead of crash-looping.
            log.warning("could not list guests: %s", exc)
            self.bus.publish(Event.status(f"Backend error listing guests: {exc}", level="error"))
            return results

        for vm in vms:
            if vm.state is not VMState.RUNNING:
                continue
            try:
                result = await self.backend.scan(vm.vm_id)
            except (BackendError, NotImplementedError) as exc:
                # One unreadable guest must not stop the others from being
                # scanned, so this is logged and reported rather than raised.
                log.warning("scan of %s failed: %s", vm.vm_id, exc)
                self.bus.publish(
                    Event.status(f"Scan of {vm.name} failed: {exc}", level="error", vm_id=vm.vm_id)
                )
                continue

            self._latest[vm.vm_id] = result
            results.append(result)
            for detection in result.detections:
                if detection.detection_id in self._reported:
                    continue
                self._reported.add(detection.detection_id)
                self.bus.publish(Event.detection(detection))
            self.bus.publish(Event.scan(result))
        return results

    async def _loop(self) -> None:
        while True:
            try:
                await self.scan_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                # The loop is the only thing keeping the dashboard live; an
                # unexpected error in one pass must not kill it permanently.
                log.exception("unexpected error during scan pass")
            await asyncio.sleep(self.interval)

    async def start(self) -> None:
        if self.running:
            return
        try:
            await self.backend.startup()
        except (BackendError, NotImplementedError) as exc:
            # A backend that cannot start is reported, not fatal. The web server
            # still serves every page, and the interface shows that it is not
            # reading any guest.
            log.warning("backend failed to start: %s", exc)
            self.bus.publish(Event.status(f"Backend failed to start: {exc}", level="error"))
        self._task = asyncio.create_task(self._loop(), name="rootview-scanner")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        try:
            await self.backend.shutdown()
        except (BackendError, NotImplementedError) as exc:
            log.warning("backend failed to shut down cleanly: %s", exc)
