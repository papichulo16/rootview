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
from rootview_web.schemas import Detection, ScanResult, VM, VMState

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
        # the loop's per-guest scans still in flight, so a slow guest is skipped
        # rather than queued up again
        self._busy: dict[str, asyncio.Task[None]] = {}

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

    async def _running_guests(self) -> list[VM]:
        try:
            vms = await self.backend.list_vms()
        except (BackendError, NotImplementedError) as exc:
            # NotImplementedError is expected while a backend is still being
            # written: the server stays up and says so instead of crash-looping.
            log.warning("could not list guests: %s", exc)
            self.bus.publish(Event.status(f"Backend error listing guests: {exc}", level="error"))
            return []
        return [vm for vm in vms if vm.state is VMState.RUNNING]

    async def _scan_guest(self, vm: VM) -> ScanResult | None:
        try:
            result = await self.backend.scan(vm.vm_id)
        except (BackendError, NotImplementedError) as exc:
            # One unreadable guest must not stop the others from being
            # scanned, so this is logged and reported rather than raised.
            log.warning("scan of %s failed: %s", vm.vm_id, exc)
            self.bus.publish(Event.status(f"Scan of {vm.name} failed: {exc}", level="error", vm_id=vm.vm_id))
            return None

        self._latest[vm.vm_id] = result
        for detection in result.detections:
            if detection.detection_id in self._reported:
                continue
            self._reported.add(detection.detection_id)
            self.bus.publish(Event.detection(detection))
        self.bus.publish(Event.scan(result))
        return result

    async def scan_once(self) -> list[ScanResult]:
        """Run one pass over every running guest, publishing what is new."""
        results = []
        for vm in await self._running_guests():
            result = await self._scan_guest(vm)
            if result is not None:
                results.append(result)
        return results

    async def _scan_logged(self, vm: VM) -> None:
        try:
            await self._scan_guest(vm)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("unexpected error scanning %s", vm.vm_id)

    async def _loop(self) -> None:
        # Every guest scans on its own task, so a slow one (a phone over adb
        # takes minutes) never holds up the rest. One still being scanned is
        # skipped until it finishes.
        while True:
            try:
                for vm in await self._running_guests():
                    busy = self._busy.get(vm.vm_id)
                    if busy is None or busy.done():
                        self._busy[vm.vm_id] = asyncio.create_task(self._scan_logged(vm), name=f"scan-{vm.vm_id}")
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
        for busy in self._busy.values():
            busy.cancel()
        await asyncio.gather(*self._busy.values(), return_exceptions=True)
        self._busy.clear()
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
