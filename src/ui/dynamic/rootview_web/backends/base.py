"""The seam between the web server and the introspection engine.

Everything above this interface is web code. Everything below it is LibVMI
walking guest page tables. The web server never imports LibVMI directly, so the
UI can be built and tested against any implementation of this interface while
the real engine is still being written.

The interface is deliberately pull-based. VMI reads guest memory on demand;
there is no callback from the guest kernel to subscribe to. RootView therefore
polls: :class:`~rootview_web.services.ScannerService` calls :meth:`scan` on an
interval and turns the differences into a live event stream for the browser.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from rootview_web.schemas import BpfSnapshot, ScanResult, VM


class BackendError(RuntimeError):
    """Raised when introspection fails.

    Expected in normal operation -- the guest may be paused, the kernel profile
    may not match, or a page may not be resident -- so callers should surface
    these to the user rather than treat them as crashes.
    """


class UnknownVMError(BackendError):
    """Raised when a vm_id does not correspond to a guest the backend knows."""


class IntrospectionBackend(ABC):
    """What the web server needs from the introspection engine."""

    @property
    def connected(self) -> bool:
        """Whether this backend can actually read a guest.

        The interface uses this to distinguish "scanned, found nothing" from
        "not scanning at all". Those must never look the same to the user: one
        is an all-clear, the other is no information.
        """
        return True

    @abstractmethod
    async def list_vms(self) -> list[VM]:
        """Return every guest this backend can introspect."""

    @abstractmethod
    async def get_vm(self, vm_id: str) -> VM:
        """Return one guest. Raises :class:`UnknownVMError` if it is not known."""

    @abstractmethod
    async def snapshot(self, vm_id: str) -> BpfSnapshot:
        """Read the guest's current eBPF program and map state.

        This is the raw introspection result with no detection logic applied.
        """

    @abstractmethod
    async def scan(self, vm_id: str) -> ScanResult:
        """Take a snapshot and run the detection rules over it."""

    async def startup(self) -> None:
        """Acquire resources. Called once when the web server starts."""

    async def shutdown(self) -> None:
        """Release resources. Called once when the web server stops."""
