"""The backend used when no introspection engine is connected.

RootView ships with no fabricated data. Until a real engine is wired up, this
backend reports honestly that it cannot see anything, and the interface says so
rather than showing an all-clear it has not earned.

It is not a stub that pretends to work: ``snapshot`` and ``scan`` raise, so any
caller that tries to use them gets a clear error instead of an empty result
that could be mistaken for "nothing suspicious found".
"""

from __future__ import annotations

from rootview_web.backends.base import BackendError, IntrospectionBackend, UnknownVMError
from rootview_web.schemas import BpfSnapshot, ScanResult, VM

#: Shown to the user wherever introspection was attempted without an engine.
MESSAGE = "No introspection backend is connected."


class UnconfiguredBackend(IntrospectionBackend):
    """Reports that RootView has nothing to introspect."""

    @property
    def connected(self) -> bool:
        return False

    async def list_vms(self) -> list[VM]:
        return []

    async def get_vm(self, vm_id: str) -> VM:
        raise UnknownVMError(MESSAGE)

    async def snapshot(self, vm_id: str) -> BpfSnapshot:
        raise BackendError(MESSAGE)

    async def scan(self, vm_id: str) -> ScanResult:
        raise BackendError(MESSAGE)
