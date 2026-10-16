"""The real backend: librootview through the rootview package."""

from __future__ import annotations

from datetime import datetime, timezone

from rootview_web.backends.base import BackendError, IntrospectionBackend, UnknownVMError
from rootview_web.detection import run_rules
from rootview_web.engine import GuestPool, bpf
from rootview_web.schemas import BpfSnapshot, GuestInfo, ScanResult, VM, VMState


class LibVMIBackend(IntrospectionBackend):
    def __init__(self, pool: GuestPool | None = None) -> None:
        self.pool = pool or GuestPool()

    @property
    def connected(self) -> bool:
        return self.pool.ready

    async def startup(self) -> None:
        await self.pool.start()

    async def shutdown(self) -> None:
        await self.pool.close()

    async def list_vms(self) -> list[VM]:
        if not self.pool.ready:
            raise BackendError("introspection engine is not running")
        return [await self._describe(v) for v in await self.pool.vm(self.pool.prim.list_vms)]

    async def get_vm(self, vm_id: str) -> VM:
        for vm in await self.list_vms():
            if vm.vm_id == vm_id:
                return vm
        raise UnknownVMError(f"no guest named {vm_id!r}")

    async def snapshot(self, vm_id: str) -> BpfSnapshot:
        vm = await self.get_vm(vm_id)
        if vm.state is not VMState.RUNNING:
            return BpfSnapshot(vm_id=vm_id)
        progs, maps = await self.pool.guest(vm_id, lambda g: bpf.read(g, self.pool.profile_errors.get(vm_id)))
        return BpfSnapshot(vm_id=vm_id, programs=progs, maps=maps)

    async def scan(self, vm_id: str) -> ScanResult:
        started = datetime.now(timezone.utc)
        snap = await self.snapshot(vm_id)
        return ScanResult(
            vm_id=vm_id,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            detections=run_rules(snap),
            programs_examined=len(snap.programs),
            maps_examined=len(snap.maps),
        )

    async def _describe(self, v) -> VM:
        if not v.running:
            return VM(vm_id=v.name, name=v.name, state=VMState.SHUT_OFF)
        if not v.kvmi:
            return VM(vm_id=v.name, name=v.name, state=VMState.UNREACHABLE)
        try:
            release = await self.pool.guest(v.name, _release)
        except BackendError:
            return VM(vm_id=v.name, name=v.name, state=VMState.UNREACHABLE)
        guest = GuestInfo(kernel_release=release, architecture="x86_64", profile_loaded=release is not None)
        return VM(vm_id=v.name, name=v.name, state=VMState.RUNNING, guest=guest)


def _release(g) -> str | None:
    return g.info().release if g.profiled else None
