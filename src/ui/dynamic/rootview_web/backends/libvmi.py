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
        # a phone's kernel release, from its last scan: describing it must not
        # wait behind a scan that holds the phone for minutes
        self._phone_release: dict[str, str | None] = {}

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
        vms = [await self._describe(v) for v in await self.pool.vm(self.pool.prim.list_vms)]
        return vms + await self._phones()

    async def get_vm(self, vm_id: str) -> VM:
        for vm in await self.list_vms():
            if vm.vm_id == vm_id:
                return vm
        raise UnknownVMError(f"no guest named {vm_id!r}")

    async def snapshot(self, vm_id: str) -> BpfSnapshot:
        vm = await self.get_vm(vm_id)
        if vm.state is not VMState.RUNNING:
            return BpfSnapshot(vm_id=vm_id)
        def read(g):
            if vm.kind == "phone":
                self._phone_release[vm_id] = _release(g)
            return bpf.read(g, self.pool.profile_errors.get(vm_id))

        progs, maps = await self.pool.guest(vm_id, read)
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


    async def _phones(self) -> list[VM]:
        """Phones on adb, as guests. No adb is no phones, not an error."""
        try:
            phones = await self.pool.vm(self.pool.prim.list_phones)
        except BackendError:
            return []
        return [self._describe_phone(p) for p in phones]

    def _describe_phone(self, p) -> VM:
        name = f"{p.model or p.product or 'phone'} ({p.serial})"
        if not (p.connected and p.pkvmi):
            return VM(vm_id=p.serial, name=name, state=VMState.UNREACHABLE, kind="phone")
        # attaching a phone builds its profile over adb (~30s), so listing never
        # does it: the first scan attaches, and the profile shows from then on
        release = self._phone_release.get(p.serial) if self.pool.attached(p.serial) is not None else None
        guest = GuestInfo(kernel_release=release, architecture="arm64", profile_loaded=release is not None)
        return VM(vm_id=p.serial, name=name, state=VMState.RUNNING, guest=guest, kind="phone")


def _release(g) -> str | None:
    return g.info().release if g.profiled else None
