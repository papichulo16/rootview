"""Shared test fixtures.

The guest data below is deliberately confined to the test suite. The shipped
package contains no fabricated guests, programs or findings: anything the
interface displays has to have come from a real introspection backend.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from rootview_web.app import create_app
from rootview_web.backends.base import IntrospectionBackend, UnknownVMError
from rootview_web.config import Settings
from rootview_web.detection import run_rules
from rootview_web.schemas import (
    AttachPoint,
    BpfMap,
    BpfMapType,
    BpfProgram,
    BpfProgType,
    BpfSnapshot,
    GuestInfo,
    ScanResult,
    Visibility,
    VM,
    VMState,
)


def clean_snapshot(vm_id: str = "vm-1") -> BpfSnapshot:
    """A guest with ordinary, benign eBPF state."""
    return BpfSnapshot(
        vm_id=vm_id,
        programs=[
            BpfProgram(
                prog_id=1,
                name="net_filter",
                prog_type=BpfProgType.XDP,
                tag="1111222233334444",
                loader_uid=0,
                loader_pid=900,
                loader_comm="loader",
                attach_points=[AttachPoint(kind=BpfProgType.XDP, target="eth0")],
                map_ids=[2],
                helpers=["bpf_map_lookup_elem"],
                visibility=Visibility.VISIBLE,
            )
        ],
        maps=[
            BpfMap(
                map_id=2,
                name="counters",
                map_type=BpfMapType.ARRAY,
                key_size=4,
                value_size=8,
                max_entries=64,
                visibility=Visibility.VISIBLE,
            )
        ],
    )


def compromised_snapshot(vm_id: str = "vm-1") -> BpfSnapshot:
    """The clean guest plus a program the guest kernel refuses to report."""
    snap = clean_snapshot(vm_id)
    snap.programs.append(
        BpfProgram(
            prog_id=99,
            name="concealed",
            prog_type=BpfProgType.TRACEPOINT,
            tag="9999888877776666",
            loader_uid=1000,
            loader_pid=None,
            loader_comm=None,
            attach_points=[AttachPoint(kind=BpfProgType.TRACEPOINT, target="sys_getdents64")],
            map_ids=[98],
            helpers=["bpf_probe_write_user"],
            pinned_path="/sys/fs/bpf/.hidden",
            visibility=Visibility.HIDDEN,
        )
    )
    snap.maps.append(
        BpfMap(
            map_id=98,
            name="hide_list",
            map_type=BpfMapType.HASH,
            key_size=32,
            value_size=4,
            max_entries=128,
            visibility=Visibility.HIDDEN,
        )
    )
    return snap


class FakeBackend(IntrospectionBackend):
    """An introspection backend that returns whatever snapshot it is handed."""

    def __init__(self, snapshot: BpfSnapshot | None = None) -> None:
        self.snapshot_to_return = snapshot or clean_snapshot()
        self._vms = {
            "vm-1": VM(
                vm_id="vm-1",
                name="test-guest",
                state=VMState.RUNNING,
                guest=GuestInfo(kernel_release="6.8.0", architecture="x86_64", profile_loaded=True),
            ),
            "vm-off": VM(vm_id="vm-off", name="powered-off-guest", state=VMState.SHUT_OFF),
        }

    async def list_vms(self) -> list[VM]:
        return list(self._vms.values())

    async def get_vm(self, vm_id: str) -> VM:
        try:
            return self._vms[vm_id]
        except KeyError:
            raise UnknownVMError(f"no such guest: {vm_id}") from None

    async def snapshot(self, vm_id: str) -> BpfSnapshot:
        vm = await self.get_vm(vm_id)
        if vm.state is not VMState.RUNNING:
            return BpfSnapshot(vm_id=vm_id)
        return self.snapshot_to_return.model_copy(update={"vm_id": vm_id}, deep=True)

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


def client_with(backend: IntrospectionBackend) -> TestClient:
    """A TestClient whose app uses the given backend."""
    app = create_app(Settings(backend="none", scan_interval=0.05))
    app.state.backend = backend
    app.state.scanner.backend = backend
    return TestClient(app)


@pytest.fixture
def clean_client():
    """A client backed by a guest with nothing suspicious on it."""
    with client_with(FakeBackend(clean_snapshot())) as c:
        yield c


@pytest.fixture
def compromised_client():
    """A client backed by a guest hiding an eBPF program."""
    with client_with(FakeBackend(compromised_snapshot())) as c:
        yield c


@pytest.fixture
def unconfigured_client():
    """A client with no introspection backend at all, which is the default."""
    with TestClient(create_app(Settings(backend="none", scan_interval=0.05))) as c:
        yield c
