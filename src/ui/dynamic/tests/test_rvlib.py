"""librootview.so through the ctypes bindings, against a real guest.

Skipped unless the library loads (``make lib`` at the repo root) and a guest
is up: ``ROOTVIEW_TEST_VM`` names it, otherwise the first running vm with a
kvmi socket is used. Building the profile pauses the guest briefly.
"""

from __future__ import annotations

import os

import pytest

from rootview_web.backends.base import BackendError

rvlib = pytest.importorskip("rootview_web.backends.rvlib")

try:
    rvlib.lib()
except BackendError as e:
    pytest.skip(f"librootview.so not loadable: {e}", allow_module_level=True)


def _guest_name() -> str | None:
    if name := os.environ.get("ROOTVIEW_TEST_VM"):
        return name
    return next((v.name for v in rvlib.list_vms() if v.running and v.kvmi), None)


@pytest.fixture(scope="module")
def guest():
    name = _guest_name()
    if name is None:
        pytest.skip("no running kvmi guest (set ROOTVIEW_TEST_VM)")
    with rvlib.Guest(name) as g:
        yield g


def test_list_vms_returns_store_entries():
    for vm in rvlib.list_vms():
        assert vm.name
        assert not (vm.kvmi and not vm.running)


def test_unknown_vm_raises_backend_error():
    with pytest.raises(BackendError):
        rvlib.Guest("no-such-vm-rootview-test")


def test_info(guest):
    info = guest.info()
    assert info.release
    assert info.release in info.banner
    assert info.version[0] >= 4
    assert info.image[0] < info.image[1]
    assert info.nsyms > 10000
    assert info.btf_types > 1000


def test_tasks_include_init(guest):
    tasks = guest.tasks()
    assert tasks
    pids = {t.pid for t in tasks}
    assert 1 in pids
    assert len(pids) == len(tasks)
    assert all(t.comm for t in tasks)


def test_field_resolves(guest):
    f = guest.field("task_struct", "pid")
    assert f.kind == "s"
    assert f.size == 4


def test_read_field_init_task_comm(guest):
    v = guest.read_field("task_struct", "comm", guest.info().init_task)
    assert v.kind == "cstr"
    assert v.value == "swapper/0"


def test_read_matches_read_field(guest):
    init_task = guest.info().init_task
    f = guest.field("task_struct", "comm")
    raw = guest.read(init_task + f.offset, f.size)
    assert raw.split(b"\0", 1)[0] == b"swapper/0"


def test_bad_field_raises_backend_error(guest):
    with pytest.raises(BackendError, match="no_such_member"):
        guest.field("task_struct", "no_such_member")



def test_list_matches_tasks(guest):
    init_task = guest.info().init_task
    off = guest.field("task_struct", "tasks").offset
    with guest.snapshot():
        addrs = guest.list(init_task + off, "task_struct", "tasks")
        tasks = guest.tasks()  # inside the caller's window: no second pause
    assert addrs == [t.addr for t in tasks]


def test_list_node_cap_raises(guest):
    off = guest.field("task_struct", "tasks").offset
    with pytest.raises(BackendError, match="more than 2"):
        guest.list(guest.info().init_task + off, "task_struct", "tasks", max=2)


def test_pid_idr_covers_tasks(guest):
    ns = guest.sym("init_pid_ns")
    entries = guest.idr(ns + guest.field("pid_namespace", "idr").offset)
    ids = [i for i, _ in entries]
    assert ids == sorted(ids)
    assert {t.pid for t in guest.tasks()} <= set(ids)


def test_prog_idr_ids_match_their_progs(guest):
    progs = guest.idr("prog_idr")
    for prog_id, prog in progs:
        aux = guest.read_field("bpf_prog", "aux", prog).value
        assert guest.read_field("bpf_prog_aux", "id", aux).value == prog_id
    for map_id, m in guest.idr("map_idr"):
        assert guest.read_field("bpf_map", "id", m).value == map_id


def test_percpu_runqueues(guest):
    n = guest.nr_cpus()
    assert n >= 1
    for cpu in range(n):
        rq = guest.percpu_addr("runqueues", cpu)
        curr = guest.read_field("rq", "curr", rq).value
        assert guest.read_field("task_struct", "comm", curr).value
    with pytest.raises(BackendError):
        guest.percpu_addr("runqueues", n)


def test_events_start_empty(guest):
    guest.poll(0)
    events, dropped = guest.events()
    assert dropped == 0
    assert all(e.name for e in events)
