"""rootview.rvprim against a real guest (see conftest.py)."""

from __future__ import annotations

import pytest

from rootview import rvprim
from rootview.rvprim import RootviewError


def test_list_vms_returns_store_entries(guest):
    for vm in rvprim.list_vms():
        assert vm.name
        assert not (vm.kvmi and not vm.running)


def test_unknown_vm_raises_rootview_error(guest):
    with pytest.raises(RootviewError):
        rvprim.Guest("no-such-vm-rootview-test")


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


def test_bad_field_raises_rootview_error(guest):
    with pytest.raises(RootviewError, match="no_such_member"):
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
    with pytest.raises(RootviewError, match="more than 2"):
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
    with pytest.raises(RootviewError):
        guest.percpu_addr("runqueues", n)


def test_events_start_empty(guest):
    guest.poll(0)
    events, dropped = guest.events()
    assert dropped == 0
    assert all(e.name for e in events)


# ---- the primitives rvtools builds on ----


def test_symbols_sorted_and_sym_at(guest):
    syms = guest.symbols()
    assert len(syms) == guest.info().nsyms
    assert all(a.addr <= b.addr for a, b in zip(syms, syms[1:]))
    init_task = guest.sym("init_task")
    sym, off = guest.sym_at(init_task + 8)
    assert (sym.name, sym.addr, off) == ("init_task", init_task, 8)
    with pytest.raises(RootviewError, match="kernel image"):
        guest.sym_at(0x1000)


def test_types_and_enums(guest):
    assert guest.type_size("module") == guest.type_size("struct module") > 0
    assert guest.type_size("rb_node") == 24
    assert guest.enum_value("PIDTYPE_PID", "pid_type") == 0
    assert guest.enum_value("PIDTYPE_PID") == 0  # found without naming the enum
    with pytest.raises(RootviewError):
        guest.enum_value("NO_SUCH_ENUMERATOR_ROOTVIEW")
    assert guest.enum_name("pid_type", 0) == guest.enum_name("enum pid_type", 0) == "PIDTYPE_PID"
    with pytest.raises(RootviewError):
        guest.enum_name("pid_type", 1000)


def test_registers_point_into_the_kernel(guest):
    sym, _ = guest.sym_at(guest.reg("msr_lstar"))
    assert sym.name.startswith("entry_SYSCALL_64")
    with pytest.raises(RootviewError, match="unknown register"):
        guest.reg("no_such_reg")


def test_idtr_maps_idt_table(guest):
    with guest.snapshot():
        assert guest.translate(guest.reg("idtr_base")) == guest.translate(guest.sym("idt_table"))


def test_read_phys_matches_read(guest):
    banner = guest.sym("linux_banner")
    with guest.snapshot():
        pa = guest.translate(banner)
        assert guest.read_phys(pa, 14) == guest.read(banner, 14) == b"Linux version "


def test_syscall_table_points_into_the_image(guest):
    lo, hi = guest.info().image
    table = guest.read(guest.sym("sys_call_table"), 8 * 64)
    for nr in range(64):
        target = int.from_bytes(table[8 * nr : 8 * nr + 8], "little")
        assert lo <= target < hi, f"syscall {nr} -> {target:#x}"


def test_pid_links_through_hlist_off(guest):
    tasks = guest.tasks()
    task = next(t for t in tasks if t.pid == 1)
    pid = guest.read_field("task_struct", "thread_pid", task.addr).value
    head = pid + guest.field("pid", "tasks").offset  # tasks[PIDTYPE_PID]
    links = guest.field("task_struct", "pid_links").offset  # pid_links[PIDTYPE_PID]
    assert task.addr in guest.hlist_off(head, links)


def test_mod_tree_matches_module_list(guest):
    with guest.snapshot():
        listed = set(guest.list(guest.sym("modules"), "module", "list"))
        root = guest.sym("mod_tree") + guest.field("mod_tree_root", "root.tree").offset  # tree[0]
        node = guest.field("mod_tree_node", "node").offset  # node[0], the one tree[0] links
        mod = guest.field("mod_tree_node", "mod").offset
        in_tree = set()
        for rb in guest.rbtree(root):
            in_tree.add(int.from_bytes(guest.read(rb - node + mod, 8), "little"))
    assert listed and listed == in_tree
