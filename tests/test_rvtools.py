"""rootview.rvtools against a real, clean guest (see conftest.py)."""

from __future__ import annotations

import time

import pytest

from rootview.rvprimitives import HookEvent
from rootview.rvtools import Ftrace, Layout, MemWatch, Modules, Symbols, Tables, Tasks
from rootview.rvtools import pagehash
from rootview.rvtools.modules import STATES


def test_layout_decodes_like_read_field(guest):
    lo = Layout(guest, "task_struct", "comm", "pid")
    buf = lo.read(guest, guest.info().init_task)
    assert lo.get(buf, "comm") == "swapper/0"
    assert lo.get(buf, "pid") == 0


def test_symbols_bisect(guest):
    syms = Symbols(guest)
    init = guest.sym("init_task")
    s, off = syms.at(init + 1)
    assert (s.name, off) == ("init_task", 1)
    assert syms.next_after(init) > init
    assert syms.at(0x1000) == (None, 0)


def test_task_sources(guest):
    tasks = Tasks(guest)
    found, errors = tasks.sources()
    assert not errors
    assert guest.info().init_task in found
    infos = {a: tasks.info(a) for a in found}
    # on a clean guest every task with a pid is in the pid idr, and every leader on the list
    for a, srcs in found.items():
        if infos[a].pid:
            assert "pid_idr" in srcs
            if infos[a].leader:
                assert "task_list" in srcs
    assert any(i.kthread for i in infos.values()) and any(not i.kthread for i in infos.values())


def test_module_sources_agree(guest):
    mods = Modules(guest)
    found, errors = mods.sources()
    assert found and not errors
    assert all(srcs == {"module_list", "mod_tree[0]", "mod_tree[1]"} for srcs in found.values())
    for m in found:
        info = mods.info(m)
        assert info.name and STATES[info.state] == "live"
        assert info.nsyms is not None and (info.nsyms_in_text or not info.text_size)


def test_carve_finds_listed_modules(guest):
    mods = Modules(guest)
    with guest.snapshot():
        listed = mods.module_list()
        # just the first listed module's neighbourhood, to keep it quick
        base = min(listed) & ~0xFFFFF
        carved = set(mods.carve(base, base + (4 << 20)))
    assert carved and carved <= set(listed)


def test_tables(guest):
    t = Tables(guest)
    with guest.snapshot():
        syscalls = t.syscall_table()
        gates = t.idt()
        idtr_frame, table_frame = t.idt_frames()
        lstar = t.place(t.lstar())
    assert len(syscalls) > 300
    assert all(t.place(a).symbol.startswith("__x64_sys_") for a in syscalls)
    assert len(gates) > 32 and all(g.selector == 0x10 for g in gates)
    assert idtr_frame == table_frame
    assert lstar.symbol == "entry_SYSCALL_64" and lstar.in_text and lstar.code_symbol


def test_place_names_a_module(guest):
    mods = Modules(guest)
    info = mods.info(mods.module_list()[0])
    t = Tables(guest, {info.name: (info.text_base, info.text_size)})
    p = t.place(info.text_base + 4)
    assert p.module == info.name and not p.in_text


def test_ftrace_records(guest):
    records, total = Ftrace(guest).records(only_active=False)
    assert total > 1000 and len(records) == total
    # on a clean idle guest nothing is attached, and every readable site is the nop
    assert all(r.nop or r.site is None for r in records if not r.enabled)


def test_pagehash_is_stable(guest):
    a = pagehash.hash_kernel(guest)
    b = pagehash.hash_kernel(guest)
    assert a["text"] and a["rodata"]
    assert pagehash.compare(a["text"], b["text"]) == []
    changed = dict(a["text"])
    va = next(iter(changed))
    changed[va] = "0" * 64
    assert pagehash.compare(a["text"], changed) == [(va, "modified")]


def _event(name, gpa, before, after, rip=0xFFFFFFFF81000000):
    return HookEvent(0, "mem", name, 0, 0, 0, 0, 0, 0, 0, False, gpa, 2, rip, "", 0, True, True,
                     gpa & ~15, bytes(before), bytes(after))


def test_memwatch_decodes_slots():
    """Decoding needs no guest: a write to slot 2 of an 8-byte table on frame 0x1234."""
    w = MemWatch(None, "t", 0xFFFFFFFF82000010, 8 * 8, 8)
    w.frames = {0x1234: 0xFFFFFFFF82000000}
    before, after = bytearray(16), bytearray(16)
    after[0:8] = (0xDEADBEEF).to_bytes(8, "little")  # the window at 0x20 holds slots 2 and 3
    x = w.decode(_event("t:0", 0x1234020, before, after))
    assert (x.slot, x.va, int.from_bytes(x.after, "little"), x.complete) == (2, 0xFFFFFFFF82000020, 0xDEADBEEF, True)
    assert w.decode(_event("t:0", 0x1234008, before, after)).slot == -1  # same frame, before the range
    assert w.decode(_event("other:0", 0x1234020, before, after)) is None
    gates = MemWatch(None, "idt", 0xFFFFFFFF82000000, 256 * 16, 16)
    gates.frames = {0x1234: 0xFFFFFFFF82000000}
    assert gates.decode(_event("idt:0", 0x1234035, before, after)).slot == 3


def test_memwatch_live_jiffies(guest):
    """jiffies is written every tick, so a watch on it should see writes right away."""
    jiffies = guest.sym("jiffies")
    seen, any_event = [], False
    with MemWatch(guest, "test-jiffies", jiffies, 8) as w:
        deadline = time.time() + 5
        while not seen and time.time() < deadline:
            writes, other = w.poll(100)
            any_event |= bool(writes or other)
            seen = [x for x in writes if x.slot == 0 and x.complete]
    if not any_event:
        pytest.skip("no hook events arrived at all: this host isn't delivering KVMI events (seen on AMD hosts)")
    assert seen
    before, after = (int.from_bytes(x, "little") for x in (seen[0].before, seen[0].after))
    assert 0 < after - before < 1000
