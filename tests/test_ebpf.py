"""rootview.rvtools.ebpf: the ISA and analysis on hand-built programs (no guest
needed), then the guest reader against whatever programs the guest has loaded."""

from __future__ import annotations

import struct
import time

import pytest

from rootview.rvtools.ebpf import Maps, Progs, Resolver, analyze, attachments
from rootview.rvtools.ebpf.analysis import build, calls, refs
from rootview.rvtools.ebpf.guest.attach import Cgroups
from rootview.rvtools.ebpf.isa import decode, line, listing


def ins(code: int, dst: int = 0, src: int = 0, off: int = 0, imm: int = 0) -> bytes:
    return struct.pack("<BBhi", code, src << 4 | dst, off, imm)


def wide(dst: int, src: int, value: int) -> bytes:
    lo, hi = struct.unpack("<ii", struct.pack("<Q", value & (1 << 64) - 1))
    return ins(0x18, dst, src, imm=lo) + ins(0, imm=hi)


# systemd's cgroup_skb program as the 5.15 guest holds it, and bpftool's dump of it
SYSTEMD_SKB = bytes.fromhex(
    "bf16000000000000" "6967b00000000000" "b408000000000000" "4408000002000000"
    "b700000001000000" "5508010002000000" "b700000000000000" "9500000000000000")
SYSTEMD_SKB_XLATED = """\
   0: (bf) r6 = r1
   1: (69) r7 = *(u16 *)(r6 +176)
   2: (b4) w8 = 0
   3: (44) w8 |= 2
   4: (b7) r0 = 1
   5: (55) if r8 != 0x2 goto pc+1
   6: (b7) r0 = 0
   7: (95) exit"""


def test_listing_matches_bpftool():
    assert "\n".join(listing(decode(SYSTEMD_SKB))) == SYSTEMD_SKB_XLATED


@pytest.mark.parametrize("raw,text", [
    (ins(0x04, 1, imm=-1), "(04) w1 += -1"),
    (ins(0xBF, 6, 1), "(bf) r6 = r1"),
    (ins(0x87, 2), "(87) r2 = -r2"),
    (ins(0xD4, 3, imm=16), "(d4) r3 = le16 r3"),
    (ins(0xDC, 3, imm=32), "(dc) r3 = be32 r3"),
    (ins(0xD7, 1, imm=16), "(d7) r1 = bswap16 r1"),
    (ins(0x37, 1, off=1, imm=3), "(37) r1 s/= 3"),
    (ins(0xBF, 1, 2, off=8), "(bf) r1 = (s8)r2"),
    (ins(0x79, 1, 10, off=-8), "(79) r1 = *(u64 *)(r10 -8)"),
    (ins(0x39, 1, 2, off=8), "(79) r1 = *(u64 *)(r2 +8)"),
    (ins(0x81, 1, 2, off=4), "(81) r1 = *(s32 *)(r2 +4)"),
    (ins(0x63, 10, 0, off=-4), "(63) *(u32 *)(r10 -4) = r0"),
    (ins(0x7A, 10, off=-16, imm=1), "(7a) *(u64 *)(r10 -16) = 1"),
    (ins(0xC2), "(c2) nospec"),
    (ins(0xDB, 0, 7), "(db) lock *(u64 *)(r0 +0) += r7"),
    (ins(0xC3, 1, 2, imm=0x01), "(c3) r2 = atomic_fetch_add((u32 *)(r1 +0), r2)"),
    (ins(0xDB, 1, 2, imm=0xE1), "(db) r2 = atomic64_xchg((u64 *)(r1 +0), r2)"),
    (ins(0xDB, 1, 2, imm=0xF1), "(db) r0 = atomic64_cmpxchg((u64 *)(r1 +0), r0, r2)"),
    (ins(0x28, imm=12), "(28) r0 = *(u16 *)skb[12]"),
    (ins(0x50, 0, 3, imm=2), "(50) r0 = *(u8 *)skb[r3 + 2]"),
    (wide(1, 0, 0xFFFF888012345678), "(18) r1 = 0xffff888012345678"),
    (wide(1, 1, 5), "(18) r1 = map[id:5]"),
    (wide(1, 2, 16 << 32 | 5), "(18) r1 = map[id:5][0]+16"),
    (ins(0x55, 8, off=1, imm=2), "(55) if r8 != 0x2 goto pc+1"),
    (ins(0x15, 1, off=3, imm=-1), "(15) if r1 == 0xffffffff goto pc+3"),
    (ins(0x2E, 1, 2, off=-4), "(2e) if w1 > w2 goto pc-4"),
    (ins(0x05, off=-8), "(05) goto pc-8"),
    (ins(0x06, imm=100), "(06) gotol pc+100"),
    (ins(0x95), "(95) exit"),
    (ins(0x85, imm=14), "(85) call unknown#14"),
    (ins(0xF5), "(85) call bpf_tail_call#12"),
    (ins(0x85, src=2, imm=123), "(85) call kernel-function#123"),
    (ins(0x85, src=1, imm=3), "(85) call pc+3"),
])
def test_line(raw, text):
    assert line(decode(raw)[0]) == text


def test_ld_imm64_takes_two_slots():
    insns = decode(wide(1, 0, 0x1122334455667788) + ins(0x95))
    assert [(i.idx, i.slots) for i in insns] == [(0, 2), (2, 1)]
    assert insns[0].imm64 == 0x1122334455667788
    with pytest.raises(ValueError):
        decode(wide(1, 0, 1)[:8])
    with pytest.raises(ValueError):
        decode(b"\x95" * 7)


def test_calls():
    prog = (ins(0x85, imm=-200) + ins(0x85, src=2, imm=-300) + ins(0x85, src=1, off=2, imm=1) + ins(0xF5)
            + ins(0x95) + ins(0xB7) + ins(0x95))
    found = [(c.idx, c.kind, c.target) for c in calls(decode(prog), jited=True)]
    assert found == [(0, "helper", None), (1, "kfunc", None), (2, "subprog", 5), (3, "tail_call", None)]
    interpreted = ins(0x85, src=1, imm=1) + ins(0x95) + ins(0x95)
    assert calls(decode(interpreted), jited=False)[0].target == 2


def test_cfg_loops_and_unreachable():
    prog = (ins(0xB7) + ins(0x07, imm=1) + ins(0x55, off=-2, imm=8) + ins(0x05, off=1) + ins(0xB7, imm=1)
            + ins(0x95))
    cfg = build(decode(prog))
    assert {b.start: (b.end, b.succs) for b in cfg.blocks.values()} == {
        0: (1, (1,)), 1: (3, (1, 3)), 3: (4, (5,)), 4: (5, (5,)), 5: (6, ())}
    assert cfg.back_edges == ((1, 1),)
    assert cfg.unreachable == (4,)
    assert cfg.bad_targets == ()


def test_cfg_subprogs_and_bad_targets():
    cfg = build(decode(ins(0x85, src=1, off=1, imm=1) + ins(0x95) + ins(0xB7) + ins(0x95)))
    assert cfg.entries == (0, 2) and cfg.subprog_of(3) == 2 and cfg.subprog_of(1) == 0
    assert not cfg.unreachable
    bad = build(decode(ins(0x05, off=1) + wide(1, 0, 7) + ins(0x95)))
    assert bad.bad_targets == ((0, 2),)


def test_refs():
    found = refs(decode(wide(1, 0, 0xFFFF888000001000) + wide(2, 1, 5) + wide(3, 4, 7) + ins(0x95)))
    assert [(r.idx, r.dst, r.kind, r.value) for r in found] == [
        (0, 1, "imm", 0xFFFF888000001000), (2, 2, "map_fd", 5), (4, 3, "func", 7)]


def test_resolver_names_helpers(guest):
    res = Resolver(guest)
    fn = guest.sym("bpf_ktime_get_ns")
    assert res.symbol(res.call_target(fn - res.call_base)) == "bpf_ktime_get_ns"
    assert res.symbol(fn + 1) is None


def test_programs_in_prog_idr(guest):
    progs, res = Progs(guest), Resolver(guest)
    with guest.snapshot():
        programs = {pid: analyze(progs, res, addr) for pid, addr in guest.idr("prog_idr")}
    if not programs:
        pytest.skip("the guest has no eBPF programs loaded")
    for pid, p in programs.items():
        assert p.info.id == pid and len(p.info.tag) == 16
        assert p.info.loaded_at and p.info.loaded_at.timestamp() < time.time() + 60
        assert sum(i.slots for i in p.insns) == p.info.len
        assert len(p.listing()) == len(p.insns)
        assert not p.cfg.bad_targets
        assert {c.call.target for c in p.calls if c.call.kind == "subprog"} <= set(p.cfg.entries)
        assert not [h for h in p.helpers if h.startswith("0x")]
        assert all(m.id for m in p.maps)
        assert {r.map.addr for r in p.map_refs} <= {m.addr for m in p.maps}


def test_maps_in_map_idr(guest):
    maps = Maps(guest)
    with guest.snapshot():
        found = {mid: maps.info(addr) for mid, addr in guest.idr("map_idr")}
    if not found:
        pytest.skip("the guest has no eBPF maps")
    for mid, m in found.items():
        assert m.id == mid and m.type.startswith("BPF_MAP_TYPE_") and m.max_entries
        assert m.data is None or m.data[1] > m.data[0]


def test_cgroup_tree(guest):
    cgroups = Cgroups(guest)
    tree = cgroups.walk()
    assert cgroups.path(tree[0]) == "/"
    assert len(tree) == len(set(tree))
    assert all(cgroups.path(c).startswith("/") for c in tree[1:])


def test_attachments(guest):
    with guest.snapshot():
        progs = {addr for _, addr in guest.idr("prog_idr")}
        found, errors = attachments(guest)
    assert not errors
    if not found:
        pytest.skip("no eBPF program is attached in the guest")
    # on a clean guest every attached program has an ID
    assert {a.prog for a in found} <= progs
    for a in found:
        if a.source == "cgroup":
            assert a.target.startswith("/") and a.attach_type.startswith("BPF_CGROUP_")
    via_link = {(a.prog, a.link) for a in found if a.source == "link" and a.link_type == "BPF_LINK_TYPE_CGROUP"}
    via_cgroup = {(a.prog, a.link) for a in found if a.source == "cgroup"}
    assert via_link <= via_cgroup
