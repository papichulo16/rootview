"""Unit tests for the detection rules.

The rules are pure functions over a snapshot, so they can be tested without a
guest, a hypervisor, or the web server.
"""

from __future__ import annotations

from rootview_web.detection import run_rules
from rootview_web.schemas import (
    AttachPoint,
    BpfMap,
    BpfMapType,
    BpfProgram,
    BpfProgType,
    BpfSnapshot,
    DetectionRule,
    Severity,
    Visibility,
)


def make_prog(**overrides) -> BpfProgram:
    defaults = dict(
        prog_id=1,
        name="benign",
        prog_type=BpfProgType.XDP,
        tag="0011223344556677",
        loader_uid=0,
        loader_pid=100,
        loader_comm="loader",
        attach_points=[AttachPoint(kind=BpfProgType.XDP, target="eth0")],
        helpers=["bpf_map_lookup_elem"],
        visibility=Visibility.VISIBLE,
    )
    defaults.update(overrides)
    return BpfProgram(**defaults)


def rules_fired(snapshot: BpfSnapshot) -> set[DetectionRule]:
    return {d.rule for d in run_rules(snapshot)}


def test_clean_snapshot_produces_no_findings():
    snap = BpfSnapshot(vm_id="vm", programs=[make_prog()])
    assert run_rules(snap) == []


def test_hidden_program_is_critical():
    snap = BpfSnapshot(vm_id="vm", programs=[make_prog(visibility=Visibility.HIDDEN)])
    findings = run_rules(snap)
    assert len(findings) == 1
    assert findings[0].rule is DetectionRule.HIDDEN_PROGRAM
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].prog_id == 1


def test_unchecked_visibility_is_not_reported_as_hidden():
    """Never having asked the guest is not the same as the guest lying."""
    snap = BpfSnapshot(vm_id="vm", programs=[make_prog(visibility=Visibility.UNCHECKED)])
    assert DetectionRule.HIDDEN_PROGRAM not in rules_fired(snap)


def test_hidden_map_is_reported():
    snap = BpfSnapshot(
        vm_id="vm",
        maps=[
            BpfMap(
                map_id=9,
                name="hide_list",
                map_type=BpfMapType.HASH,
                key_size=8,
                value_size=8,
                max_entries=64,
                visibility=Visibility.HIDDEN,
            )
        ],
    )
    findings = run_rules(snap)
    assert [f.rule for f in findings] == [DetectionRule.HIDDEN_MAP]
    assert findings[0].map_id == 9


def test_probe_write_user_is_flagged():
    prog = make_prog(helpers=["bpf_map_lookup_elem", "bpf_probe_write_user"])
    findings = run_rules(BpfSnapshot(vm_id="vm", programs=[prog]))
    assert [f.rule for f in findings] == [DetectionRule.PROBE_WRITE_USER]
    assert findings[0].severity is Severity.HIGH


def test_concealment_hook_is_flagged():
    prog = make_prog(
        prog_type=BpfProgType.TRACEPOINT,
        attach_points=[AttachPoint(kind=BpfProgType.TRACEPOINT, target="sys_getdents64")],
    )
    assert DetectionRule.GETDENTS_HOOK in rules_fired(BpfSnapshot(vm_id="vm", programs=[prog]))


def test_concealment_hook_matches_prefixed_tracepoint_names():
    """Targets arrive as either `sys_read` or `syscalls:sys_read` depending on
    how the program was attached; both must match."""
    prog = make_prog(
        prog_type=BpfProgType.TRACEPOINT,
        attach_points=[AttachPoint(kind=BpfProgType.TRACEPOINT, target="syscalls:sys_getdents64")],
    )
    assert DetectionRule.GETDENTS_HOOK in rules_fired(BpfSnapshot(vm_id="vm", programs=[prog]))


def test_unprivileged_tracing_load_is_flagged():
    prog = make_prog(prog_type=BpfProgType.KPROBE, loader_uid=1000)
    assert DetectionRule.UNPRIVILEGED_LOAD in rules_fired(BpfSnapshot(vm_id="vm", programs=[prog]))


def test_unprivileged_network_load_is_not_flagged():
    """Non-tracing program types do not need the same capabilities, so a
    non-root loader there is not on its own suspicious."""
    prog = make_prog(prog_type=BpfProgType.XDP, loader_uid=1000)
    assert DetectionRule.UNPRIVILEGED_LOAD not in rules_fired(BpfSnapshot(vm_id="vm", programs=[prog]))


def test_pinned_and_unattached_is_flagged_as_persistence():
    prog = make_prog(attach_points=[], pinned_path="/sys/fs/bpf/.stage")
    assert DetectionRule.PERSISTENT_PINNED in rules_fired(BpfSnapshot(vm_id="vm", programs=[prog]))


def test_pinned_but_attached_is_not_persistence():
    prog = make_prog(pinned_path="/sys/fs/bpf/agent")
    assert DetectionRule.PERSISTENT_PINNED not in rules_fired(BpfSnapshot(vm_id="vm", programs=[prog]))


def test_orphaned_program_is_flagged():
    prog = make_prog(loader_comm=None)
    assert DetectionRule.ORPHANED_PROGRAM in rules_fired(BpfSnapshot(vm_id="vm", programs=[prog]))


def test_detection_ids_are_stable_across_runs():
    """Stability is what lets the scanner suppress repeat alerts."""
    snap = BpfSnapshot(vm_id="vm", programs=[make_prog(visibility=Visibility.HIDDEN)])
    assert [d.detection_id for d in run_rules(snap)] == [d.detection_id for d in run_rules(snap)]


def test_findings_are_sorted_most_severe_first():
    snap = BpfSnapshot(
        vm_id="vm",
        programs=[
            make_prog(prog_id=1, attach_points=[], pinned_path="/sys/fs/bpf/x"),  # low
            make_prog(prog_id=2, visibility=Visibility.HIDDEN),  # critical
            make_prog(prog_id=3, helpers=["bpf_probe_write_user"]),  # high
        ],
    )
    severities = [d.severity for d in run_rules(snap)]
    assert severities[0] is Severity.CRITICAL
    assert severities == sorted(severities, key=lambda s: ["critical", "high", "medium", "low", "info"].index(s.value))
