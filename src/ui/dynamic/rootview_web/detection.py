"""Detection rules that turn an eBPF snapshot into user-facing findings.

These run on the web-server side against a :class:`BpfSnapshot`, which means
they work identically over any backend. The introspection engine's job is to
report *what is there*; deciding what is *suspicious* happens here, where it can
be changed without touching guest memory parsing.

Each rule is a small function so the test plan can exercise them one at a time.
"""

from __future__ import annotations

from rootview_web.schemas import (
    BpfProgram,
    BpfSnapshot,
    Detection,
    DetectionRule,
    Severity,
    Visibility,
)

# Helpers that let a program write into another process's memory or otherwise
# escape read-only observation. Legitimate uses exist but are rare enough that
# they are worth surfacing.
DANGEROUS_HELPERS = {
    "bpf_probe_write_user": (
        Severity.HIGH,
        "This helper writes directly into userspace process memory. eBPF rootkits use "
        "it to rewrite syscall arguments and return values in flight -- for example, to "
        "strip their own files out of a directory listing.",
    ),
    "bpf_override_return": (
        Severity.HIGH,
        "This helper forces a kernel function to return a chosen value, which can be "
        "used to make operations silently fail or succeed.",
    ),
    "bpf_send_signal": (
        Severity.MEDIUM,
        "This helper sends signals to processes from kernel context and can be used to "
        "kill monitoring or security agents.",
    ),
}

# Syscalls whose hooking is characteristic of hiding files, processes, or
# network connections from the operator.
CONCEALMENT_TARGETS = {
    "sys_getdents": "directory listings (hiding files and processes)",
    "sys_getdents64": "directory listings (hiding files and processes)",
    "sys_read": "file contents (tampering with logs or /proc)",
    "sys_bpf": "the bpf syscall itself (hiding other eBPF objects)",
    "tcp4_seq_show": "the /proc network tables (hiding connections)",
    "tcp6_seq_show": "the /proc network tables (hiding connections)",
}


def _detection_id(vm_id: str, rule: DetectionRule, subject: int | str) -> str:
    """Build a stable id for a finding.

    Deterministic on purpose: rescanning an unchanged guest produces the same
    ids, so the event stream can suppress repeats instead of re-alerting the
    user every polling interval.
    """
    return f"{vm_id}:{rule.value}:{subject}"


def _check_hidden_programs(snapshot: BpfSnapshot) -> list[Detection]:
    """A program the hypervisor sees but the guest does not report is hiding.

    This is RootView's core check and the reason the tool lives outside the
    guest. A rootkit can lie to ``bpftool``; it cannot lie about the kernel
    structures we read from the host.
    """
    out = []
    for prog in snapshot.programs:
        if prog.visibility is not Visibility.HIDDEN:
            continue
        out.append(
            Detection(
                detection_id=_detection_id(snapshot.vm_id, DetectionRule.HIDDEN_PROGRAM, prog.prog_id),
                vm_id=snapshot.vm_id,
                severity=Severity.CRITICAL,
                rule=DetectionRule.HIDDEN_PROGRAM,
                title=f"Hidden eBPF program: {prog.name}",
                description=(
                    f"Program {prog.prog_id} ({prog.name}, type {prog.prog_type.value}) is "
                    "loaded in the guest kernel but does not appear in the guest's own "
                    "listing of loaded programs. Something inside the guest is concealing "
                    "it, which is the defining behaviour of an eBPF rootkit."
                ),
                prog_id=prog.prog_id,
                evidence={
                    "prog_id": prog.prog_id,
                    "tag": prog.tag,
                    "seen_by_hypervisor": True,
                    "reported_by_guest": False,
                    "attach_points": ", ".join(a.target for a in prog.attach_points) or None,
                },
                recommendation=(
                    "Treat the guest as compromised. Capture a memory image before "
                    "shutting it down, since the program exists only in kernel memory."
                ),
            )
        )
    return out


def _check_hidden_maps(snapshot: BpfSnapshot) -> list[Detection]:
    """Maps hidden from the guest, same reasoning as hidden programs.

    Rated below hidden programs because a map is storage rather than code, but
    a hidden map is typically where a rootkit keeps its list of what to hide.
    """
    out = []
    for bpf_map in snapshot.maps:
        if bpf_map.visibility is not Visibility.HIDDEN:
            continue
        out.append(
            Detection(
                detection_id=_detection_id(snapshot.vm_id, DetectionRule.HIDDEN_MAP, bpf_map.map_id),
                vm_id=snapshot.vm_id,
                severity=Severity.HIGH,
                rule=DetectionRule.HIDDEN_MAP,
                title=f"Hidden eBPF map: {bpf_map.name}",
                description=(
                    f"Map {bpf_map.map_id} ({bpf_map.name}, type {bpf_map.map_type.value}) "
                    "exists in guest kernel memory but is not reported by the guest. "
                    "Hidden maps commonly hold a rootkit's configuration, such as the "
                    "filenames or PIDs it has been told to conceal."
                ),
                map_id=bpf_map.map_id,
                evidence={
                    "map_id": bpf_map.map_id,
                    "max_entries": bpf_map.max_entries,
                    "value_size": bpf_map.value_size,
                    "reported_by_guest": False,
                },
                recommendation="Dump the map contents to learn what the rootkit is hiding.",
            )
        )
    return out


def _check_dangerous_helpers(prog: BpfProgram, vm_id: str) -> list[Detection]:
    """Flag programs that call helpers capable of modifying, not just observing."""
    out = []
    for helper in prog.helpers:
        entry = DANGEROUS_HELPERS.get(helper)
        if entry is None:
            continue
        severity, why = entry
        out.append(
            Detection(
                detection_id=_detection_id(vm_id, DetectionRule.PROBE_WRITE_USER, f"{prog.prog_id}:{helper}"),
                vm_id=vm_id,
                severity=severity,
                rule=DetectionRule.PROBE_WRITE_USER,
                title=f"{prog.name} calls {helper}",
                description=f"Program {prog.prog_id} ({prog.name}) references {helper}. {why}",
                prog_id=prog.prog_id,
                evidence={"prog_id": prog.prog_id, "helper": helper, "jited": prog.jited},
                recommendation=(
                    "Confirm the program belongs to a tool you deployed. Observability "
                    "agents rarely need write access to process memory."
                ),
            )
        )
    return out


def _check_concealment_hooks(prog: BpfProgram, vm_id: str) -> list[Detection]:
    """Flag attachment to syscalls used for hiding things from the operator."""
    out = []
    for attach in prog.attach_points:
        target = attach.target.split(":")[-1]
        what = CONCEALMENT_TARGETS.get(target)
        if what is None:
            continue
        out.append(
            Detection(
                detection_id=_detection_id(vm_id, DetectionRule.GETDENTS_HOOK, f"{prog.prog_id}:{target}"),
                vm_id=vm_id,
                severity=Severity.MEDIUM,
                rule=DetectionRule.GETDENTS_HOOK,
                title=f"{prog.name} hooks {target}",
                description=(
                    f"Program {prog.prog_id} ({prog.name}) is attached to {target}, which "
                    f"controls {what}. Attaching here is how a rootkit filters what the "
                    "operator is allowed to see."
                ),
                prog_id=prog.prog_id,
                evidence={"prog_id": prog.prog_id, "attach_target": attach.target},
                recommendation="Check whether this hook belongs to an expected monitoring agent.",
            )
        )
    return out


def _check_unprivileged_load(prog: BpfProgram, vm_id: str) -> list[Detection]:
    """A tracing program loaded by a non-root user is unusual.

    Loading tracing programs normally requires CAP_BPF and CAP_PERFMON, so a
    non-zero loader uid suggests either a privilege escalation or a
    misattributed load worth looking at.
    """
    tracing_types = {"kprobe", "tracepoint", "raw_tracepoint", "tracing", "perf_event"}
    if prog.loader_uid in (None, 0) or prog.prog_type.value not in tracing_types:
        return []
    return [
        Detection(
            detection_id=_detection_id(vm_id, DetectionRule.UNPRIVILEGED_LOAD, prog.prog_id),
            vm_id=vm_id,
            severity=Severity.MEDIUM,
            rule=DetectionRule.UNPRIVILEGED_LOAD,
            title=f"{prog.name} was loaded by uid {prog.loader_uid}",
            description=(
                f"Program {prog.prog_id} ({prog.name}) is a {prog.prog_type.value} program "
                f"but was loaded by uid {prog.loader_uid} rather than root. Tracing programs "
                "normally require elevated capabilities to load."
            ),
            prog_id=prog.prog_id,
            evidence={
                "prog_id": prog.prog_id,
                "loader_uid": prog.loader_uid,
                "loader_pid": prog.loader_pid,
                "loader_comm": prog.loader_comm,
            },
            recommendation="Check what capabilities that account holds and how it obtained them.",
        )
    ]


def _check_persistence(prog: BpfProgram, vm_id: str) -> list[Detection]:
    """Pinned-but-unattached programs are staged for later use.

    Pinning to bpffs keeps a program alive after the loading process exits,
    which is the usual persistence mechanism for eBPF malware.
    """
    if prog.pinned_path is None or prog.attach_points:
        return []
    return [
        Detection(
            detection_id=_detection_id(vm_id, DetectionRule.PERSISTENT_PINNED, prog.prog_id),
            vm_id=vm_id,
            severity=Severity.LOW,
            rule=DetectionRule.PERSISTENT_PINNED,
            title=f"{prog.name} is pinned but not attached",
            description=(
                f"Program {prog.prog_id} ({prog.name}) is pinned at {prog.pinned_path} with no "
                "active attach point. Pinning keeps a program loaded after the process that "
                "loaded it exits, so this may be staged to attach later."
            ),
            prog_id=prog.prog_id,
            evidence={"prog_id": prog.prog_id, "pinned_path": prog.pinned_path},
            recommendation="Confirm the pin belongs to a service that attaches on demand.",
        )
    ]


def _check_orphaned(prog: BpfProgram, vm_id: str) -> list[Detection]:
    """Attached programs with no identifiable loader.

    Every legitimately loaded program was loaded by some process. If the
    backend resolved attach points but could not attribute a loader, either the
    loader exited or the attribution was tampered with.
    """
    if prog.loader_comm is not None or not prog.attach_points:
        return []
    return [
        Detection(
            detection_id=_detection_id(vm_id, DetectionRule.ORPHANED_PROGRAM, prog.prog_id),
            vm_id=vm_id,
            severity=Severity.LOW,
            rule=DetectionRule.ORPHANED_PROGRAM,
            title=f"{prog.name} has no identifiable loader",
            description=(
                f"Program {prog.prog_id} ({prog.name}) is attached and running, but RootView "
                "could not attribute it to a loading process."
            ),
            prog_id=prog.prog_id,
            evidence={"prog_id": prog.prog_id, "attach_count": len(prog.attach_points)},
            recommendation="Correlate the load time against process accounting for that window.",
        )
    ]


#: Severity order used for sorting findings, most urgent first.
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def run_rules(snapshot: BpfSnapshot) -> list[Detection]:
    """Run every detection rule over a snapshot, most severe finding first."""
    detections = _check_hidden_programs(snapshot) + _check_hidden_maps(snapshot)
    for prog in snapshot.programs:
        detections += _check_dangerous_helpers(prog, snapshot.vm_id)
        detections += _check_concealment_hooks(prog, snapshot.vm_id)
        detections += _check_unprivileged_load(prog, snapshot.vm_id)
        detections += _check_persistence(prog, snapshot.vm_id)
        detections += _check_orphaned(prog, snapshot.vm_id)
    detections.sort(key=lambda d: (_SEVERITY_ORDER[d.severity], d.detection_id))
    return detections
