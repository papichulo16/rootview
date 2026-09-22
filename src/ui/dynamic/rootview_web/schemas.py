"""The RootView data contract.

Everything the web server renders comes through these models. They are the
agreed boundary between the LibVMI introspection backend (C, later exposed via
the Python API) and this web server, so changes here need to be coordinated
with the backend team.

The central idea of RootView shows up as the ``visible_to_guest`` field on
:class:`BpfProgram` and :class:`BpfMap`. The hypervisor walks guest kernel
structures directly, so it sees the ground truth. A guest-side tool such as
``bpftool`` sees only what the (possibly compromised) kernel chooses to report.
When those two disagree, something is hiding.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    """How much a detection should alarm the user.

    The simple dashboard shows only ``high`` and ``critical`` by default; the
    advanced view shows everything.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BpfProgType(str, Enum):
    """Mirrors ``enum bpf_prog_type`` in the guest kernel.

    Kept as strings rather than the kernel's integers so the UI and the JSON
    API stay readable. The backend is responsible for the mapping, and for
    emitting ``unknown`` rather than guessing when it reads a value it does not
    recognize (kernel versions add new types over time).
    """

    SOCKET_FILTER = "socket_filter"
    KPROBE = "kprobe"
    TRACEPOINT = "tracepoint"
    RAW_TRACEPOINT = "raw_tracepoint"
    XDP = "xdp"
    PERF_EVENT = "perf_event"
    CGROUP_SKB = "cgroup_skb"
    SCHED_CLS = "sched_cls"
    SCHED_ACT = "sched_act"
    LSM = "lsm"
    TRACING = "tracing"
    STRUCT_OPS = "struct_ops"
    SYSCALL = "syscall"
    UNKNOWN = "unknown"


class BpfMapType(str, Enum):
    """Mirrors ``enum bpf_map_type`` in the guest kernel."""

    HASH = "hash"
    ARRAY = "array"
    PROG_ARRAY = "prog_array"
    PERF_EVENT_ARRAY = "perf_event_array"
    PERCPU_HASH = "percpu_hash"
    PERCPU_ARRAY = "percpu_array"
    STACK_TRACE = "stack_trace"
    LRU_HASH = "lru_hash"
    LPM_TRIE = "lpm_trie"
    RINGBUF = "ringbuf"
    SK_STORAGE = "sk_storage"
    TASK_STORAGE = "task_storage"
    UNKNOWN = "unknown"


class Visibility(str, Enum):
    """Whether an object the hypervisor can see is also reported by the guest.

    ``HIDDEN`` is the interesting case and is what a rootkit detection is
    usually built on. ``UNCHECKED`` means no guest-side comparison was
    available -- RootView must not report a hidden object when it simply never
    asked the guest, so the two cases stay distinct.
    """

    VISIBLE = "visible"
    HIDDEN = "hidden"
    UNCHECKED = "unchecked"


class AttachPoint(BaseModel):
    """Where a program is hooked into the kernel.

    ``target`` is the kernel symbol, tracepoint, or interface name -- e.g.
    ``sys_getdents64``, ``sched:sched_process_exec``, ``eth0``.
    """

    kind: BpfProgType
    target: str
    attached_at: datetime | None = None


class BpfProgram(BaseModel):
    """A loaded eBPF program as seen from the hypervisor."""

    prog_id: int
    name: str
    prog_type: BpfProgType
    tag: str = Field(description="8-byte kernel-computed hash of the instructions, hex encoded")
    loaded_at: datetime | None = None
    loader_uid: int | None = None
    loader_pid: int | None = None
    loader_comm: str | None = Field(default=None, description="Process name that called bpf(BPF_PROG_LOAD)")
    attach_points: list[AttachPoint] = Field(default_factory=list)
    map_ids: list[int] = Field(default_factory=list)
    helpers: list[str] = Field(
        default_factory=list,
        description="bpf helper functions referenced by the program, e.g. bpf_probe_write_user",
    )
    jited: bool = False
    bytes_xlated: int | None = None
    bytes_jited: int | None = None
    pinned_path: str | None = Field(
        default=None,
        description="bpffs path the program is pinned to, if any. Pinning survives the "
        "loading process exiting, which is how eBPF malware persists.",
    )
    visibility: Visibility = Visibility.UNCHECKED


class BpfMap(BaseModel):
    """A loaded eBPF map as seen from the hypervisor."""

    map_id: int
    name: str
    map_type: BpfMapType
    key_size: int
    value_size: int
    max_entries: int
    loaded_at: datetime | None = None
    visibility: Visibility = Visibility.UNCHECKED


class GuestInfo(BaseModel):
    """Identity of the guest kernel, needed to interpret every offset above."""

    kernel_release: str | None = None
    architecture: str | None = None
    profile_loaded: bool = Field(
        default=False,
        description="Whether a matching kernel profile / symbol table was found for this guest",
    )


class VMState(str, Enum):
    RUNNING = "running"
    PAUSED = "paused"
    SHUT_OFF = "shut_off"
    UNREACHABLE = "unreachable"


class VM(BaseModel):
    """A guest under introspection."""

    vm_id: str
    name: str
    state: VMState
    guest: GuestInfo = Field(default_factory=GuestInfo)
    last_scan: datetime | None = None


class BpfSnapshot(BaseModel):
    """The full eBPF state of one guest at one instant.

    This is what the advanced introspection view renders.
    """

    vm_id: str
    captured_at: datetime = Field(default_factory=_now)
    programs: list[BpfProgram] = Field(default_factory=list)
    maps: list[BpfMap] = Field(default_factory=list)


class DetectionRule(str, Enum):
    """Stable identifiers for the things RootView knows how to detect.

    Stable because the UI keys explanations off them and the test plan will
    reference them by name.
    """

    HIDDEN_PROGRAM = "hidden_program"
    HIDDEN_MAP = "hidden_map"
    PROBE_WRITE_USER = "probe_write_user"
    GETDENTS_HOOK = "getdents_hook"
    UNPRIVILEGED_LOAD = "unprivileged_load"
    ORPHANED_PROGRAM = "orphaned_program"
    PERSISTENT_PINNED = "persistent_pinned"


class Detection(BaseModel):
    """One thing RootView wants to tell the user about.

    ``evidence`` is deliberately a free-form mapping: each rule reports the
    specific values it compared, and the advanced view renders them as a table
    without needing to know what the rule looked at.
    """

    detection_id: str
    vm_id: str
    timestamp: datetime = Field(default_factory=_now)
    severity: Severity
    rule: DetectionRule
    title: str
    description: str
    prog_id: int | None = None
    map_id: int | None = None
    evidence: dict[str, str | int | bool | None] = Field(default_factory=dict)
    recommendation: str | None = None


class ScanResult(BaseModel):
    """Outcome of one detection pass over a guest."""

    vm_id: str
    started_at: datetime
    finished_at: datetime
    detections: list[Detection] = Field(default_factory=list)
    programs_examined: int = 0
    maps_examined: int = 0
    errors: list[str] = Field(default_factory=list)
