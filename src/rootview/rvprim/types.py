from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VmConfig:
    name: str
    memory_mb: int
    cpus: int
    disk_image: str
    cdrom: str
    network: str
    display: str
    kvm: bool
    kvmi_enabled: bool
    extra_args: str


@dataclass(frozen=True)
class Vm:
    name: str
    config: VmConfig
    running: bool
    kvmi: bool
    pid: int | None
    started_at: int | None
    qmp_socket: str
    monitor_socket: str
    kvmi_socket: str
    log_path: str


@dataclass(frozen=True)
class KernelInfo:
    banner: str
    release: str
    version: tuple[int, int, int]
    image: tuple[int, int]
    nsyms: int
    btf_types: int
    init_task: int
    btf_va: int
    btf_by_symbol: bool


@dataclass(frozen=True)
class Task:
    addr: int
    pid: int
    tgid: int
    comm: str


@dataclass(frozen=True)
class Symbol:
    name: str
    addr: int
    type: str


@dataclass(frozen=True)
class Field:
    offset: int
    size: int
    bit_off: int
    bit_size: int
    kind: str
    type: int
    ref: int


@dataclass(frozen=True)
class BtfType:
    id: int
    kind: str
    name: str


@dataclass(frozen=True)
class Value:
    kind: str
    value: int | str | bytes
    length: int = 0
    enum_name: str | None = None


@dataclass(frozen=True)
class Hook:
    name: str
    kind: str
    reg: str = ""
    vaddr: int = 0
    cpuid_leaf: int | None = None
    descriptor: str = ""
    mem_gfn: int = 0
    access: str = ""
    capture: bool = False


@dataclass(frozen=True)
class HookEvent:
    seq: int
    kind: str
    name: str
    vcpu: int
    vaddr: int
    old_value: int
    new_value: int
    cpuid_leaf: int
    cpuid_subleaf: int
    descriptor: str
    desc_is_write: bool
    mem_gpa: int
    mem_access: str
    rip: int = 0
    rip_sym: str = ""
    rip_off: int = 0
    captured: bool = False
    after_ok: bool = False
    window: int = 0
    before: bytes = b""
    after: bytes = b""
