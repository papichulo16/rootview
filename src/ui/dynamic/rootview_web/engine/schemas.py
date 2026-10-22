"""Request and response shapes for the engine's routes.

Addresses and register values travel as "0x..." strings: they exceed what a
JavaScript number holds exactly. Memory travels as a hex string.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, BeforeValidator, Field, PlainSerializer, WithJsonSchema


def _int(v: object) -> object:
    if isinstance(v, str):
        return int(v, 0)
    return v


def _hex_bytes(v: object) -> object:
    if isinstance(v, str):
        return bytes.fromhex(v.removeprefix("0x"))
    return v


Hex = Annotated[
    int,
    BeforeValidator(_int),
    PlainSerializer(lambda v: f"{v:#x}", return_type=str),
    WithJsonSchema({"type": "string", "examples": ["0xffffffff81000000"]}),
]
HexBytes = Annotated[
    bytes,
    BeforeValidator(_hex_bytes),
    PlainSerializer(lambda v: v.hex(), return_type=str),
    WithJsonSchema({"type": "string", "examples": ["4889e5"]}),
]


class Space(str, Enum):
    PHYS = "phys"
    VIRT = "virt"
    KERNEL = "kernel"


class EngineStatus(BaseModel):
    connected: bool
    allow_writes: bool


class VmConfig(BaseModel):
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


class VmCreate(BaseModel):
    name: str = Field(min_length=1, max_length=63)
    memory_mb: int | None = Field(default=None, gt=0)
    cpus: int | None = Field(default=None, gt=0)
    disk_image: str | None = None
    cdrom: str | None = None
    network: Literal["none", "user", "tap"] | None = None
    display: Literal["none", "gtk", "vnc"] | None = None
    kvm: bool | None = None
    kvmi_enabled: bool | None = None
    extra_args: str | None = None


class VmDetails(BaseModel):
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
    attached: bool = False
    profile_loaded: bool = False
    profile_error: str | None = None


class KernelInfo(BaseModel):
    banner: str
    release: str
    version: tuple[int, int, int]
    image: tuple[Hex, Hex]
    nsyms: int
    btf_types: int
    init_task: Hex
    btf_va: Hex
    btf_by_symbol: bool


class Memory(BaseModel):
    space: Space
    addr: Hex
    data: HexBytes


class Translation(BaseModel):
    va: Hex
    pa: Hex


class Register(BaseModel):
    name: str
    value: Hex


class RegisterWrite(BaseModel):
    value: Hex


class Task(BaseModel):
    addr: Hex
    pid: int
    tgid: int
    comm: str


class Symbol(BaseModel):
    name: str
    addr: Hex
    type: str
    offset: int = 0


class FieldInfo(BaseModel):
    type: str
    path: str
    offset: int
    size: int
    bit_off: int
    bit_size: int
    kind: str
    type_name: str
    ref_name: str | None = None
    value: str | None = Field(default=None, description="read at addr: hex for ptr and bytes, else text")
    length: int | None = None


HookKind = Literal["register", "breakpoint", "cpuid", "descriptor", "mem"]


class HookCreate(BaseModel):
    name: str = Field(min_length=1, max_length=63)
    kind: HookKind
    reg: Literal["cr0", "cr3", "cr4", "msr_all"] | None = None
    addr: Hex | None = None
    gfn: Hex | None = None
    leaf: str = "any"
    table: Literal["idtr", "gdtr", "ldtr", "tr"] | None = None
    access: str | None = Field(default=None, pattern="^[rwx]{1,3}$")
    capture: bool = False


class Hook(BaseModel):
    name: str
    kind: str
    reg: str
    vaddr: Hex
    cpuid_leaf: Hex | None
    descriptor: str
    mem_gfn: Hex
    access: str
    capture: bool


class HookEvent(BaseModel):
    seq: int
    kind: str
    name: str
    vcpu: int
    vaddr: Hex
    old_value: Hex
    new_value: Hex
    cpuid_leaf: Hex
    cpuid_subleaf: Hex
    descriptor: str
    desc_is_write: bool
    mem_gpa: Hex
    mem_access: str
    rip: Hex
    rip_sym: str
    rip_off: int
    captured: bool
    after_ok: bool
    window: Hex
    before: HexBytes
    after: HexBytes


class HookEvents(BaseModel):
    events: list[HookEvent]
    dropped: int
