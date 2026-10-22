from __future__ import annotations

import ctypes as c

NAME_MAX = 64
PATH_MAX = 4096
COMM_MAX = 16
SYM_MAX = 128
KSYM_NAME_MAX = 512
WINDOW = 16
EVENTS_MAX = 4096


class VmConfig(c.Structure):
    _fields_ = [
        ("name", c.c_char * NAME_MAX),
        ("memory_mb", c.c_int),
        ("cpus", c.c_int),
        ("disk_image", c.c_char * PATH_MAX),
        ("cdrom", c.c_char * PATH_MAX),
        ("network", c.c_char * 8),
        ("display", c.c_char * 8),
        ("use_kvm", c.c_int),
        ("kvmi_enabled", c.c_int),
        ("extra_args", c.c_char * 512),
    ]


class Vm(c.Structure):
    _fields_ = [
        ("config", VmConfig),
        ("running", c.c_int),
        ("kvmi", c.c_int),
        ("pid", c.c_int),
        ("started_at", c.c_int64),
        ("qmp_socket", c.c_char * PATH_MAX),
        ("monitor_socket", c.c_char * PATH_MAX),
        ("kvmi_socket", c.c_char * PATH_MAX),
        ("log_path", c.c_char * PATH_MAX),
    ]


REGS = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "rflags",
    "cr0", "cr2", "cr3", "cr4",
    "dr6", "dr7",
    "idtr_base", "idtr_limit", "gdtr_base", "gdtr_limit",
    "fs_base", "gs_base", "shadow_gs",
    "msr_efer", "msr_star", "msr_lstar", "msr_cstar",
    "sysenter_cs", "sysenter_esp", "sysenter_eip",
)


class Regs(c.Structure):
    _fields_ = [(r, c.c_uint64) for r in REGS]


class Info(c.Structure):
    _fields_ = [
        ("banner", c.c_char * 512),
        ("release", c.c_char * 65),
        ("major", c.c_uint32),
        ("minor", c.c_uint32),
        ("patch", c.c_uint32),
        ("image_start", c.c_uint64),
        ("image_end", c.c_uint64),
        ("nsyms", c.c_uint64),
        ("btf_types", c.c_uint32),
        ("init_task", c.c_uint64),
        ("btf_va", c.c_uint64),
        ("btf_by_symbol", c.c_int),
    ]


class Task(c.Structure):
    _fields_ = [
        ("addr", c.c_uint64),
        ("pid", c.c_int64),
        ("tgid", c.c_int64),
        ("comm", c.c_char * (COMM_MAX + 1)),
    ]


class Field(c.Structure):
    _fields_ = [
        ("offset", c.c_uint64),
        ("size", c.c_uint32),
        ("bit_off", c.c_uint32),
        ("bit_size", c.c_uint32),
        ("kind", c.c_int),
        ("type", c.c_uint32),
        ("ref", c.c_uint32),
    ]


class Value(c.Structure):
    _fields_ = [
        ("kind", c.c_int),
        ("u", c.c_uint64),
        ("s", c.c_int64),
        ("enum_name", c.c_char * 64),
        ("len", c.c_size_t),
        ("bytes", c.c_ubyte * 256),
    ]


class Type(c.Structure):
    _fields_ = [("kind", c.c_char * 16), ("name", c.c_char * 256)]


class IdrEntry(c.Structure):
    _fields_ = [("id", c.c_uint64), ("ptr", c.c_uint64)]


class Ksym(c.Structure):
    _fields_ = [("addr", c.c_uint64), ("type", c.c_char), ("name", c.c_char * KSYM_NAME_MAX)]


class Hook(c.Structure):
    _fields_ = [
        ("name", c.c_char * NAME_MAX),
        ("kind", c.c_int),
        ("reg", c.c_char * 32),
        ("vaddr", c.c_uint64),
        ("cpuid_leaf", c.c_uint32),
        ("cpuid_any", c.c_int),
        ("descriptor", c.c_int),
        ("mem_gfn", c.c_uint64),
        ("mem_access", c.c_uint32),
        ("mem_capture", c.c_int),
    ]


class Event(c.Structure):
    _fields_ = [
        ("seq", c.c_uint64),
        ("kind", c.c_int),
        ("name", c.c_char * NAME_MAX),
        ("vcpu", c.c_uint32),
        ("vaddr", c.c_uint64),
        ("old_value", c.c_uint64),
        ("new_value", c.c_uint64),
        ("cpuid_leaf", c.c_uint32),
        ("cpuid_subleaf", c.c_uint32),
        ("descriptor", c.c_int),
        ("desc_is_write", c.c_int),
        ("mem_gpa", c.c_uint64),
        ("mem_access", c.c_uint32),
        ("rip", c.c_uint64),
        ("rip_sym", c.c_char * SYM_MAX),
        ("rip_off", c.c_uint64),
        ("captured", c.c_int),
        ("after_ok", c.c_int),
        ("window", c.c_uint64),
        ("before", c.c_uint8 * WINDOW),
        ("after", c.c_uint8 * WINDOW),
    ]
