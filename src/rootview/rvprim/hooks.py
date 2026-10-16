from __future__ import annotations

import ctypes as c

from rootview.rvprim import _structs as s
from rootview.rvprim._lib import call, declare, fill, text
from rootview.rvprim.types import Hook, HookEvent

KINDS = ("register", "breakpoint", "cpuid", "descriptor", "mem")
DESCRIPTORS = {1: "idtr", 2: "gdtr", 3: "ldtr", 4: "tr"}

_err = (c.c_char_p, c.c_size_t)
_h = c.c_void_p
_named = (_h, c.c_char_p)
declare({
    "rv_hook_reg": (c.c_int, (*_named, c.c_char_p, *_err)),
    "rv_hook_bp": (c.c_int, (*_named, c.c_uint64, *_err)),
    "rv_hook_cpuid": (c.c_int, (*_named, c.c_char_p, *_err)),
    "rv_hook_desc": (c.c_int, (*_named, c.c_char_p, *_err)),
    "rv_hook_mem": (c.c_int, (*_named, c.c_uint64, c.c_char_p, *_err)),
    "rv_hook_mem_gfn": (c.c_int, (*_named, c.c_uint64, c.c_char_p, c.c_int, *_err)),
    "rv_hook_remove": (c.c_int, (*_named, *_err)),
    "rv_hooks": (c.c_int, (_h, c.POINTER(s.Hook), c.c_size_t, c.POINTER(c.c_size_t), *_err)),
    "rv_hook_poll": (c.c_int, (_h, c.c_uint32, *_err)),
    "rv_events": (c.c_int, (_h, c.POINTER(s.Event), c.c_size_t, c.POINTER(c.c_size_t),
                            c.POINTER(c.c_uint64), *_err)),
})


def _kind(k: int) -> str:
    return KINDS[k] if 0 <= k < len(KINDS) else str(k)


def _access(bits: int) -> str:
    return "".join(ch for bit, ch in ((1, "r"), (2, "w"), (4, "x")) if bits & bit)


def _hook(h: s.Hook) -> Hook:
    kind = _kind(h.kind)
    return Hook(
        name=text(h.name),
        kind=kind,
        reg=text(h.reg),
        vaddr=h.vaddr,
        cpuid_leaf=None if h.cpuid_any else h.cpuid_leaf,
        descriptor=DESCRIPTORS.get(h.descriptor, "") if kind == "descriptor" else "",
        mem_gfn=h.mem_gfn,
        access=_access(h.mem_access),
        capture=bool(h.mem_capture),
    )


def _event(e: s.Event) -> HookEvent:
    kind = _kind(e.kind)
    return HookEvent(
        seq=e.seq,
        kind=kind,
        name=text(e.name),
        vcpu=e.vcpu,
        vaddr=e.vaddr,
        old_value=e.old_value,
        new_value=e.new_value,
        cpuid_leaf=e.cpuid_leaf,
        cpuid_subleaf=e.cpuid_subleaf,
        descriptor=DESCRIPTORS.get(e.descriptor, "") if kind == "descriptor" else "",
        desc_is_write=bool(e.desc_is_write),
        mem_gpa=e.mem_gpa,
        mem_access=_access(e.mem_access),
        rip=e.rip,
        rip_sym=text(e.rip_sym),
        rip_off=e.rip_off,
        captured=bool(e.captured),
        after_ok=bool(e.after_ok),
        window=e.window,
        before=bytes(e.before),
        after=bytes(e.after),
    )


class HookMixin:
    handle: int

    def hook_reg(self, name: str, reg: str) -> None:
        call("rv_hook_reg", self.handle, name.encode(), reg.encode())

    def hook_bp(self, name: str, va: int) -> None:
        call("rv_hook_bp", self.handle, name.encode(), va)

    def hook_cpuid(self, name: str, leaf: str = "any") -> None:
        call("rv_hook_cpuid", self.handle, name.encode(), leaf.encode())

    def hook_desc(self, name: str, table: str) -> None:
        call("rv_hook_desc", self.handle, name.encode(), table.encode())

    def hook_mem(self, name: str, va: int, access: str) -> None:
        call("rv_hook_mem", self.handle, name.encode(), va, access.encode())

    def hook_mem_gfn(self, name: str, gfn: int, access: str, capture: bool = False) -> None:
        call("rv_hook_mem_gfn", self.handle, name.encode(), gfn, access.encode(), int(capture))

    def hook_remove(self, name: str) -> None:
        call("rv_hook_remove", self.handle, name.encode())

    def hooks(self) -> list[Hook]:
        return [_hook(h) for h in fill("rv_hooks", s.Hook, self.handle)]

    def poll(self, timeout_ms: int = 0) -> None:
        call("rv_hook_poll", self.handle, timeout_ms)

    def events(self) -> tuple[list[HookEvent], int]:
        out = (s.Event * s.EVENTS_MAX)()
        n = c.c_size_t()
        dropped = c.c_uint64()
        call("rv_events", self.handle, out, s.EVENTS_MAX, c.byref(n), c.byref(dropped))
        return [_event(e) for e in out[: n.value]], dropped.value
