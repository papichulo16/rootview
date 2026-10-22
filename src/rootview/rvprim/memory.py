from __future__ import annotations

import ctypes as c

from rootview.rvprim import _structs as s
from rootview.rvprim._lib import call, declare

_err = (c.c_char_p, c.c_size_t)
_h = c.c_void_p
_buf = (c.c_uint64, c.c_void_p, c.c_size_t, *_err)
declare({
    "rv_pause": (c.c_int, (_h, *_err)),
    "rv_resume": (c.c_int, (_h, *_err)),
    "rv_read_phys": (c.c_int, (_h, *_buf)),
    "rv_write_phys": (c.c_int, (_h, *_buf)),
    "rv_read_virt": (c.c_int, (_h, *_buf)),
    "rv_write_virt": (c.c_int, (_h, *_buf)),
    "rv_translate": (c.c_int, (_h, c.c_uint64, c.POINTER(c.c_uint64), *_err)),
    "rv_reg": (c.c_int, (_h, c.c_char_p, c.POINTER(c.c_uint64), *_err)),
    "rv_set_reg": (c.c_int, (_h, c.c_char_p, c.c_uint64, *_err)),
    "rv_regs": (c.c_int, (_h, c.POINTER(s.Regs), *_err)),
})


class MemoryMixin:
    handle: int

    def _read(self, fn: str, addr: int, length: int) -> bytes:
        buf = c.create_string_buffer(length)
        call(fn, self.handle, addr, buf, length)
        return buf.raw

    def pause(self) -> None:
        call("rv_pause", self.handle)

    def resume(self) -> None:
        call("rv_resume", self.handle)

    def read_phys(self, pa: int, length: int) -> bytes:
        return self._read("rv_read_phys", pa, length)

    def write_phys(self, pa: int, data: bytes) -> None:
        call("rv_write_phys", self.handle, pa, data, len(data))

    def read_virt(self, va: int, length: int) -> bytes:
        return self._read("rv_read_virt", va, length)

    def write_virt(self, va: int, data: bytes) -> None:
        call("rv_write_virt", self.handle, va, data, len(data))

    def translate(self, va: int) -> int:
        pa = c.c_uint64()
        call("rv_translate", self.handle, va, c.byref(pa))
        return pa.value

    def reg(self, name: str) -> int:
        value = c.c_uint64()
        call("rv_reg", self.handle, name.encode(), c.byref(value))
        return value.value

    def set_reg(self, name: str, value: int) -> None:
        call("rv_set_reg", self.handle, name.encode(), value)

    def regs(self) -> dict[str, int]:
        r = s.Regs()
        call("rv_regs", self.handle, c.byref(r))
        return {name: getattr(r, name) for name in s.REGS}
