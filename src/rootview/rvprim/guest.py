from __future__ import annotations

import ctypes as c

from rootview.rvprim._lib import ERR_MAX, RootviewError, call, declare, lib, lock, text
from rootview.rvprim.hooks import HookMixin
from rootview.rvprim.kernel import KernelMixin
from rootview.rvprim.memory import MemoryMixin
from rootview.rvprim.types import Symbol

_err = (c.c_char_p, c.c_size_t)
declare({
    "rv_attach": (c.c_void_p, (c.c_char_p, *_err)),
    "rv_detach": (None, (c.c_void_p,)),
    "rv_prof": (c.c_int, (c.c_void_p, *_err)),
    "rv_profiled": (c.c_int, (c.c_void_p,)),
})


class Guest(MemoryMixin, KernelMixin, HookMixin):
    def __init__(self, vm_name: str, profile: bool = True) -> None:
        self.name = vm_name
        self._h: int | None = None
        self._symbols: list[Symbol] | None = None
        fn = lib().rv_attach
        err = c.create_string_buffer(ERR_MAX)
        with lock:
            h = fn(vm_name.encode(), err, ERR_MAX)
        if not h:
            raise RootviewError(f"{vm_name}: {text(err.value) or 'rv_attach failed'}")
        self._h = h
        if profile:
            try:
                self.load_profile()
            except RootviewError:
                self.close()
                raise

    def load_profile(self) -> None:
        self._symbols = None
        call("rv_prof", self.handle)

    @property
    def profiled(self) -> bool:
        fn = lib().rv_profiled
        with lock:
            return bool(fn(self.handle))

    @property
    def handle(self) -> int:
        if self._h is None:
            raise RootviewError(f"{self.name}: guest is closed")
        return self._h

    def close(self) -> None:
        with lock:
            if self._h is not None:
                lib().rv_detach(self._h)
                self._h = None

    def __enter__(self) -> Guest:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        if getattr(self, "_h", None) is not None:
            self.close()
