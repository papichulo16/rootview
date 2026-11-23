from __future__ import annotations

import ctypes
import os
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
ERR_MAX = 512

# reentrant: Guest.__del__ can run from a GC pass inside a locked call
lock = threading.RLock()
# pkvm-vmi handles take their own lock: one phone call can run for a minute
# over adb, and holding the global lock that long stalls a paused kvm-vmi guest
# until KVMI drops it. the two backends share no state in librootview.
pkvm_lock = threading.RLock()
_handle_locks: dict[int, threading.RLock] = {}
_lib: ctypes.CDLL | None = None
_sigs: dict[str, tuple[object, tuple]] = {}


class RootviewError(RuntimeError):
    pass


def declare(sigs: dict[str, tuple[object, tuple]]) -> None:
    _sigs.update(sigs)


def text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def _load(path: str | os.PathLike | None) -> ctypes.CDLL:
    path = path or os.environ.get("ROOTVIEW_LIB") or REPO_ROOT / "librootview.so"
    try:
        dll = ctypes.CDLL(str(path))
    except OSError as e:
        raise RootviewError(f"could not load {path} (run `make lib` at the repo root): {e}") from None
    for name, (restype, argtypes) in _sigs.items():
        fn = getattr(dll, name)
        fn.restype = restype
        fn.argtypes = argtypes
    dll.rv_set_base(str(REPO_ROOT).encode())
    return dll


def lib(path: str | os.PathLike | None = None) -> ctypes.CDLL:
    global _lib
    with lock:
        if _lib is None:
            _lib = _load(path)
        return _lib


def handle_lock(handle: int, lk: threading.RLock) -> None:
    """Calls on handle take lk instead of the global lock."""
    _handle_locks[handle] = lk


def handle_unlock(handle: int) -> None:
    _handle_locks.pop(handle, None)


def call(name: str, *args) -> None:
    fn = getattr(lib(), name)
    err = ctypes.create_string_buffer(ERR_MAX)
    handle = args[0] if args and isinstance(args[0], int) else None
    with _handle_locks.get(handle, lock):
        rc = fn(*args, err, ERR_MAX)
    if rc != 0:
        raise RootviewError(text(err.value) or f"{name} failed")


def fill(name: str, struct: type[ctypes.Structure], *args, cap: int = 64) -> list:
    while True:
        out = (struct * cap)()
        n = ctypes.c_size_t()
        call(name, *args, out, cap, ctypes.byref(n))
        if n.value <= cap:
            return out[: n.value]
        cap = n.value + 64
