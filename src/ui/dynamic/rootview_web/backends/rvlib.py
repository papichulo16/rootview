"""ctypes bindings for librootview.so, the engine's flat C API (bind/rootview.h).

Built with ``make lib`` at the repository root, which puts ``librootview.so``
next to ``rv``. Set ``ROOTVIEW_LIB`` to load it from anywhere else.

The C side is not thread-safe, and the web server calls in from
``asyncio.to_thread`` workers, so every call into the library goes through one
process-wide lock. A failed call's err string comes back as
:class:`~rootview_web.backends.base.BackendError`.
"""

from __future__ import annotations

import ctypes
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from rootview_web.backends.base import BackendError

#: The repository root: rootview_web/backends/ -> src/ui/dynamic -> repo.
REPO_ROOT = Path(__file__).resolve().parents[5]

ERR_MAX = 512
NAME_MAX = 64
COMM_MAX = 16
EVENTS_MAX = 4096

#: Node cap for list and idr walks; the C side clamps it to 1M.
WALK_MAX = 65536

# reentrant: Guest.__del__ can run from a GC pass that fires inside a locked call
_lock = threading.RLock()
_lib: ctypes.CDLL | None = None


class _Vm(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char * NAME_MAX),
        ("running", ctypes.c_int),
        ("kvmi", ctypes.c_int),
        ("memory_mb", ctypes.c_int),
        ("cpus", ctypes.c_int),
    ]


class _Info(ctypes.Structure):
    _fields_ = [
        ("banner", ctypes.c_char * 512),
        ("release", ctypes.c_char * 65),
        ("major", ctypes.c_uint32),
        ("minor", ctypes.c_uint32),
        ("patch", ctypes.c_uint32),
        ("image_start", ctypes.c_uint64),
        ("image_end", ctypes.c_uint64),
        ("root_pgd", ctypes.c_uint64),
        ("nsyms", ctypes.c_uint64),
        ("btf_types", ctypes.c_uint32),
        ("init_task", ctypes.c_uint64),
    ]


class _Task(ctypes.Structure):
    _fields_ = [
        ("addr", ctypes.c_uint64),
        ("pid", ctypes.c_int64),
        ("tgid", ctypes.c_int64),
        ("comm", ctypes.c_char * (COMM_MAX + 1)),
    ]


class _Field(ctypes.Structure):
    _fields_ = [
        ("offset", ctypes.c_uint64),
        ("size", ctypes.c_uint32),
        ("bit_off", ctypes.c_uint32),
        ("bit_size", ctypes.c_uint32),
        ("kind", ctypes.c_int),
        ("type", ctypes.c_uint32),
        ("ref", ctypes.c_uint32),
    ]


class _Value(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_int),
        ("u", ctypes.c_uint64),
        ("s", ctypes.c_int64),
        ("enum_name", ctypes.c_char * 64),
        ("len", ctypes.c_size_t),
        ("bytes", ctypes.c_ubyte * 256),
    ]


class _IdrEntry(ctypes.Structure):
    _fields_ = [("id", ctypes.c_uint64), ("ptr", ctypes.c_uint64)]


class _Event(ctypes.Structure):
    _fields_ = [
        ("seq", ctypes.c_uint64),
        ("kind", ctypes.c_int),
        ("name", ctypes.c_char * NAME_MAX),
        ("vcpu", ctypes.c_uint32),
        ("vaddr", ctypes.c_uint64),
        ("old_value", ctypes.c_uint64),
        ("new_value", ctypes.c_uint64),
        ("cpuid_leaf", ctypes.c_uint32),
        ("cpuid_subleaf", ctypes.c_uint32),
        ("descriptor", ctypes.c_int),
        ("desc_is_write", ctypes.c_int),
        ("mem_gpa", ctypes.c_uint64),
        ("mem_access", ctypes.c_uint32),
    ]


#: rv_field's kind, by value (the RV_* enum in rootview.h).
KINDS = ("u", "s", "ptr", "bytes", "cstr", "enum")
#: rv_event_t's kind, by value (RV_HOOK_*).
HOOK_KINDS = ("register", "breakpoint", "cpuid", "descriptor", "mem")


@dataclass(frozen=True)
class GuestVm:
    name: str
    running: bool
    kvmi: bool
    memory_mb: int
    cpus: int


@dataclass(frozen=True)
class KernelInfo:
    banner: str
    release: str
    version: tuple[int, int, int]
    image: tuple[int, int]
    root_pgd: int
    nsyms: int
    btf_types: int
    init_task: int


@dataclass(frozen=True)
class Task:
    addr: int
    pid: int
    tgid: int
    comm: str


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
class Value:
    """A field's value. ``value`` is an int, str or bytes depending on ``kind``.

    ``bytes`` and ``cstr`` values are cut at 256 bytes; ``length`` is the full
    length in the guest.
    """

    kind: str
    value: int | str | bytes
    length: int = 0
    enum_name: str | None = None


@dataclass(frozen=True)
class HookEvent:
    """One hook firing. Which fields mean anything depends on ``kind``; see rv_event_t."""

    seq: int
    kind: str
    name: str
    vcpu: int
    vaddr: int
    old_value: int
    new_value: int
    cpuid_leaf: int
    cpuid_subleaf: int
    descriptor: int
    desc_is_write: bool
    mem_gpa: int
    mem_access: int


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def _load(path: str | os.PathLike | None = None) -> ctypes.CDLL:
    path = path or os.environ.get("ROOTVIEW_LIB") or REPO_ROOT / "librootview.so"
    try:
        lib = ctypes.CDLL(str(path))
    except OSError as e:
        raise BackendError(f"could not load {path} (run `make lib` at the repo root): {e}") from None

    c = ctypes
    err = (c.c_char_p, c.c_size_t)
    h = c.c_void_p
    size_p = c.POINTER(c.c_size_t)
    u64_p = c.POINTER(c.c_uint64)
    status = c.c_int
    sigs = {
        "rv_set_base": (None, (c.c_char_p,)),
        "rv_vm_list": (status, (c.POINTER(_Vm), c.c_size_t, size_p, *err)),
        "rv_init": (h, (c.c_char_p, *err)),
        "rv_close": (None, (h,)),
        "rv_info": (status, (h, c.POINTER(_Info), *err)),
        "rv_snapshot_begin": (status, (h, *err)),
        "rv_snapshot_end": (status, (h, *err)),
        "rv_read": (status, (h, c.c_uint64, c.c_void_p, c.c_size_t, *err)),
        "rv_sym": (status, (h, c.c_char_p, u64_p, *err)),
        "rv_field": (status, (h, c.c_char_p, c.c_char_p, c.POINTER(_Field), *err)),
        "rv_field_read": (status, (h, c.c_char_p, c.c_char_p, c.c_uint64, c.POINTER(_Value), *err)),
        "rv_tasks": (status, (h, c.POINTER(_Task), c.c_size_t, size_p, *err)),
        "rv_list": (status, (h, c.c_uint64, c.c_char_p, c.c_char_p, u64_p, c.c_size_t, size_p, *err)),
        "rv_hlist": (status, (h, c.c_uint64, c.c_char_p, c.c_char_p, u64_p, c.c_size_t, size_p, *err)),
        "rv_nr_cpus": (status, (h, c.POINTER(c.c_uint32), *err)),
        "rv_percpu_addr": (status, (h, c.c_char_p, c.c_uint32, u64_p, *err)),
        "rv_idr": (status, (h, c.c_uint64, c.POINTER(_IdrEntry), c.c_size_t, size_p, *err)),
        "rv_hook_reg": (status, (h, c.c_char_p, c.c_char_p, *err)),
        "rv_hook_bp": (status, (h, c.c_char_p, c.c_uint64, *err)),
        "rv_hook_cpuid": (status, (h, c.c_char_p, c.c_char_p, *err)),
        "rv_hook_desc": (status, (h, c.c_char_p, c.c_char_p, *err)),
        "rv_hook_mem": (status, (h, c.c_char_p, c.c_uint64, c.c_char_p, *err)),
        "rv_hook_remove": (status, (h, c.c_char_p, *err)),
        "rv_hook_poll": (status, (h, c.c_uint32, *err)),
        "rv_events": (status, (h, c.POINTER(_Event), c.c_size_t, size_p, u64_p, *err)),
    }
    for name, (restype, argtypes) in sigs.items():
        fn = getattr(lib, name)
        fn.restype = restype
        fn.argtypes = argtypes
    lib.rv_set_base(str(REPO_ROOT).encode())
    return lib


def lib(path: str | os.PathLike | None = None) -> ctypes.CDLL:
    """The loaded library, loading it on first use. Raises BackendError if it can't be."""
    global _lib
    with _lock:
        if _lib is None:
            _lib = _load(path)
        return _lib


def _call(fn, *args) -> None:
    """Calls an int-returning rv_* function under the lock, raising its err on failure."""
    err = ctypes.create_string_buffer(ERR_MAX)
    with _lock:
        rc = fn(*args, err, ERR_MAX)
    if rc != 0:
        raise BackendError(_text(err.value) or f"{fn.__name__} failed")


def set_base(dir: str | os.PathLike) -> None:
    """Point the vm store at ``<dir>/.rootview/vms``. Defaults to the repo root."""
    fn = lib().rv_set_base
    with _lock:
        fn(str(dir).encode())


def list_vms() -> list[GuestVm]:
    l = lib()
    cap = 64
    while True:
        out = (_Vm * cap)()
        n = ctypes.c_size_t()
        _call(l.rv_vm_list, out, cap, ctypes.byref(n))
        if n.value <= cap:
            break
        cap = n.value
    return [GuestVm(_text(v.name), bool(v.running), bool(v.kvmi), v.memory_mb, v.cpus) for v in out[: n.value]]


class Guest:
    """An attached guest with its kernel profile built. Close it, or use it as a context manager."""

    def __init__(self, vm_name: str) -> None:
        self._lib = lib()
        err = ctypes.create_string_buffer(ERR_MAX)
        with _lock:
            h = self._lib.rv_init(vm_name.encode(), err, ERR_MAX)
        if not h:
            raise BackendError(f"{vm_name}: {_text(err.value) or 'rv_init failed'}")
        self._h: int | None = h
        self.name = vm_name

    def close(self) -> None:
        with _lock:
            if self._h is not None:
                self._lib.rv_close(self._h)
                self._h = None

    def __enter__(self) -> Guest:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        if getattr(self, "_h", None) is not None:
            self.close()

    @property
    def handle(self) -> int:
        if self._h is None:
            raise BackendError(f"{self.name}: guest is closed")
        return self._h

    def info(self) -> KernelInfo:
        i = _Info()
        _call(self._lib.rv_info, self.handle, ctypes.byref(i))
        return KernelInfo(
            banner=_text(i.banner),
            release=_text(i.release),
            version=(i.major, i.minor, i.patch),
            image=(i.image_start, i.image_end),
            root_pgd=i.root_pgd,
            nsyms=i.nsyms,
            btf_types=i.btf_types,
            init_task=i.init_task,
        )

    @contextmanager
    def snapshot(self) -> Iterator[Guest]:
        """Pause the guest and cache every read until the block ends.

        Everything read inside is one consistent view of the guest; nothing
        read outside is cached. Keep the block short: the guest is stopped.
        """
        _call(self._lib.rv_snapshot_begin, self.handle)
        try:
            yield self
        finally:
            _call(self._lib.rv_snapshot_end, self.handle)

    def read(self, va: int, length: int) -> bytes:
        buf = ctypes.create_string_buffer(length)
        _call(self._lib.rv_read, self.handle, va, buf, length)
        return buf.raw

    def sym(self, name: str) -> int:
        addr = ctypes.c_uint64()
        _call(self._lib.rv_sym, self.handle, name.encode(), ctypes.byref(addr))
        return addr.value

    def field(self, type: str, path: str) -> Field:
        f = _Field()
        _call(self._lib.rv_field, self.handle, type.encode(), path.encode(), ctypes.byref(f))
        return Field(f.offset, f.size, f.bit_off, f.bit_size, KINDS[f.kind], f.type, f.ref)

    def read_field(self, type: str, path: str, base_va: int) -> Value:
        v = _Value()
        _call(self._lib.rv_field_read, self.handle, type.encode(), path.encode(), base_va, ctypes.byref(v))
        kind = KINDS[v.kind]
        if kind == "cstr":
            return Value(kind, _text(ctypes.string_at(v.bytes)), v.len)
        if kind == "bytes":
            return Value(kind, bytes(v.bytes[: min(v.len, len(v.bytes))]), v.len)
        if kind == "enum":
            return Value(kind, v.s, enum_name=_text(v.enum_name) or None)
        return Value(kind, v.s if kind == "s" else v.u)

    def tasks(self) -> list[Task]:
        """Every process but swapper/0, read in one pause window."""
        cap = 1024
        while True:
            out = (_Task * cap)()
            n = ctypes.c_size_t()
            _call(self._lib.rv_tasks, self.handle, out, cap, ctypes.byref(n))
            if n.value <= cap:
                break
            cap = n.value + 64  # it can grow between the two walks
        return [Task(t.addr, t.pid, t.tgid, _text(t.comm)) for t in out[: n.value]]

    def _walk(self, fn, head: int, type: str, member: str, max: int) -> list[int]:
        out = (ctypes.c_uint64 * max)()
        n = ctypes.c_size_t()
        _call(fn, self.handle, head, type.encode(), member.encode(), out, max, ctypes.byref(n))
        return list(out[: n.value])

    def list(self, head: int, type: str, member: str, max: int = WALK_MAX) -> list[int]:
        """Container addresses on the list_head list anchored at ``head``.

        More than ``max`` nodes, a cycle, or a wild pointer raises BackendError.
        """
        return self._walk(self._lib.rv_list, head, type, member, max)

    def hlist(self, head: int, type: str, member: str, max: int = WALK_MAX) -> list[int]:
        """The same for an hlist_head and its hlist_node member."""
        return self._walk(self._lib.rv_hlist, head, type, member, max)

    def nr_cpus(self) -> int:
        n = ctypes.c_uint32()
        _call(self._lib.rv_nr_cpus, self.handle, ctypes.byref(n))
        return n.value

    def percpu_addr(self, sym: str, cpu: int) -> int:
        addr = ctypes.c_uint64()
        _call(self._lib.rv_percpu_addr, self.handle, sym.encode(), cpu, ctypes.byref(addr))
        return addr.value

    def idr(self, idr: int | str, max: int = WALK_MAX) -> list[tuple[int, int]]:
        """(id, pointer) pairs of a struct idr, by address or by symbol ("prog_idr")."""
        addr = self.sym(idr) if isinstance(idr, str) else idr
        out = (_IdrEntry * max)()
        n = ctypes.c_size_t()
        _call(self._lib.rv_idr, self.handle, addr, out, max, ctypes.byref(n))
        return [(e.id, e.ptr) for e in out[: n.value]]

    # ---- hooks: events land in the C ring; poll() fills it, events() drains it ----

    def hook_reg(self, name: str, reg: str) -> None:
        """Watch writes to cr0, cr3, cr4, or every msr (``msr_all``)."""
        _call(self._lib.rv_hook_reg, self.handle, name.encode(), reg.encode())

    def hook_bp(self, name: str, va: int) -> None:
        _call(self._lib.rv_hook_bp, self.handle, name.encode(), va)

    def hook_cpuid(self, name: str, leaf: str = "any") -> None:
        _call(self._lib.rv_hook_cpuid, self.handle, name.encode(), leaf.encode())

    def hook_desc(self, name: str, table: str) -> None:
        _call(self._lib.rv_hook_desc, self.handle, name.encode(), table.encode())

    def hook_mem(self, name: str, va: int, access: str) -> None:
        """Trap ``access`` (any of r, w, x) to the page holding ``va``."""
        _call(self._lib.rv_hook_mem, self.handle, name.encode(), va, access.encode())

    def hook_remove(self, name: str) -> None:
        _call(self._lib.rv_hook_remove, self.handle, name.encode())

    def poll(self, timeout_ms: int = 0) -> None:
        """Pump the vmi event queue into the ring.

        This holds the library lock for up to ``timeout_ms``, so every other
        call waits behind it; keep it short and call it often.
        """
        _call(self._lib.rv_hook_poll, self.handle, timeout_ms)

    def events(self) -> tuple[list[HookEvent], int]:
        """Drain the ring: the events oldest first, and how many were dropped since the last drain."""
        out = (_Event * EVENTS_MAX)()
        n = ctypes.c_size_t()
        dropped = ctypes.c_uint64()
        _call(self._lib.rv_events, self.handle, out, EVENTS_MAX, ctypes.byref(n), ctypes.byref(dropped))
        return [
            HookEvent(
                e.seq,
                HOOK_KINDS[e.kind] if 0 <= e.kind < len(HOOK_KINDS) else str(e.kind),
                _text(e.name),
                e.vcpu,
                e.vaddr,
                e.old_value,
                e.new_value,
                e.cpuid_leaf,
                e.cpuid_subleaf,
                e.descriptor,
                bool(e.desc_is_write),
                e.mem_gpa,
                e.mem_access,
            )
            for e in out[: n.value]
        ], dropped.value
