from __future__ import annotations

import ctypes as c
from collections.abc import Iterator
from contextlib import contextmanager

from rootview.rvprim import _structs as s
from rootview.rvprim._lib import call, declare, fill, text
from rootview.rvprim.types import BtfType, Field, KernelInfo, Symbol, Task, Value

WALK_MAX = 65536
KSYMS_CHUNK = 4096
KINDS = ("u", "s", "ptr", "bytes", "cstr", "enum")

_err = (c.c_char_p, c.c_size_t)
_h = c.c_void_p
_u64p = c.POINTER(c.c_uint64)
_sizep = c.POINTER(c.c_size_t)
_out = (_u64p, c.c_size_t, _sizep, *_err)
declare({
    "rv_info": (c.c_int, (_h, c.POINTER(s.Info), *_err)),
    "rv_snapshot_begin": (c.c_int, (_h, *_err)),
    "rv_snapshot_end": (c.c_int, (_h, *_err)),
    "rv_read": (c.c_int, (_h, c.c_uint64, c.c_void_p, c.c_size_t, *_err)),
    "rv_sym": (c.c_int, (_h, c.c_char_p, _u64p, *_err)),
    "rv_sym_at": (c.c_int, (_h, c.c_uint64, c.POINTER(s.Ksym), *_err)),
    "rv_ksyms": (c.c_int, (_h, c.c_size_t, c.POINTER(s.Ksym), c.c_size_t, _sizep, *_err)),
    "rv_field": (c.c_int, (_h, c.c_char_p, c.c_char_p, c.POINTER(s.Field), *_err)),
    "rv_field_read": (c.c_int, (_h, c.c_char_p, c.c_char_p, c.c_uint64, c.POINTER(s.Value), *_err)),
    "rv_type": (c.c_int, (_h, c.c_uint32, c.POINTER(s.Type), *_err)),
    "rv_type_size": (c.c_int, (_h, c.c_char_p, _u64p, *_err)),
    "rv_enum_value": (c.c_int, (_h, c.c_char_p, c.c_char_p, c.POINTER(c.c_int64), *_err)),
    "rv_tasks": (c.c_int, (_h, c.POINTER(s.Task), c.c_size_t, _sizep, *_err)),
    "rv_list": (c.c_int, (_h, c.c_uint64, c.c_char_p, c.c_char_p, *_out)),
    "rv_hlist": (c.c_int, (_h, c.c_uint64, c.c_char_p, c.c_char_p, *_out)),
    "rv_list_off": (c.c_int, (_h, c.c_uint64, c.c_uint64, *_out)),
    "rv_hlist_off": (c.c_int, (_h, c.c_uint64, c.c_uint64, *_out)),
    "rv_rbtree": (c.c_int, (_h, c.c_uint64, *_out)),
    "rv_idr": (c.c_int, (_h, c.c_uint64, c.POINTER(s.IdrEntry), c.c_size_t, _sizep, *_err)),
    "rv_nr_cpus": (c.c_int, (_h, c.POINTER(c.c_uint32), *_err)),
    "rv_percpu_addr": (c.c_int, (_h, c.c_char_p, c.c_uint32, _u64p, *_err)),
})


def _symbol(k: s.Ksym) -> Symbol:
    return Symbol(text(k.name), k.addr, text(k.type))


class KernelMixin:
    handle: int
    _symbols: list[Symbol] | None

    def info(self) -> KernelInfo:
        i = s.Info()
        call("rv_info", self.handle, c.byref(i))
        return KernelInfo(
            banner=text(i.banner),
            release=text(i.release),
            version=(i.major, i.minor, i.patch),
            image=(i.image_start, i.image_end),
            nsyms=i.nsyms,
            btf_types=i.btf_types,
            init_task=i.init_task,
            btf_va=i.btf_va,
            btf_by_symbol=bool(i.btf_by_symbol),
        )

    @contextmanager
    def snapshot(self) -> Iterator[KernelMixin]:
        call("rv_snapshot_begin", self.handle)
        try:
            yield self
        finally:
            call("rv_snapshot_end", self.handle)

    def read(self, va: int, length: int) -> bytes:
        buf = c.create_string_buffer(length)
        call("rv_read", self.handle, va, buf, length)
        return buf.raw

    def sym(self, name: str) -> int:
        addr = c.c_uint64()
        call("rv_sym", self.handle, name.encode(), c.byref(addr))
        return addr.value

    def sym_at(self, va: int) -> tuple[Symbol, int]:
        k = s.Ksym()
        call("rv_sym_at", self.handle, va, c.byref(k))
        return _symbol(k), va - k.addr

    def symbols(self) -> list[Symbol]:
        if self._symbols is None:
            out = (s.Ksym * KSYMS_CHUNK)()
            total = c.c_size_t()
            syms: list[Symbol] = []
            while True:
                call("rv_ksyms", self.handle, len(syms), out, KSYMS_CHUNK, c.byref(total))
                syms.extend(_symbol(k) for k in out[: min(KSYMS_CHUNK, total.value - len(syms))])
                if len(syms) >= total.value:
                    break
            self._symbols = syms
        return self._symbols

    def field(self, type: str, path: str) -> Field:
        f = s.Field()
        call("rv_field", self.handle, type.encode(), path.encode(), c.byref(f))
        return Field(f.offset, f.size, f.bit_off, f.bit_size, KINDS[f.kind], f.type, f.ref)

    def read_field(self, type: str, path: str, base_va: int) -> Value:
        v = s.Value()
        call("rv_field_read", self.handle, type.encode(), path.encode(), base_va, c.byref(v))
        kind = KINDS[v.kind]
        if kind == "cstr":
            return Value(kind, text(c.string_at(v.bytes)), v.len)
        if kind == "bytes":
            return Value(kind, bytes(v.bytes[: min(v.len, len(v.bytes))]), v.len)
        if kind == "enum":
            return Value(kind, v.s, enum_name=text(v.enum_name) or None)
        return Value(kind, v.s if kind == "s" else v.u)

    def btf_type(self, id: int) -> BtfType:
        t = s.Type()
        call("rv_type", self.handle, id, c.byref(t))
        return BtfType(id, text(t.kind), text(t.name))

    def type_size(self, type: str) -> int:
        size = c.c_uint64()
        call("rv_type_size", self.handle, type.encode(), c.byref(size))
        return size.value

    def enum_value(self, name: str, enum: str | None = None) -> int:
        value = c.c_int64()
        call("rv_enum_value", self.handle, enum.encode() if enum else None, name.encode(), c.byref(value))
        return value.value

    def tasks(self) -> list[Task]:
        raw = fill("rv_tasks", s.Task, self.handle, cap=1024)
        return [Task(t.addr, t.pid, t.tgid, text(t.comm)) for t in raw]

    def _walk(self, fn: str, *args, max: int) -> list[int]:
        out = (c.c_uint64 * max)()
        n = c.c_size_t()
        call(fn, self.handle, *args, out, max, c.byref(n))
        return list(out[: n.value])

    def list(self, head: int, type: str, member: str, max: int = WALK_MAX) -> list[int]:
        return self._walk("rv_list", head, type.encode(), member.encode(), max=max)

    def hlist(self, head: int, type: str, member: str, max: int = WALK_MAX) -> list[int]:
        return self._walk("rv_hlist", head, type.encode(), member.encode(), max=max)

    def list_off(self, head: int, off: int, max: int = WALK_MAX) -> list[int]:
        return self._walk("rv_list_off", head, off, max=max)

    def hlist_off(self, head: int, off: int, max: int = WALK_MAX) -> list[int]:
        return self._walk("rv_hlist_off", head, off, max=max)

    def rbtree(self, root: int, max: int = WALK_MAX) -> list[int]:
        return self._walk("rv_rbtree", root, max=max)

    def idr(self, idr: int | str, max: int = WALK_MAX) -> list[tuple[int, int]]:
        addr = self.sym(idr) if isinstance(idr, str) else idr
        out = (s.IdrEntry * max)()
        n = c.c_size_t()
        call("rv_idr", self.handle, addr, out, max, c.byref(n))
        return [(e.id, e.ptr) for e in out[: n.value]]

    def nr_cpus(self) -> int:
        n = c.c_uint32()
        call("rv_nr_cpus", self.handle, c.byref(n))
        return n.value

    def percpu_addr(self, sym: str, cpu: int) -> int:
        addr = c.c_uint64()
        call("rv_percpu_addr", self.handle, sym.encode(), cpu, c.byref(addr))
        return addr.value
