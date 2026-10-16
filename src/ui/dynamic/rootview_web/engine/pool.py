"""Attached guests, shared by the backend and the tool routes."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from types import ModuleType
from typing import Any, TypeVar

from rootview_web.backends.base import BackendError, UnknownVMError

try:
    from rootview import rvprim
except ImportError:
    rvprim = None

T = TypeVar("T")


class GuestPool:
    def __init__(self, store: str | None = None, prim: ModuleType | None = None) -> None:
        self.store = store
        self.prim = prim or rvprim
        self.ready = False
        self.profile_errors: dict[str, str] = {}
        self._guests: dict[str, Any] = {}
        self._locks: dict[str, threading.Lock] = {}
        self._mutex = threading.Lock()

    async def start(self) -> None:
        if self.prim is None:
            raise BackendError("the rootview package is not installed (pip install -e the repo root)")
        await self.vm(self._load)
        self.ready = True

    async def close(self) -> None:
        await asyncio.to_thread(self._close_all)
        self.ready = False

    async def vm(self, fn: Callable[..., T], *args: Any) -> T:
        return await asyncio.to_thread(self._call, fn, *args)

    async def guest(self, vm_id: str, fn: Callable[[Any], T]) -> T:
        return await asyncio.to_thread(self._with_guest, vm_id, fn)

    async def lifecycle(self, vm_id: str, fn: Callable[..., T], *args: Any) -> T:
        await asyncio.to_thread(self._drop, vm_id)
        return await self.vm(fn, vm_id, *args)

    def attached(self, vm_id: str) -> Any | None:
        return self._guests.get(vm_id)

    def _load(self) -> None:
        self.prim.lib()
        if self.store:
            self.prim.set_base(self.store)

    def _call(self, fn: Callable[..., T], *args: Any) -> T:
        try:
            return fn(*args)
        except self.prim.RootviewError as e:
            raise BackendError(str(e)) from e

    def _lock(self, vm_id: str) -> threading.Lock:
        with self._mutex:
            return self._locks.setdefault(vm_id, threading.Lock())

    def _with_guest(self, vm_id: str, fn: Callable[[Any], T]) -> T:
        with self._lock(vm_id):
            g = self._attach(vm_id)
            try:
                return fn(g)
            except self.prim.RootviewError as e:
                if not self._running(vm_id):
                    self._drop_locked(vm_id)
                raise BackendError(f"{vm_id}: {e}") from e

    def _attach(self, vm_id: str) -> Any:
        if vm_id in self._guests:
            return self._guests[vm_id]
        if vm_id not in {v.name for v in self._call(self.prim.list_vms)}:
            raise UnknownVMError(f"no guest named {vm_id!r}")
        g = self._call(self.prim.Guest, vm_id, False)
        try:
            g.load_profile()
            self.profile_errors.pop(vm_id, None)
        except self.prim.RootviewError as e:
            self.profile_errors[vm_id] = str(e)
        self._guests[vm_id] = g
        return g

    def _running(self, vm_id: str) -> bool:
        try:
            return self.prim.inspect_vm(vm_id).running
        except self.prim.RootviewError:
            return False

    def _drop(self, vm_id: str) -> None:
        with self._lock(vm_id):
            self._drop_locked(vm_id)

    def _drop_locked(self, vm_id: str) -> None:
        g = self._guests.pop(vm_id, None)
        if g is not None:
            g.close()
        self.profile_errors.pop(vm_id, None)

    def _close_all(self) -> None:
        for vm_id in list(self._guests):
            self._drop(vm_id)
