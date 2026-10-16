"""Hooks, as the kvmi shell's watch/bp/cpuidhook/deschook/memhook/unhook/list/listen do it."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from rootview_web.deps import get_engine, same_origin
from rootview_web.engine import GuestPool
from rootview_web.engine.schemas import Hook, HookCreate, HookEvent, HookEvents

router = APIRouter(prefix="/api/vms/{vm_id}/hooks", tags=["hooks"])

POLL_MAX_MS = 1000


def _need(value: Any, what: str) -> Any:
    if value is None:
        raise HTTPException(status_code=422, detail=f"{what} is required for this hook kind")
    return value


def _adder(h: HookCreate):
    if h.kind == "register":
        reg = _need(h.reg, "reg")
        return lambda g: g.hook_reg(h.name, reg)
    if h.kind == "breakpoint":
        addr = _need(h.addr, "addr")
        return lambda g: g.hook_bp(h.name, addr)
    if h.kind == "cpuid":
        return lambda g: g.hook_cpuid(h.name, h.leaf)
    if h.kind == "descriptor":
        table = _need(h.table, "table")
        return lambda g: g.hook_desc(h.name, table)
    access = _need(h.access, "access")
    if h.gfn is not None:
        return lambda g: g.hook_mem_gfn(h.name, h.gfn, access, h.capture)
    addr = _need(h.addr, "addr or gfn")
    return lambda g: g.hook_mem(h.name, addr, access)


def _hooks(g) -> list[Hook]:
    return [Hook.model_validate(h, from_attributes=True) for h in g.hooks()]


@router.get("", response_model=list[Hook])
async def list_hooks(vm_id: str, engine: GuestPool = Depends(get_engine)) -> list[Hook]:
    return await engine.guest(vm_id, _hooks)


@router.post("", response_model=list[Hook], status_code=201, dependencies=[Depends(same_origin)])
async def add_hook(vm_id: str, body: HookCreate, engine: GuestPool = Depends(get_engine)) -> list[Hook]:
    add = _adder(body)

    def apply(g):
        add(g)
        return _hooks(g)

    return await engine.guest(vm_id, apply)


@router.delete("/{name}", status_code=204, dependencies=[Depends(same_origin)])
async def remove_hook(vm_id: str, name: str, engine: GuestPool = Depends(get_engine)) -> Response:
    await engine.guest(vm_id, lambda g: g.hook_remove(name))
    return Response(status_code=204)


@router.get("/events", response_model=HookEvents)
async def events(
    vm_id: str, timeout_ms: int = Query(default=0, ge=0, le=POLL_MAX_MS), engine: GuestPool = Depends(get_engine)
) -> HookEvents:
    def drain(g):
        g.poll(timeout_ms)
        return g.events()

    evs, dropped = await engine.guest(vm_id, drain)
    return HookEvents(events=[HookEvent.model_validate(e, from_attributes=True) for e in evs], dropped=dropped)
