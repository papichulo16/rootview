"""The engine itself: whether it is up, and every guest it manages."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from rootview_web.deps import get_engine
from rootview_web.engine import GuestPool
from rootview_web.engine.schemas import EngineStatus, VmDetails
from rootview_web.routers.vms import details_of

router = APIRouter(prefix="/api/engine", tags=["engine"])


@router.get("", response_model=EngineStatus)
async def status(request: Request) -> EngineStatus:
    engine = request.app.state.engine
    return EngineStatus(
        connected=engine is not None and engine.ready,
        allow_writes=request.app.state.settings.allow_writes,
    )


@router.get("/vms", response_model=list[VmDetails])
async def vms(engine: GuestPool = Depends(get_engine)) -> list[VmDetails]:
    return [details_of(engine, vm) for vm in await engine.vm(engine.prim.list_vms)]
