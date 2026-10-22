"""Guest lifecycle, as ``rv vm`` does it."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response

from rootview_web.deps import get_engine, same_origin
from rootview_web.engine import GuestPool
from rootview_web.engine.schemas import VmCreate, VmDetails

router = APIRouter(prefix="/api/vms", tags=["vms"])


def details_of(engine: GuestPool, vm) -> VmDetails:
    g = engine.attached(vm.name)
    return VmDetails.model_validate(
        {
            **VmDetails.model_validate(vm, from_attributes=True).model_dump(),
            "attached": g is not None,
            "profile_loaded": g is not None and g.profiled,
            "profile_error": engine.profile_errors.get(vm.name),
        }
    )


async def details(engine: GuestPool, vm_id: str) -> VmDetails:
    return details_of(engine, await engine.vm(engine.prim.inspect_vm, vm_id))


@router.get("/{vm_id}/details", response_model=VmDetails)
async def inspect(vm_id: str, engine: GuestPool = Depends(get_engine)) -> VmDetails:
    return await details(engine, vm_id)


@router.post("", response_model=VmDetails, status_code=201, dependencies=[Depends(same_origin)])
async def create(body: VmCreate, engine: GuestPool = Depends(get_engine)) -> VmDetails:
    settings = body.model_dump(exclude_none=True, exclude={"name"})
    await engine.vm(lambda: engine.prim.create_vm(body.name, **settings))
    return await details(engine, body.name)


@router.post("/{vm_id}/start", response_model=VmDetails, dependencies=[Depends(same_origin)])
async def start(vm_id: str, engine: GuestPool = Depends(get_engine)) -> VmDetails:
    await engine.lifecycle(vm_id, engine.prim.start_vm)
    return await details(engine, vm_id)


@router.post("/{vm_id}/stop", response_model=VmDetails, dependencies=[Depends(same_origin)])
async def stop(vm_id: str, engine: GuestPool = Depends(get_engine)) -> VmDetails:
    await engine.lifecycle(vm_id, engine.prim.stop_vm)
    return await details(engine, vm_id)


@router.post("/{vm_id}/restart", response_model=VmDetails, dependencies=[Depends(same_origin)])
async def restart(vm_id: str, engine: GuestPool = Depends(get_engine)) -> VmDetails:
    await engine.lifecycle(vm_id, engine.prim.restart_vm)
    return await details(engine, vm_id)


@router.delete("/{vm_id}", status_code=204, dependencies=[Depends(same_origin)])
async def destroy(vm_id: str, force: bool = False, engine: GuestPool = Depends(get_engine)) -> Response:
    await engine.lifecycle(vm_id, engine.prim.destroy_vm, force)
    return Response(status_code=204)
