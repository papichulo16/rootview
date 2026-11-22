"""Phones on adb, listed the way /api/vms lists guests. Attached ones are
introspected through the same /api/vms/{serial}/... routes as a guest."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from rootview_web.deps import get_engine
from rootview_web.engine import GuestPool
from rootview_web.engine.schemas import PhoneDetails

router = APIRouter(prefix="/api/phones", tags=["phones"])


def details_of(engine: GuestPool, phone) -> PhoneDetails:
    g = engine.attached(phone.serial)
    return PhoneDetails(
        serial=phone.serial,
        state=phone.state,
        model=phone.model,
        product=phone.product,
        pkvmi=phone.pkvmi,
        connected=phone.connected,
        attached=g is not None,
        profile_loaded=g is not None and g.profiled,
        profile_error=engine.profile_errors.get(phone.serial),
    )


async def details(engine: GuestPool, serial: str) -> PhoneDetails:
    return details_of(engine, await engine.vm(engine.prim.inspect_phone, serial))


@router.get("", response_model=list[PhoneDetails])
async def list_phones(engine: GuestPool = Depends(get_engine)) -> list[PhoneDetails]:
    return [details_of(engine, p) for p in await engine.vm(engine.prim.list_phones)]


@router.get("/{serial}/details", response_model=PhoneDetails)
async def inspect(serial: str, engine: GuestPool = Depends(get_engine)) -> PhoneDetails:
    return await details(engine, serial)
