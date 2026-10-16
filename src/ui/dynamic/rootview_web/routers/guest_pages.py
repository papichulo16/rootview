"""Guest management and per-guest introspection pages."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from rootview_web.backends.base import BackendError
from rootview_web.config import Settings
from rootview_web.deps import get_settings
from rootview_web.routers.vms import details, details_of
from rootview_web.templating import templates

router = APIRouter(include_in_schema=False)


def _engine(request: Request):
    engine = request.app.state.engine
    return engine if engine is not None and engine.ready else None


def _page(request: Request, name: str, settings: Settings, **context) -> HTMLResponse:
    return templates.TemplateResponse(
        request, name, {"settings": settings, "active": "guests", "live": False, **context}
    )


@router.get("/guests", response_class=HTMLResponse)
async def guests(request: Request, settings: Settings = Depends(get_settings)):
    engine = _engine(request)
    vms, error = [], None
    if engine is not None:
        try:
            vms = [details_of(engine, vm) for vm in await engine.vm(engine.prim.list_vms)]
        except BackendError as exc:
            error = str(exc)
    return _page(request, "guests.html", settings, connected=engine is not None, vms=vms, error=error)


@router.get("/guests/{vm_id}", response_class=HTMLResponse)
async def guest(request: Request, vm_id: str, settings: Settings = Depends(get_settings)):
    engine = _engine(request)
    vm, error = None, None
    if engine is not None:
        try:
            vm = await details(engine, vm_id)
        except BackendError as exc:
            error = str(exc)
    status = 404 if engine is not None and vm is None else 200
    response = _page(request, "guest.html", settings, connected=engine is not None, vm=vm, vm_id=vm_id, error=error)
    response.status_code = status
    return response
