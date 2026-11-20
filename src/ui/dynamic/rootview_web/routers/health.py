"""System health page: the engine, the scanner, and each guest's kernel."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from rootview_web.backends.base import IntrospectionBackend
from rootview_web.config import Settings
from rootview_web.deps import get_backend, get_bus, get_scanner, get_settings
from rootview_web.events import EventBus
from rootview_web.routers.pages import safe_list_vms
from rootview_web.services import ScannerService
from rootview_web.templating import templates

router = APIRouter(include_in_schema=False)


@router.get("/health", response_class=HTMLResponse)
async def health(
    request: Request,
    backend: IntrospectionBackend = Depends(get_backend),
    scanner: ScannerService = Depends(get_scanner),
    bus: EventBus = Depends(get_bus),
    settings: Settings = Depends(get_settings),
):
    engine = request.app.state.engine
    engine_ready = engine is not None and engine.ready
    rows = [
        {
            "vm": vm,
            "scan": scanner.latest(vm.vm_id),
            "error": scanner.errors.get(vm.vm_id),
            "profile_error": engine.profile_errors.get(vm.vm_id) if engine_ready else None,
        }
        for vm in await safe_list_vms(backend)
    ]
    return templates.TemplateResponse(
        request,
        "health.html",
        {
            "rows": rows,
            "connected": backend.connected,
            "engine_ready": engine_ready,
            "scanner_running": scanner.running,
            "subscribers": bus.subscriber_count,
            "settings": settings,
            "active": "health",
            "live": True,
        },
    )
