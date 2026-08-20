"""HTML pages.

A landing page explaining the project, plus the two live views from the project
plan: a dashboard that just says whether anything is wrong, and an introspection
view for someone who wants to read the guest's eBPF state themselves.

The live pages are server-rendered for their initial state and then updated in
place from the event stream, so there is no build step and no client-side
router. The landing page is static and opens no stream.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from rootview_web import deliverables
from rootview_web.backends.base import BackendError, IntrospectionBackend
from rootview_web.config import Settings
from rootview_web.deps import get_backend, get_scanner, get_settings
from rootview_web.schemas import VMState
from rootview_web.services import ScannerService
from rootview_web.templating import templates

router = APIRouter(include_in_schema=False)


async def safe_list_vms(backend: IntrospectionBackend) -> list:
    """List guests, treating any backend failure as "no guests".

    Pages must render whatever the engine is doing. A backend that is
    unavailable, half-written, or raising is a state the interface has to
    display, not a 500. The verdict logic reports the situation honestly, so
    an empty list here never becomes a false all-clear.
    """
    try:
        return await backend.list_vms()
    except (BackendError, NotImplementedError):
        return []


def verdict_state(
    backend: IntrospectionBackend,
    scanner: ScannerService,
    detections: list,
) -> str:
    """Decide what the dashboard is allowed to claim.

    The distinction that matters is between ``clear`` and the two states that
    are not clear. Telling a user "no suspicious activity detected" when
    nothing has been examined is worse than telling them nothing at all, so an
    all-clear is only returned once a scan has actually completed.
    """
    if detections:
        return "alert"
    if not backend.connected:
        return "unconfigured"
    if not scanner.has_results:
        return "pending"
    return "clear"


@router.get("/", response_class=HTMLResponse)
async def landing(
    request: Request,
    backend: IntrospectionBackend = Depends(get_backend),
    settings: Settings = Depends(get_settings),
):
    """Explains what RootView is, for someone arriving with no context.

    Deliberately static: no event stream, nothing that depends on a guest being
    reachable, so the page still works as an explanation when no VM is running.
    The only live number is the guest count, and it degrades to nothing if the
    backend cannot answer.
    """
    vms = await safe_list_vms(backend)
    return templates.TemplateResponse(
        request,
        "landing.html",
        {
            "vms": vms,
            "running_count": sum(1 for v in vms if v.state is VMState.RUNNING),
            "connected": backend.connected,
            "project_name": deliverables.PROJECT_NAME,
            "team": deliverables.TEAM,
            "advisor": deliverables.ADVISOR,
            "semesters": deliverables.SEMESTERS,
            "tools": deliverables.TOOLS,
            "challenges": deliverables.CHALLENGES,
            "settings": settings,
            "active": "home",
            "live": False,
        },
    )


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    backend: IntrospectionBackend = Depends(get_backend),
    scanner: ScannerService = Depends(get_scanner),
    settings: Settings = Depends(get_settings),
):
    """The simple view: is anything wrong, and how bad."""
    vms = await safe_list_vms(backend)
    detections = scanner.all_detections()
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "vms": vms,
            "detections": detections,
            "verdict": verdict_state(backend, scanner, detections),
            "settings": settings,
            "active": "dashboard",
            "live": True,
        },
    )


@router.get("/introspect", response_class=HTMLResponse)
async def introspect(
    request: Request,
    vm: str | None = None,
    backend: IntrospectionBackend = Depends(get_backend),
    settings: Settings = Depends(get_settings),
):
    """The advanced view: the raw eBPF state of one guest."""
    vms = await safe_list_vms(backend)
    running = [v for v in vms if v.state is VMState.RUNNING]
    # Default to the first running guest so the page is never empty on load.
    selected = vm or (running[0].vm_id if running else None)

    snapshot = None
    error = None
    if selected is not None:
        try:
            snapshot = await backend.snapshot(selected)
        except (BackendError, NotImplementedError) as exc:
            error = str(exc)

    return templates.TemplateResponse(
        request,
        "introspect.html",
        {
            "vms": vms,
            "selected": selected,
            "snapshot": snapshot,
            "error": error,
            "connected": backend.connected,
            "settings": settings,
            "active": "introspect",
            "live": True,
        },
    )
