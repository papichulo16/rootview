"""JSON API.

This is the same surface the researcher-facing Python API will wrap, so it is
kept explicit and typed rather than shaped around what the current pages
happen to need. FastAPI generates OpenAPI docs from these signatures at /docs.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from rootview_web.backends.base import BackendError, IntrospectionBackend, UnknownVMError
from rootview_web.config import Settings
from rootview_web.deps import get_backend, get_bus, get_scanner, get_settings
from rootview_web.events import EventBus, sse_source
from rootview_web.schemas import BpfSnapshot, Detection, ScanResult, VM
from rootview_web.services import ScannerService

router = APIRouter(prefix="/api", tags=["api"])


@router.get("/health")
async def health(
    settings: Settings = Depends(get_settings),
    backend: IntrospectionBackend = Depends(get_backend),
    scanner: ScannerService = Depends(get_scanner),
    bus: EventBus = Depends(get_bus),
) -> dict:
    """Liveness plus enough state to tell whether detection is actually running.

    ``backend_connected`` is the one to watch: the web server can be perfectly
    healthy while reading no guest at all.
    """
    return {
        "status": "ok",
        "backend": settings.backend,
        "backend_connected": backend.connected,
        "scanner_running": scanner.running,
        "scan_interval": settings.scan_interval,
        "subscribers": bus.subscriber_count,
    }


@router.get("/vms", response_model=list[VM])
async def list_vms(backend: IntrospectionBackend = Depends(get_backend)) -> list[VM]:
    """Every guest RootView can introspect."""
    return await backend.list_vms()


@router.get("/vms/{vm_id}", response_model=VM)
async def get_vm(vm_id: str, backend: IntrospectionBackend = Depends(get_backend)) -> VM:
    return await backend.get_vm(vm_id)


@router.get("/vms/{vm_id}/snapshot", response_model=BpfSnapshot)
async def get_snapshot(
    vm_id: str, backend: IntrospectionBackend = Depends(get_backend)
) -> BpfSnapshot:
    """Raw eBPF state of a guest, with no detection logic applied.

    This is what the advanced introspection view renders.
    """
    try:
        return await backend.snapshot(vm_id)
    except UnknownVMError:
        # Subclass of BackendError, so it has to be re-raised ahead of the
        # generic handler below to reach the 404 handler instead of becoming a 502.
        raise
    except BackendError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/vms/{vm_id}/scan", response_model=ScanResult)
async def scan_vm(
    vm_id: str, backend: IntrospectionBackend = Depends(get_backend)
) -> ScanResult:
    """Run the detection rules against a guest right now.

    Does not wait for the polling interval. Findings from an on-demand scan are
    returned to the caller but are not published to the event stream, so a user
    clicking "scan now" does not spam every other open dashboard.
    """
    try:
        return await backend.scan(vm_id)
    except UnknownVMError:
        raise
    except BackendError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/detections", response_model=list[Detection])
async def list_detections(
    vm_id: str | None = None,
    scanner: ScannerService = Depends(get_scanner),
) -> list[Detection]:
    """Currently-standing findings from the most recent scan of each guest."""
    detections = scanner.all_detections()
    if vm_id is not None:
        detections = [d for d in detections if d.vm_id == vm_id]
    return detections


@router.get("/stream")
async def stream(bus: EventBus = Depends(get_bus)) -> StreamingResponse:
    """Live event stream consumed by the dashboard over Server-Sent Events."""
    return StreamingResponse(
        sse_source(bus),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            # Tells nginx not to buffer the response, which would otherwise
            # hold events until the buffer filled.
            "X-Accel-Buffering": "no",
        },
    )
