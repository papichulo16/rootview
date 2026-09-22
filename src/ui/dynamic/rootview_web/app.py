"""Application factory and wiring."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from rootview_web.backends.base import IntrospectionBackend, UnknownVMError
from rootview_web.backends.libvmi import LibVMIBackend
from rootview_web.backends.unconfigured import UnconfiguredBackend
from rootview_web.config import Settings
from rootview_web.events import EventBus
from rootview_web.routers import api, pages
from rootview_web.services import ScannerService
from rootview_web.templating import STATIC_DIR

log = logging.getLogger(__name__)


def build_backend(settings: Settings) -> IntrospectionBackend:
    """Choose the introspection backend.

    The single place that knows about concrete backends. When the LibVMI engine
    is ready it gets added here as another branch; nothing else in the web
    server changes.
    """
    if settings.backend == "none":
        return UnconfiguredBackend()
    if settings.backend == "libvmi":
        return LibVMIBackend()
    raise ValueError(
        f"unknown backend {settings.backend!r}; expected 'none' or 'libvmi'"
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await app.state.scanner.start()
        log.info(
            "RootView web server up: backend=%s scan_interval=%ss",
            settings.backend,
            settings.scan_interval,
        )
        try:
            yield
        finally:
            await app.state.scanner.stop()

    app = FastAPI(
        title="RootView",
        description="Hypervisor-based eBPF rootkit detection for KVM guests.",
        version="0.1.0",
        lifespan=lifespan,
    )

    backend = build_backend(settings)
    bus = EventBus()
    app.state.settings = settings
    app.state.backend = backend
    app.state.bus = bus
    app.state.scanner = ScannerService(backend, bus, interval=settings.scan_interval)

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(api.router)
    app.include_router(pages.router)

    @app.exception_handler(UnknownVMError)
    async def _unknown_vm(request: Request, exc: UnknownVMError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(NotImplementedError)
    async def _not_implemented(request: Request, exc: NotImplementedError) -> JSONResponse:
        # Reached while a backend is still being written. 501 says exactly that,
        # where a 500 would suggest the web server itself is broken.
        return JSONResponse(status_code=501, content={"detail": str(exc)})

    return app


#: Module-level app for ``uvicorn rootview_web.app:app``.
app = create_app()
