"""FastAPI dependencies.

Shared objects live on ``app.state`` and are reached through these accessors,
so routes never import a concrete backend. Swapping in a different engine is a
change in :func:`rootview_web.app.build_backend` alone.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import HTTPException, Request

from rootview_web.backends.base import IntrospectionBackend
from rootview_web.config import Settings
from rootview_web.engine import GuestPool
from rootview_web.events import EventBus
from rootview_web.services import ScannerService


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_backend(request: Request) -> IntrospectionBackend:
    return request.app.state.backend


def get_bus(request: Request) -> EventBus:
    return request.app.state.bus


def get_scanner(request: Request) -> ScannerService:
    return request.app.state.scanner


def get_engine(request: Request) -> GuestPool:
    engine = request.app.state.engine
    if engine is None or not engine.ready:
        raise HTTPException(status_code=503, detail="no introspection engine (ROOTVIEW_BACKEND=libvmi)")
    return engine


def same_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin and urlsplit(origin).netloc != request.headers.get("host"):
        raise HTTPException(status_code=403, detail="cross-origin request refused")


def writes_allowed(request: Request) -> None:
    if not request.app.state.settings.allow_writes:
        raise HTTPException(status_code=403, detail="guest writes are disabled (ROOTVIEW_ALLOW_WRITES=1)")
