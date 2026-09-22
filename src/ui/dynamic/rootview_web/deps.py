"""FastAPI dependencies.

Shared objects live on ``app.state`` and are reached through these accessors,
so routes never import a concrete backend. Swapping in a different engine is a
change in :func:`rootview_web.app.build_backend` alone.
"""

from __future__ import annotations

from fastapi import Request

from rootview_web.backends.base import IntrospectionBackend
from rootview_web.config import Settings
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
