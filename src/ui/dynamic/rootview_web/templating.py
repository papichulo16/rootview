"""Jinja2 environment shared by the page routes."""

from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

TEMPLATE_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def _severity_rank(severity: str) -> int:
    """Sort key for severities, most urgent first. Exposed to templates."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(severity, 5)


templates.env.filters["severity_rank"] = _severity_rank
