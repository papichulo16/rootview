"""Tests for the standalone static project page.

The static page and the running application share templates, so a change made
for one can silently break the other. These tests pin the differences that
matter: the static build must contain no link to something only a server can
answer, and it must still carry all the project content.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import build_static_site  # noqa: E402

from rootview_web import deliverables  # noqa: E402


@pytest.fixture(scope="module")
def page() -> str:
    return build_static_site.rewrite_absolute_asset_links(build_static_site.render_page())


def test_no_links_that_need_a_server(page):
    for dead in ('href="/dashboard"', 'href="/introspect"', 'href="/docs"'):
        assert dead not in page


def test_no_javascript(page):
    """Nothing on the static page is live, so it should ship no scripts."""
    assert "app.js" not in page
    assert "<script" not in page


def test_no_backend_status_footer(page):
    """Backend name and scan interval describe a running server."""
    assert "scan interval" not in page
    assert "backend:" not in page


def test_stylesheets_are_relative(page):
    """Absolute /static paths break when served from a subdirectory."""
    assert 'href="static/css/app.css"' in page
    assert 'href="static/css/landing.css"' in page
    assert 'href="/static/' not in page


def test_carries_the_project_identity(page):
    assert deliverables.PROJECT_NAME in page
    for name, email in deliverables.TEAM:
        assert name in page
        assert f"mailto:{email}" in page
    assert deliverables.ADVISOR[0] in page


def test_carries_every_deliverable(page):
    for semester in deliverables.SEMESTERS:
        for row in semester["rows"]:
            assert row["milestone"] in page
            assert row["due"] in page
            for doc in row["documents"]:
                assert doc["label"] in page


def test_carries_tools_challenges_and_tasks(page):
    for tool, purpose in deliverables.TOOLS:
        assert tool in page
        assert purpose in page
    for title, _ in deliverables.CHALLENGES:
        assert title in page
    for semester in deliverables.SEMESTERS:
        for row in semester["rows"]:
            for task in row.get("tasks", []):
                assert task in page


def test_published_documents_keep_their_link(page):
    """Whatever is published in deliverables.py has to survive the build."""
    published = [
        doc
        for semester in deliverables.SEMESTERS
        for row in semester["rows"]
        for doc in row["documents"]
        if doc["url"]
    ]
    for doc in published:
        expected = doc["url"].replace("/static/", "static/", 1)
        assert f'href="{expected}"' in page


def test_local_document_urls_are_rewritten_relative(monkeypatch):
    monkeypatch.setattr(
        deliverables,
        "SEMESTERS",
        [
            {
                "label": "First Semester",
                "rows": [
                    {
                        "milestone": "Plan",
                        "due": "Aug 31",
                        "documents": [{"label": "Plan", "url": "/static/docs/plan.pdf"}],
                    }
                ],
            }
        ],
    )
    html = build_static_site.rewrite_absolute_asset_links(build_static_site.render_page())
    assert 'href="static/docs/plan.pdf"' in html


def test_external_document_urls_are_left_alone(monkeypatch):
    url = "https://example.com/plan.pdf"
    monkeypatch.setattr(
        deliverables,
        "SEMESTERS",
        [
            {
                "label": "First Semester",
                "rows": [
                    {
                        "milestone": "Plan",
                        "due": "Aug 31",
                        "documents": [{"label": "Plan", "url": url}],
                    }
                ],
            }
        ],
    )
    html = build_static_site.rewrite_absolute_asset_links(build_static_site.render_page())
    assert f'href="{url}"' in html
