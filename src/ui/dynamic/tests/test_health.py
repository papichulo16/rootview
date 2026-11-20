"""Health page tests."""

from __future__ import annotations

from rootview_web.backends.base import BackendError
from rootview_web.events import Event
from tests.conftest import FakeBackend, client_with, compromised_snapshot


def test_health_without_a_backend_says_so(unconfigured_client):
    page = unconfigured_client.get("/health").text
    assert "not connected" in page
    assert "No introspection backend is connected" in page


def test_health_is_in_the_nav(unconfigured_client):
    assert 'href="/health"' in unconfigured_client.get("/dashboard").text


def test_health_lists_guests_with_their_last_scan():
    with client_with(FakeBackend(compromised_snapshot())) as c:
        c.portal.call(c.app.state.scanner.scan_once)
        page = c.get("/health").text
    assert "test-guest" in page and "6.8.0" in page
    assert 'data-role="last" data-at="' in page
    assert "2 / 2" in page
    assert "not scanned" in page


def test_health_shows_why_a_guest_could_not_be_scanned():
    backend = FakeBackend()

    async def broken(vm_id):
        raise BackendError("no kernel profile")

    backend.scan = broken
    with client_with(backend) as c:
        c.portal.call(c.app.state.scanner.scan_once)
        page = c.get("/health").text
    assert "could not be scanned" in page
    assert "no kernel profile" in page


def test_scan_event_carries_its_duration():
    with client_with(FakeBackend()) as c:
        result = c.portal.call(c.app.state.scanner.scan_once)[0]
    assert Event.scan(result)["data"]["duration_ms"] >= 0
