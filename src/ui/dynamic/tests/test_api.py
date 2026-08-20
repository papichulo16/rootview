"""API and page tests."""

from __future__ import annotations

import pytest

from rootview_web import deliverables
from rootview_web.app import build_backend
from rootview_web.backends.libvmi import LibVMIBackend
from rootview_web.config import Settings
from tests.conftest import FakeBackend, client_with, compromised_snapshot


# --------------------------------------------------------------------------
# with no introspection backend connected -- the default state
# --------------------------------------------------------------------------


def test_health_reports_no_backend(unconfigured_client):
    body = unconfigured_client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["backend_connected"] is False


def test_no_guests_are_listed(unconfigured_client):
    assert unconfigured_client.get("/api/vms").json() == []


def test_snapshot_without_a_backend_is_an_error_not_an_empty_result(unconfigured_client):
    """An empty snapshot could be read as 'nothing suspicious'. It must not be
    what an unconfigured server returns.

    502 rather than 404: the guest id was never the problem, the engine behind
    it is unavailable.
    """
    response = unconfigured_client.get("/api/vms/anything/snapshot")
    assert response.status_code == 502
    assert "No introspection backend is connected" in response.json()["detail"]


def test_dashboard_does_not_claim_a_clean_system(unconfigured_client):
    """The single most important thing this interface must never do."""
    page = unconfigured_client.get("/dashboard").text
    assert "No introspection backend connected" in page
    assert "No suspicious eBPF activity detected" not in page


def test_introspect_explains_it_has_nothing_to_read(unconfigured_client):
    assert "No introspection backend is connected" in unconfigured_client.get("/introspect").text


def test_landing_reports_no_backend(unconfigured_client):
    assert "No introspection backend connected" in unconfigured_client.get("/").text


def test_no_demo_endpoint_exists(unconfigured_client):
    assert unconfigured_client.post("/api/demo/reset").status_code == 404


# --------------------------------------------------------------------------
# with a backend connected
# --------------------------------------------------------------------------


def test_health_reports_a_connected_backend(clean_client):
    assert clean_client.get("/api/health").json()["backend_connected"] is True


def test_list_vms(clean_client):
    assert {vm["vm_id"] for vm in clean_client.get("/api/vms").json()} == {"vm-1", "vm-off"}


def test_get_unknown_vm_is_404(clean_client):
    assert clean_client.get("/api/vms/nope").status_code == 404


def test_snapshot_of_running_guest(clean_client):
    snap = clean_client.get("/api/vms/vm-1/snapshot").json()
    assert snap["vm_id"] == "vm-1"
    assert len(snap["programs"]) == 1
    assert snap["programs"][0]["visibility"] == "visible"


def test_snapshot_of_powered_off_guest_is_empty(clean_client):
    """A powered-off guest has no kernel state; that is an answer, not an error."""
    snap = clean_client.get("/api/vms/vm-off/snapshot").json()
    assert snap["programs"] == []
    assert snap["maps"] == []


def test_clean_guest_produces_no_findings(clean_client):
    assert clean_client.post("/api/vms/vm-1/scan").json()["detections"] == []


def test_scan_finds_a_hidden_program(compromised_client):
    result = compromised_client.post("/api/vms/vm-1/scan").json()
    rules = {d["rule"] for d in result["detections"]}
    assert "hidden_program" in rules
    assert "hidden_map" in rules
    assert result["programs_examined"] == 2


def test_scan_of_unknown_guest_is_404(clean_client):
    assert clean_client.post("/api/vms/nope/scan").status_code == 404


def test_detections_endpoint_filters_by_vm(clean_client):
    detections = clean_client.get("/api/detections", params={"vm_id": "vm-1"}).json()
    assert all(d["vm_id"] == "vm-1" for d in detections)


def test_introspect_page_shows_a_hidden_program(compromised_client):
    response = compromised_client.get("/introspect", params={"vm": "vm-1"})
    assert response.status_code == 200
    assert "concealed" in response.text
    assert "row-hidden" in response.text


def test_introspect_defaults_to_first_running_guest(clean_client):
    response = clean_client.get("/introspect")
    assert response.status_code == 200
    assert "test-guest" in response.text


# --------------------------------------------------------------------------
# pages and schema
# --------------------------------------------------------------------------


def test_landing_page_renders(unconfigured_client):
    response = unconfigured_client.get("/")
    assert response.status_code == 200
    assert "RootView" in response.text
    assert "/dashboard" in response.text


def test_landing_page_holds_no_stream(unconfigured_client):
    """The landing page is static; a connection indicator there would only ever
    read as broken."""
    assert 'id="conn"' not in unconfigured_client.get("/").text


def test_dashboard_page_renders(clean_client):
    response = clean_client.get("/dashboard")
    assert response.status_code == 200
    assert "RootView" in response.text


def test_dashboard_reports_findings_when_they_exist():
    with client_with(FakeBackend(compromised_snapshot())) as c:
        # Force a scan pass so the dashboard has standing findings to render.
        c.app.state.scanner.forget()
        c.portal.call(c.app.state.scanner.scan_once)
        page = c.get("/dashboard").text
    assert "need attention" in page
    assert "Hidden eBPF program" in page


# --------------------------------------------------------------------------
# course project header
# --------------------------------------------------------------------------


def test_landing_shows_project_identity(unconfigured_client):
    page = unconfigured_client.get("/").text
    assert deliverables.PROJECT_NAME in page
    for name, email in deliverables.TEAM:
        assert name in page
        assert f"mailto:{email}" in page
    assert f"mailto:{deliverables.ADVISOR[1]}" in page


def test_landing_lists_every_deliverable(unconfigured_client):
    page = unconfigured_client.get("/").text
    for semester in deliverables.SEMESTERS:
        assert semester["label"].upper() in page.upper()
        for row in semester["rows"]:
            assert row["milestone"] in page
            assert row["due"] in page
            for doc in row["documents"]:
                assert doc["label"] in page


def test_landing_lists_tools_and_challenges(unconfigured_client):
    page = unconfigured_client.get("/").text
    for tool, purpose in deliverables.TOOLS:
        assert tool in page
        assert purpose in page
    for title, detail in deliverables.CHALLENGES:
        assert title in page
        assert detail[:40] in page


def test_landing_lists_every_milestone_task(unconfigured_client):
    page = unconfigured_client.get("/").text
    tasks = [
        task
        for semester in deliverables.SEMESTERS
        for row in semester["rows"]
        for task in row.get("tasks", [])
    ]
    assert len(tasks) > 0
    for task in tasks:
        assert task in page


def test_milestone_dates_come_from_one_source(unconfigured_client):
    """The milestone cards and the deliverables table read the same rows, so a
    date can never be updated in one place and stale in the other."""
    page = unconfigured_client.get("/").text
    for semester in deliverables.SEMESTERS:
        for row in semester["rows"]:
            if not row.get("tasks"):
                continue
            # Once in the deliverables table, once on the milestone card.
            assert page.count(row["due"]) >= 2


def test_unpublished_deliverables_are_not_links(unconfigured_client):
    """A deliverable with no url must not render as a dead hyperlink."""
    page = unconfigured_client.get("/").text
    assert 'href=""' not in page
    assert 'class="doc doc-pending"' in page


def _one_row(documents):
    return [
        {
            "label": "First Semester",
            "rows": [{"milestone": "Plan", "due": "Aug 31", "documents": documents}],
        }
    ]


def test_a_published_deliverable_becomes_a_link(unconfigured_client, monkeypatch):
    """Filling in a url in deliverables.py is all it should take."""
    monkeypatch.setattr(
        deliverables, "SEMESTERS", _one_row([{"label": "Plan", "url": "/static/docs/plan.pdf"}])
    )
    page = unconfigured_client.get("/").text
    assert '<a class="doc" href="/static/docs/plan.pdf">Plan</a>' in page


def test_documents_are_comma_separated_without_stray_spaces(unconfigured_client, monkeypatch):
    """Regression: the separator has to sit tight against both a published link
    and an unpublished one, whichever comes first."""
    monkeypatch.setattr(
        deliverables,
        "SEMESTERS",
        _one_row(
            [
                {"label": "Plan", "url": "/static/docs/plan.pdf"},
                {"label": "Presentation", "url": ""},
                {"label": "Extra", "url": "/static/docs/extra.pdf"},
            ]
        ),
    )
    page = unconfigured_client.get("/").text
    assert "</a>, " in page  # published item followed by a separator
    assert "</span>, " in page  # unpublished item followed by a separator
    assert "</a> ," not in page
    assert "</span> ," not in page


# --------------------------------------------------------------------------
# the not-yet-written LibVMI backend
# --------------------------------------------------------------------------


def test_libvmi_backend_can_be_selected():
    """Selecting the unwritten backend must not stop the server from starting."""
    assert isinstance(build_backend(Settings(backend="libvmi")), LibVMIBackend)


def test_unknown_backend_name_is_rejected():
    with pytest.raises(ValueError):
        build_backend(Settings(backend="nonsense"))


def test_pages_still_render_with_an_unimplemented_backend():
    """Someone filling in the backend should be able to see the interface while
    none of its methods work yet."""
    with client_with(LibVMIBackend()) as c:
        for path in ("/", "/dashboard", "/introspect"):
            assert c.get(path).status_code == 200, path
        assert "No introspection backend connected" in c.get("/dashboard").text


def test_api_reports_unimplemented_as_501():
    """501 says the backend is unwritten; 500 would blame the web server."""
    with client_with(LibVMIBackend()) as c:
        assert c.get("/api/vms").status_code == 501
        assert c.post("/api/vms/x/scan").status_code == 501


def test_openapi_schema_is_generated(unconfigured_client):
    """The researcher-facing Python API will be generated from this."""
    schema = unconfigured_client.get("/openapi.json").json()
    assert "/api/vms/{vm_id}/snapshot" in schema["paths"]
