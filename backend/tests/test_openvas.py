from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.gmp import (
    GmpAuthError,
    GmpCommandError,
    GmpConnection,
    GmpConnectionError,
    GmpError,
    element,
)
from app.main import _sync_once, create_app
from app.openvas import OpenVasError, icalendar, parse_targets

from .conftest import OPENVAS_DEMOS, WRITE, make_settings, upload
from .gvmd_fake import FakeGvmd

MB = 1024 * 1024


@pytest.fixture
def gvmd(tmp_path):
    fake = FakeGvmd(tmp_path / "gvmd.sock", chunk=997)  # replies arrive in pieces
    yield fake
    fake.close()


@pytest.fixture
def ov_app(gvmd):
    return create_app(
        make_settings(
            openvas_socket=gvmd.path,
            openvas_password="secret",
            openvas_sync_minutes=0,  # tests call the sync directly
        )
    )


@pytest.fixture
def ov_client(ov_app):
    with TestClient(ov_app) as client:
        yield client


# ---------- The protocol client ----------


def test_reply_read_in_pieces_and_status_checked(gvmd):
    gvmd.chunk = 3  # split inside tags and attribute values
    with GmpConnection(gvmd.path, timeout=5, max_reply_bytes=MB) as gmp:
        assert gmp.request(element("get_version")).findtext("version") == "22.8"
        gmp.authenticate("admin", "secret")
        with pytest.raises(GmpCommandError, match="Bogus command"):
            gmp.request(element("get_nonsense"))


def test_wrong_password_is_reported(gvmd):
    with GmpConnection(gvmd.path, timeout=5, max_reply_bytes=MB) as gmp:
        with pytest.raises(GmpAuthError, match="OPENVAS_PASSWORD"):
            gmp.authenticate("admin", "wrong")


def test_reply_with_a_dtd_is_refused(gvmd):
    gvmd.raw_reply = b'<!DOCTYPE x [<!ENTITY a "b">]><get_version_response status="200"/>'
    with GmpConnection(gvmd.path, timeout=5, max_reply_bytes=MB) as gmp:
        with pytest.raises(GmpError, match="not acceptable XML"):
            gmp.request(element("get_version"))


def test_reply_size_is_capped(gvmd):
    gvmd.raw_reply = b'<get_version_response status="200">' + b"x" * 5000 + b"</get_version_response>"
    with GmpConnection(gvmd.path, timeout=5, max_reply_bytes=1000) as gmp:
        with pytest.raises(GmpError, match="larger than"):
            gmp.request(element("get_version"))


def test_missing_socket_is_a_clear_error(tmp_path):
    with pytest.raises(GmpConnectionError, match="does not exist"):
        GmpConnection(str(tmp_path / "nothing.sock"), max_reply_bytes=MB).open()


# ---------- Status and tasks ----------


def test_status_when_not_configured(client):
    status = client.get("/api/openvas/status").json()
    assert status["configured"] is False and status["connected"] is False
    assert client.get("/api/openvas/tasks").status_code == 409
    assert client.post("/api/openvas/sync", headers=WRITE).status_code == 409
    assert client.get("/api/summary").json()["openvas"] == {"configured": False}


def test_status_reports_feed_loading_then_ready(ov_client, gvmd):
    gvmd.loading = True
    loading = ov_client.get("/api/openvas/status").json()
    assert loading["connected"] and loading["feed_loading"] and not loading["ready"]
    assert "loading its vulnerability feed" in loading["message"]

    gvmd.loading = False
    ready = ov_client.get("/api/openvas/status").json()
    assert ready["ready"] and ready["version"] == "22.8"


def test_status_never_exposes_the_password(ov_client):
    assert "secret" not in ov_client.get("/api/openvas/status").text


def test_bad_password_shows_in_status_not_as_a_crash(gvmd):
    app = create_app(make_settings(openvas_socket=gvmd.path, openvas_password="nope", openvas_sync_minutes=0))
    with TestClient(app) as client:
        status = client.get("/api/openvas/status").json()
    assert status["connected"] is False and "rejected" in status["message"]


def test_tasks_are_listed(ov_client, gvmd):
    gvmd.tasks_xml = """
      <task id="11111111-1111-4111-8111-111111111111"><name>Home LAN</name><status>Running</status>
        <progress>42</progress><target id="x"><name>LAN</name></target>
        <config id="c"><name>Full and fast</name></config><report_count>3<finished>2</finished></report_count>
        <last_report><report id="r9"><timestamp>2026-11-20T10:00:00Z</timestamp></report></last_report>
        <schedule id="s"><name>Weekly</name></schedule><usage_type>scan</usage_type></task>
      <task id="22222222-2222-4222-8222-222222222222"><name>Policy audit</name><status>Done</status>
        <usage_type>audit</usage_type></task>"""

    tasks = ov_client.get("/api/openvas/tasks").json()

    assert [t["name"] for t in tasks] == ["Home LAN"]  # compliance audits are left out
    task = tasks[0]
    assert task["status"] == "Running" and task["progress"] == 42 and task["reports"] == 3
    assert task["schedule"] == "Weekly" and task["last_report_imported"] is False


def test_start_task(ov_client, gvmd):
    task_id = "11111111-1111-4111-8111-111111111111"
    response = ov_client.post(f"/api/openvas/tasks/{task_id}/start", headers=WRITE)
    assert response.status_code == 202
    assert gvmd.sent("start_task")[0].get("task_id") == task_id
    assert ov_client.post("/api/openvas/tasks/not-a-task/start", headers=WRITE).status_code == 422
    assert ov_client.post(f"/api/openvas/tasks/{task_id}/start").status_code == 403  # CSRF


# ---------- Sync ----------


def test_sync_imports_finished_reports_oldest_first_and_once(ov_client, gvmd):
    for path in reversed(OPENVAS_DEMOS[:3]):  # listed newest first on purpose
        gvmd.add_report(path)
    gvmd.add_report(None, status="Running", report_id="aaaaaaaa-0000-4000-8000-000000000001")
    gvmd.add_report(None, status="Interrupted", report_id="aaaaaaaa-0000-4000-8000-000000000002")

    outcome = ov_client.post("/api/openvas/sync", headers=WRITE).json()

    assert [i["scan_time"][:10] for i in outcome["imported"]] == ["2026-10-04", "2026-10-11", "2026-10-18"]
    assert outcome["waiting"] == 1 and outcome["unfinished"] == 1 and outcome["errors"] == []
    fetch = [c for c in gvmd.sent("get_reports") if c.get("report_id")][0]
    assert "min_qod=70" in fetch.get("filter") and "apply_overrides=1" in fetch.get("filter")
    assert fetch.get("details") == "1"

    scans = ov_client.get("/api/scans").json()
    assert [s["origin"] for s in scans] == ["openvas-sync"] * 3
    assert all(s["archived"] and s["task_name"] == "Home network weekly" for s in scans)
    assert [(s["new"], s["fixed"]) for s in scans] == [(20, 0), (0, 0), (0, 1)]

    again = ov_client.post("/api/openvas/sync", headers=WRITE).json()
    assert again["imported"] == []
    # The same report downloaded by hand from Greenbone is recognised too.
    assert upload(ov_client, OPENVAS_DEMOS[0]).status_code == 409
    status = ov_client.get("/api/openvas/status").json()
    assert status["last_sync"]["error"] is None


def test_sync_skips_a_broken_report_and_keeps_going(ov_client, gvmd):
    gvmd.add_report(OPENVAS_DEMOS[0])
    broken = gvmd.add_report(None, report_id="bbbbbbbb-0000-4000-8000-000000000001", time="2026-10-05T10:00:00Z")
    gvmd.reports[broken]["xml"] = b'<report id="x"><name>no results</name></report>'

    outcome = ov_client.post("/api/openvas/sync", headers=WRITE).json()

    assert len(outcome["imported"]) == 1
    assert len(outcome["errors"]) == 1 and "no results section" in outcome["errors"][0]


def test_background_sync_records_its_outcome(ov_app, ov_client, gvmd):
    gvmd.add_report(OPENVAS_DEMOS[0])
    _sync_once(ov_app)
    assert len(ov_app.state.openvas.last_sync["imported"]) == 1

    ov_app.state.openvas.sync_lock.acquire()
    try:
        response = ov_client.post("/api/openvas/sync", headers=WRITE)
        assert response.status_code == 409 and "already running" in response.json()["detail"]
        _sync_once(ov_app)  # quietly does nothing while another sync runs
    finally:
        ov_app.state.openvas.sync_lock.release()


# ---------- Creating scans ----------


def test_create_scan_starts_it_with_escaped_values(ov_client, gvmd):
    response = ov_client.post(
        "/api/openvas/tasks",
        json={"name": "Home <b>LAN</b> & lab", "targets": "192.168.50.0/24, nas01.local", "consider_alive": True},
        headers=WRITE,
    )

    assert response.status_code == 201, response.text
    assert response.json()["started"] is True
    target = gvmd.sent("create_target")[0]
    assert target.findtext("hosts") == "192.168.50.0/24,nas01.local"
    assert [t.text for t in target.findall("alive_tests/alive_test")] == ["Consider Alive"]
    assert target.find("port_list").get("id") == "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
    task = gvmd.sent("create_task")[0]
    assert task.findtext("name") == "Home bLANb lab"  # markup characters are dropped
    assert task.find("config").get("id") == "daba56c8-73ec-11df-a475-002264764cea"
    assert task.find("schedule") is None
    assert len(gvmd.sent("start_task")) == 1


def test_create_weekly_scan_makes_a_schedule_instead_of_starting(ov_client, gvmd):
    start = (datetime.now(UTC) + timedelta(days=1)).replace(microsecond=0)
    response = ov_client.post(
        "/api/openvas/tasks",
        json={
            "name": "Weekly",
            "targets": "192.168.50.10",
            "consider_alive": False,
            "repeat": "weekly",
            "start_at": start.isoformat(),
            "timezone": "America/Los_Angeles",
        },
        headers=WRITE,
    )

    assert response.status_code == 201, response.text
    assert response.json()["started"] is False
    schedule = gvmd.sent("create_schedule")[0]
    assert "RRULE:FREQ=WEEKLY" in schedule.findtext("icalendar")
    assert f"DTSTART:{start:%Y%m%dT%H%M%SZ}" in schedule.findtext("icalendar")
    assert schedule.findtext("timezone") == "America/Los_Angeles"
    alive = [t.text for t in gvmd.sent("create_target")[0].findall("alive_tests/alive_test")]
    assert alive == ["ICMP Ping", "TCP-ACK Service Ping", "ARP Ping"]
    assert gvmd.sent("create_task")[0].find("schedule") is not None
    assert gvmd.sent("start_task") == []


def test_create_scan_refuses_public_targets(ov_client, gvmd):
    for targets in ("8.8.8.8", "example.com", "192.168.1.0/16, 1.1.1.1"):
        response = ov_client.post(
            "/api/openvas/tasks", json={"name": "x", "targets": targets}, headers=WRITE
        )
        assert response.status_code == 400, targets
    assert gvmd.sent("create_target") == []


def test_create_scan_waits_for_the_feed(ov_client, gvmd):
    gvmd.loading = True
    response = ov_client.post(
        "/api/openvas/tasks", json={"name": "x", "targets": "10.0.0.1"}, headers=WRITE
    )
    assert response.status_code == 400 and "not finished loading" in response.json()["detail"]


@pytest.mark.parametrize(
    "text",
    ["192.168.1.10", "192.168.1.0/24", "192.168.1.10-20", "192.168.1.10-192.168.1.40",
     "10.0.0.1, 172.16.5.5", "fd00::1", "fe80::1", "nas01", "printer.lan", "cam.home.arpa"],
)
def test_private_targets_are_accepted(text):
    assert parse_targets(text)


@pytest.mark.parametrize(
    ("text", "message"),
    [("", "at least one"), ("8.8.8.8", "public"), ("scanme.nmap.org", "own network"),
     ("10.0.0.0/8", "addresses"), ("999.1.1.1", "not an IP"), ("a;b<c>", "not an IP"),
     (" ".join(f"10.0.0.{n}" for n in range(40)), "at most")],
)
def test_bad_targets_are_refused(text, message):
    with pytest.raises(OpenVasError, match=message):
        parse_targets(text)


def test_public_targets_can_be_allowed_on_purpose():
    assert parse_targets("8.8.8.8, example.com", allow_public=True) == ["8.8.8.8", "example.com"]


def test_icalendar_shape():
    now = datetime(2026, 11, 26, 12, 0)
    text = icalendar(datetime(2026, 11, 29, 10, 0), "daily", now)
    assert text.startswith("BEGIN:VCALENDAR\r\n") and text.endswith("END:VCALENDAR\r\n")
    assert "DTSTART:20261129T100000Z" in text and "RRULE:FREQ=DAILY" in text
    assert "RRULE" not in icalendar(datetime(2026, 11, 29, 10, 0), "none", now)
