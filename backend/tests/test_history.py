import random
from datetime import datetime

import pytest

import app.main as main_module

from .conftest import OPENVAS_DEMOS, upload

OPEN_TOTALS = [20, 20, 19, 20, 18, 18, 18, 15]
FLOW = [(20, 0, 0), (0, 0, 0), (0, 1, 0), (2, 1, 0), (0, 2, 0), (0, 1, 1), (1, 1, 0), (0, 3, 0)]


def total(open_counts: dict) -> int:
    return sum(open_counts.values())


def find(client, text: str, host: str | None = None, status: str = "all") -> dict:
    items = client.get("/api/findings", params={"q": text, "status": status}).json()["items"]
    if host:
        items = [i for i in items if i["host"]["hostname"].startswith(host)]
    assert len(items) == 1, items
    return items[0]


@pytest.fixture
def frozen_now(monkeypatch):
    now = datetime(2026, 11, 26, 12, 0)
    monkeypatch.setattr(main_module, "utcnow", lambda: now)
    return now


def test_each_scan_records_what_changed(openvas_loaded):
    scans = openvas_loaded.get("/api/scans").json()

    assert [(s["new"], s["fixed"], s["reopened"]) for s in scans] == FLOW
    assert [total(s["open"]) for s in scans] == OPEN_TOTALS
    assert all(s["archived"] and s["has_history"] and s["origin"] == "upload" for s in scans)
    assert scans[0]["scan_time"].endswith("Z")  # sent with an explicit UTC marker
    assert scans[-1]["risk_total"] < scans[0]["risk_total"]


def test_a_check_that_errored_does_not_count_as_fixed(openvas_loaded):
    smb = find(openvas_loaded, "EternalBlue")
    timeline = openvas_loaded.get(f"/api/findings/{smb['id']}").json()["timeline"]

    assert [e["kind"] for e in timeline["events"]] == ["new", "fixed"]  # fixed in week 8 only
    assert timeline["events"][1]["at"].startswith("2026-11-22")
    week2 = timeline["sightings"][1]
    assert week2["scan_time"].startswith("2026-10-11") and week2["carried"] is True

    scan2 = openvas_loaded.get("/api/scans").json()[1]
    detail = openvas_loaded.get(f"/api/scans/{scan2['id']}").json()
    assert [f["plugin_name"] for f in detail["carried"]] == [smb["plugin_name"]]
    assert detail["changes"]["fixed"] == []


def test_an_unfinished_host_keeps_its_findings_open(openvas_loaded):
    scan6 = openvas_loaded.get("/api/scans").json()[5]
    detail = openvas_loaded.get(f"/api/scans/{scan6['id']}").json()

    nvr = next(h for h in detail["hosts"] if h["hostname"] == "cam-nvr.home.arpa")
    assert nvr["complete"] is False
    assert {f["host"]["hostname"] for f in detail["carried"]} == {"cam-nvr.home.arpa"}
    assert len(detail["carried"]) == 2
    cert = find(openvas_loaded, "certificate cannot be trusted", host="cam-nvr")
    assert cert["status"] == "open"


def test_reopened_finding_has_a_full_timeline(openvas_loaded):
    tls = find(openvas_loaded, "TLS version 1.0", host="edge-router")
    detail = openvas_loaded.get(f"/api/findings/{tls['id']}").json()

    assert detail["status"] == "fixed"
    kinds = [(e["kind"], e["at"][:10]) for e in detail["timeline"]["events"]]
    assert kinds == [
        ("new", "2026-10-04"),
        ("fixed", "2026-11-01"),
        ("reopened", "2026-11-08"),
        ("fixed", "2026-11-22"),
    ]
    assert len(detail["timeline"]["sightings"]) == 6
    assert detail["qod"] == 98


def test_scan_detail_lists_new_fixed_and_hosts(openvas_loaded):
    scan4 = openvas_loaded.get("/api/scans").json()[3]
    detail = openvas_loaded.get(f"/api/scans/{scan4['id']}").json()

    assert {f["host"]["hostname"] for f in detail["changes"]["new"]} == {"smart-tv.home.arpa"}
    assert [f["plugin_name"] for f in detail["changes"]["fixed"]] == [
        "SNMP agent answers to the default community name"
    ]
    assert len(detail["hosts"]) == 7 and all(h["complete"] for h in detail["hosts"])
    assert openvas_loaded.get("/api/scans/9999").status_code == 404


def test_original_report_can_be_downloaded(openvas_loaded):
    first = openvas_loaded.get("/api/scans").json()[0]

    response = openvas_loaded.get(f"/api/scans/{first['id']}/report")

    assert response.status_code == 200
    assert response.content == OPENVAS_DEMOS[0].read_bytes()
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["content-disposition"].startswith("attachment;")
    assert openvas_loaded.get("/api/scans/9999/report").status_code == 404


def test_trends_summarise_the_whole_history(openvas_loaded, frozen_now):
    trends = openvas_loaded.get("/api/trends").json()

    assert [total(p["open"]) for p in trends["points"]] == OPEN_TOTALS
    assert trends["summary"] == {
        "scans": 8,
        "open_now": 15,
        "open_at_start": 20,
        "new": 3,  # the first scan's 20 are not counted as found
        "fixed": 9,
        "reopened": 1,
        "includes_first_scan": True,
    }
    assert [p["first_scan"] for p in trends["points"]] == [True] + [False] * 7
    fix = trends["fix_times"]
    assert fix["critical"] == {"fixed": 2, "median_days": 21.0, "mean_days": 21.0}
    assert fix["high"]["fixed"] == 3 and fix["high"]["median_days"] == 42.0
    assert fix["critical_and_high"] == {"fixed": 5, "median_days": 28.0, "mean_days": 30.8}
    ages = {b["label"]: total(b["open"]) for b in trends["open_by_age"]}
    assert ages == {"0-30 days": 1, "31-90 days": 14, "Over 90 days": 0}
    nvr = next(h for h in trends["hosts"] if h["hostname"] == "cam-nvr.home.arpa")
    assert total(nvr["open_now"]) == 5 and len(nvr["points"]) == 8


def test_trends_can_be_limited_to_recent_weeks(openvas_loaded, frozen_now):
    trends = openvas_loaded.get("/api/trends", params={"days": 30}).json()

    assert [p["scan_time"][:10] for p in trends["points"]] == [
        "2026-11-01", "2026-11-08", "2026-11-15", "2026-11-22",
    ]
    summary = trends["summary"]
    assert summary["open_at_start"] == 20  # the last scan before the window
    assert summary["includes_first_scan"] is False
    assert (summary["new"], summary["fixed"], summary["reopened"]) == (1, 7, 1)
    assert trends["fix_times"]["critical"]["fixed"] == 1
    assert openvas_loaded.get("/api/trends", params={"days": 0}).status_code == 422


def test_hosts_carry_a_short_history(openvas_loaded):
    hosts = openvas_loaded.get("/api/hosts").json()
    tv = next(h for h in hosts if h["hostname"] == "smart-tv.home.arpa")
    assert [p["total"] for p in tv["history"]] == [2, 2, 2, 2, 1]


def test_reports_imported_out_of_order_give_the_same_trend(client):
    shuffled = OPENVAS_DEMOS[:]
    random.Random(7).shuffle(shuffled)
    assert shuffled != OPENVAS_DEMOS
    for path in shuffled:
        assert upload(client, path).status_code == 201

    scans = client.get("/api/scans").json()
    assert [total(s["open"]) for s in scans] == OPEN_TOTALS


def test_empty_addresses_from_a_network_sweep_are_not_tracked(client):
    data = OPENVAS_DEMOS[0].read_bytes().replace(
        b"<scan_end>",
        b"<host><ip>192.168.50.99</ip><start>2026-10-04T10:00:00Z</start>"
        b"<end>2026-10-04T10:01:00Z</end></host><scan_end>",
        1,
    )
    response = client.post(
        "/api/scans",
        files={"file": ("sweep.xml", data)},
        headers={"X-Requested-With": "vulndash"},
    )
    assert response.status_code == 201 and response.json()["host_count"] == 6
    assert "192.168.50.99" not in {h["ip"] for h in client.get("/api/hosts").json()}


def test_each_scanner_keeps_its_own_open_findings(client):
    """An OpenVAS scan of a host does not hide the Nessus findings still open on it."""
    from .conftest import DEMO_SCANS

    assert upload(client, DEMO_SCANS[-1]).status_code == 201  # Nessus, Nov 22, 18 open
    assert upload(client, OPENVAS_DEMOS[-1]).status_code == 201  # OpenVAS, Nov 22, 15 open

    scans = client.get("/api/scans").json()
    summary = client.get("/api/summary").json()["open"]
    expected = summary["critical"] + summary["high"] + summary["medium"] + summary["low"]
    assert total(scans[-1]["open"]) == expected == 18 + 15
