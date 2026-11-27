from fastapi.testclient import TestClient

from app.main import create_app

from .conftest import DEMO_SCANS, WRITE, make_settings, upload_bytes


def test_health_and_empty_dashboard(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    summary = client.get("/api/summary").json()
    assert summary["hosts"] == 0 and summary["last_scan"] is None
    assert client.get("/api/findings").json() == {"total": 0, "items": []}


def test_dashboard_page_is_served_with_security_headers(client):
    response = client.get("/")

    assert response.status_code == 200
    assert "HomeLab Vuln Dashboard" in response.text
    csp = response.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "unsafe-inline" not in csp
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"


def test_page_makes_no_third_party_requests(client):
    for path in ("/", "/app.js", "/styles.css"):
        text = client.get(path).text
        assert "http://" not in text.replace("http://www.w3.org/2000/svg", "")
        assert "https://" not in text


def test_writes_need_the_custom_header(client):
    """A cross-site form or image tag cannot add this header, which blocks CSRF."""
    assert client.post("/api/intel/refresh").status_code == 403
    assert client.patch("/api/hosts/1", json={"criticality": 5}).status_code == 403
    assert client.post("/api/scans", files={"file": ("a.nessus", b"x")}).status_code == 403


def test_unknown_host_header_is_refused(client):
    """Stops DNS rebinding: a hostile site resolving its own name to 127.0.0.1."""
    assert client.get("/api/summary", headers={"Host": "evil.example"}).status_code == 400


def test_api_docs_are_off_by_default(client):
    assert client.get("/api/docs").status_code == 404
    with TestClient(create_app(make_settings(enable_api_docs=True))) as with_docs:
        assert with_docs.get("/api/docs").status_code == 200


def test_upload_rejects_bad_files(client):
    assert upload_bytes(client, b"").status_code == 400
    assert upload_bytes(client, b"MZ\x90\x00 not xml").status_code == 400
    wrong = upload_bytes(client, b"<?xml version='1.0'?><nmaprun/>")
    assert wrong.status_code == 400 and "Nessus" in wrong.json()["detail"]
    assert client.get("/api/scans").json() == []


def test_upload_size_limit():
    with TestClient(create_app(make_settings(max_upload_mb=0))) as small:
        response = upload_bytes(small, b"x" * 200_000)
    assert response.status_code == 413


def test_uploaded_filename_is_sanitised(client):
    data = DEMO_SCANS[0].read_bytes()
    response = upload_bytes(client, data, name="../../etc/<script>alert(1)</script>.nessus")

    assert response.status_code == 201
    assert response.json()["filename"] == "script_.nessus"


def test_summary_after_demo_scans(loaded):
    summary = loaded.get("/api/summary").json()

    assert summary["open"] == {"critical": 2, "high": 4, "medium": 8, "low": 4, "info": 6}
    assert summary["hosts"] == 6
    assert summary["kev_open"] == 0  # no threat intel loaded yet
    assert summary["last_scan"]["filename"] == "demo-scan-3-2026-11-22.nessus"
    assert summary["intel_updated_at"] is None
    assert len(loaded.get("/api/scans").json()) == 3


def test_findings_are_ranked_and_filterable(loaded):
    everything = loaded.get("/api/findings").json()
    assert everything["total"] == 18
    scores = [item["risk_score"] for item in everything["items"]]
    assert scores == sorted(scores, reverse=True)
    assert everything["items"][0]["severity_label"] == "Critical"

    assert loaded.get("/api/findings", params={"min_severity": 4}).json()["total"] == 2
    assert loaded.get("/api/findings", params={"min_severity": 0}).json()["total"] == 24
    fixed = loaded.get("/api/findings", params={"status": "fixed"}).json()
    assert {item["plugin_id"] for item in fixed["items"]} == {"900001", "900006", "900013"}
    assert loaded.get("/api/findings", params={"status": "all"}).json()["total"] == 21

    by_cve = loaded.get("/api/findings", params={"q": "cve-2014-0160"}).json()
    assert [item["plugin_id"] for item in by_cve["items"]] == ["900003"]
    by_name = loaded.get("/api/findings", params={"q": "smb"}).json()
    assert by_name["total"] == 3
    assert loaded.get("/api/findings", params={"q": "%"}).json()["total"] == 0  # no wildcards

    page = loaded.get("/api/findings", params={"limit": 5, "offset": 15}).json()
    assert page["total"] == 18 and len(page["items"]) == 3
    assert loaded.get("/api/findings", params={"limit": 5000}).status_code == 422
    assert loaded.get("/api/findings", params={"status": "open; drop table"}).status_code == 422


def test_finding_detail_explains_its_score(loaded):
    top = loaded.get("/api/findings", params={"q": "default administrator"}).json()["items"][0]

    detail = loaded.get(f"/api/findings/{top['id']}").json()

    assert detail["host"]["hostname"] == "CAM-NVR"
    assert detail["age_days"] >= 0
    assert detail["risk_breakdown"] == {
        "cvss_used": 9.8,
        "cvss_points": 58.8,
        "epss_points": 0.0,
        "kev_points": 0.0,
        "criticality_multiplier": 1.0,
        "score": 58.8,
    }
    assert loaded.get("/api/findings/999999").status_code == 404


def test_hosts_are_ranked_by_top_risk(loaded):
    hosts = loaded.get("/api/hosts").json()

    assert len(hosts) == 6
    assert [h["max_risk"] for h in hosts] == sorted((h["max_risk"] for h in hosts), reverse=True)
    nvr = next(h for h in hosts if h["hostname"] == "CAM-NVR")
    assert nvr["open"] == {"critical": 1, "high": 1, "medium": 2, "low": 1}
    desktop = next(h for h in hosts if h["hostname"] == "GAMING-PC")
    assert desktop["open"] == {"critical": 0, "high": 0, "medium": 1, "low": 0}


def test_host_criticality_rescales_risk(loaded):
    nas = next(h for h in loaded.get("/api/hosts").json() if h["hostname"] == "NAS01")
    assert nas["max_risk"] == 58.8

    response = loaded.patch(f"/api/hosts/{nas['id']}", json={"criticality": 5}, headers=WRITE)

    assert response.status_code == 200
    after = next(h for h in loaded.get("/api/hosts").json() if h["hostname"] == "NAS01")
    assert after["criticality"] == 5 and after["max_risk"] == 70.6  # 58.8 x 1.2
    assert (
        loaded.patch(f"/api/hosts/{nas['id']}", json={"criticality": 9}, headers=WRITE).status_code
        == 422
    )
    assert (
        loaded.patch("/api/hosts/99999", json={"criticality": 2}, headers=WRITE).status_code == 404
    )
