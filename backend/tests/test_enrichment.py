import httpx2
import pytest
from sqlalchemy import select

from app.enrichment import IntelError, chunk_cves, fetch_epss, fetch_kev
from app.models import Finding

from .conftest import WRITE, make_settings

KEV_FEED = {
    "catalogVersion": "2026.11.20",
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        },
        {"cveID": "CVE-2017-0144", "dateAdded": "2022-02-10", "dueDate": "not a date"},
        "garbage entry",
    ],
}


def fake_feeds(requests: list[httpx2.Request] | None = None) -> httpx2.Client:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if requests is not None:
            requests.append(request)
        if request.url.host == "www.cisa.gov":
            return httpx2.Response(200, json=KEV_FEED)
        asked = request.url.params["cve"].split(",")
        data = [{"cve": "CVE-1900-0001", "epss": "0.5", "percentile": "0.5"}]  # never asked for
        if "CVE-2021-44228" in asked:
            data.append({"cve": "CVE-2021-44228", "epss": "0.944", "percentile": "0.999"})
        if "CVE-2017-0144" in asked:
            data.append({"cve": "CVE-2017-0144", "epss": "7", "percentile": "nope"})  # invalid
        return httpx2.Response(200, json={"status": "OK", "data": data})

    return httpx2.Client(transport=httpx2.MockTransport(handler))


def test_fetch_kev_reads_entries_and_skips_garbage():
    entries, version = fetch_kev(fake_feeds(), make_settings().kev_url)

    assert version == "2026.11.20"
    assert set(entries) == {"CVE-2021-44228", "CVE-2017-0144"}
    assert entries["CVE-2021-44228"].ransomware is True
    assert entries["CVE-2017-0144"].due_date is None


def test_fetch_epss_only_accepts_requested_cves_and_valid_scores():
    scores = fetch_epss(fake_feeds(), make_settings().epss_url, ["CVE-2021-44228", "CVE-2017-0144"])

    assert scores == {
        "CVE-2021-44228": (0.944, 0.999),
        "CVE-2017-0144": (None, None),  # out-of-range values are dropped, not trusted
    }


def test_fetch_epss_never_puts_malformed_ids_in_the_url():
    requests: list[httpx2.Request] = []

    fetch_epss(
        fake_feeds(requests),
        make_settings().epss_url,
        ["CVE-2021-44228", "CVE-2021-1&scope=all", "../../etc/passwd", "cve-2021-44228"],
    )

    assert [str(r.url) for r in requests] == [
        "https://api.first.org/data/v1/epss?cve=CVE-2021-44228"
    ]


def test_feeds_must_be_https():
    with pytest.raises(IntelError):
        fetch_kev(fake_feeds(), "http://www.cisa.gov/feed.json")


def test_unreachable_feed_is_reported_cleanly():
    def refuse(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("no route", request=request)

    with pytest.raises(IntelError, match="www.cisa.gov"):
        fetch_kev(httpx2.Client(transport=httpx2.MockTransport(refuse)), make_settings().kev_url)


def test_chunking_respects_both_api_limits():
    cves = [f"CVE-2024-{n:05d}" for n in range(250)]
    batches = list(chunk_cves(cves))

    assert [len(b) for b in batches] == [100, 100, 50]
    assert sum(batches, []) == cves

    long_ids = [f"CVE-2024-{n:045d}" for n in range(100)]
    for batch in chunk_cves(long_ids):
        assert len(",".join(batch)) <= 2000


def test_refresh_updates_findings_and_sends_only_cve_ids(loaded, app, db):
    requests: list[httpx2.Request] = []
    app.state.intel_client = fake_feeds(requests)

    response = loaded.post("/api/intel/refresh", headers=WRITE)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["kev_matches"] == 2
    assert body["kev_catalog_version"] == "2026.11.20"

    log4shell = db.scalars(select(Finding).where(Finding.plugin_id == "900001")).one()
    assert log4shell.in_kev is True
    assert str(log4shell.kev_due_date) == "2021-12-24"
    assert log4shell.epss == 0.944
    assert log4shell.risk_score == 98.6  # 10.0 x 6, plus 0.944 x 25, plus 15 for KEV

    eternalblue = db.scalars(select(Finding).where(Finding.plugin_id == "900002")).one()
    assert eternalblue.in_kev is True
    assert eternalblue.epss is None
    assert eternalblue.risk_score == 63.6  # 8.1 x 6, plus 15 for KEV

    epss_request = next(r for r in requests if r.url.host == "api.first.org")
    assert str(epss_request.url).startswith("https://api.first.org/data/v1/epss?cve=CVE-")
    assert "," in str(epss_request.url) and "%2C" not in str(epss_request.url)

    # Privacy check: nothing but CVE IDs may leave the machine.
    for request in requests:
        assert request.method == "GET"
        assert request.content == b""
        query = str(request.url.query, "ascii")
        assert "192.168" not in query and "home.arpa" not in query


def test_refresh_keeps_working_when_one_feed_is_down(loaded, app, db):
    def handler(request: httpx2.Request) -> httpx2.Response:
        if request.url.host == "www.cisa.gov":
            return httpx2.Response(200, json=KEV_FEED)
        return httpx2.Response(503, text="maintenance")

    app.state.intel_client = httpx2.Client(transport=httpx2.MockTransport(handler))

    body = loaded.post("/api/intel/refresh", headers=WRITE).json()

    assert body["kev_matches"] == 2
    assert body["epss_scores"] is None
    assert len(body["warnings"]) == 1 and "EPSS was not updated" in body["warnings"][0]
    log4shell = db.scalars(select(Finding).where(Finding.plugin_id == "900001")).one()
    assert log4shell.in_kev is True and log4shell.risk_score == 75.0


def test_refresh_reports_feed_outage(loaded, app):
    def refuse(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("offline", request=request)

    app.state.intel_client = httpx2.Client(transport=httpx2.MockTransport(refuse))

    response = loaded.post("/api/intel/refresh", headers=WRITE)

    assert response.status_code == 502
    assert "www.cisa.gov" in response.json()["detail"]
