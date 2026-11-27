from datetime import datetime

import pytest
from sqlalchemy import select

from app.importer import DuplicateScanError, import_scan
from app.models import Finding, Host

from .conftest import DEMO_SCANS, one_host_scan, upload

T1 = datetime(2026, 11, 1, 9, 0)
T2 = datetime(2026, 11, 8, 9, 0)
T3 = datetime(2026, 11, 15, 9, 0)


def finding(db, plugin_id: str) -> Finding:
    return db.scalars(select(Finding).where(Finding.plugin_id == plugin_id)).one()


def test_first_import_creates_open_findings(db):
    result = import_scan(db, one_host_scan(T1, "100", "200"), filename="a", sha256="a" * 64)

    assert (result.new, result.fixed, result.reopened) == (2, 0, 0)
    assert finding(db, "100").status == "open"
    assert finding(db, "100").first_seen == T1
    assert result.scan.open_high == 2


def test_missing_finding_is_marked_fixed_and_keeps_its_history(db):
    import_scan(db, one_host_scan(T1, "100", "200"), filename="a", sha256="a" * 64)
    result = import_scan(db, one_host_scan(T2, "100"), filename="b", sha256="b" * 64)

    assert (result.new, result.fixed, result.reopened) == (0, 1, 0)
    gone = finding(db, "200")
    assert gone.status == "fixed"
    assert gone.fixed_at == T2
    assert gone.first_seen == T1
    still = finding(db, "100")
    assert still.status == "open"
    assert still.first_seen == T1  # age is measured from the first sighting
    assert still.last_seen == T2
    assert result.scan.open_high == 1


def test_fixed_finding_that_returns_is_reopened(db):
    import_scan(db, one_host_scan(T1, "100"), filename="a", sha256="a" * 64)
    import_scan(db, one_host_scan(T2), filename="b", sha256="b" * 64)
    result = import_scan(db, one_host_scan(T3, "100"), filename="c", sha256="c" * 64)

    assert (result.new, result.fixed, result.reopened) == (0, 0, 1)
    back = finding(db, "100")
    assert back.status == "open"
    assert back.fixed_at is None
    assert back.first_seen == T1


def test_hosts_outside_the_scan_are_left_alone(db):
    import_scan(db, one_host_scan(T1, "100", ip="10.0.0.5"), filename="a", sha256="a" * 64)
    result = import_scan(db, one_host_scan(T2, "300", ip="10.0.0.9"), filename="b", sha256="b" * 64)

    assert result.fixed == 0
    assert finding(db, "100").status == "open"
    assert db.scalar(select(Host).where(Host.ip == "10.0.0.9")) is not None


def test_older_scan_imported_late_does_not_rewrite_newer_state(db):
    import_scan(db, one_host_scan(T2, "100"), filename="new", sha256="b" * 64)
    result = import_scan(db, one_host_scan(T1, "100", "200"), filename="old", sha256="a" * 64)

    assert (result.new, result.fixed, result.reopened) == (0, 0, 0)
    assert finding(db, "100").status == "open"
    assert finding(db, "100").first_seen == T1  # the older sighting extends its age
    assert finding(db, "100").last_seen == T2
    historic = finding(db, "200")  # seen in the old scan, absent from the newer one
    assert historic.status == "fixed"
    assert historic.fixed_at == T2


def test_same_file_cannot_be_imported_twice(db):
    import_scan(db, one_host_scan(T1, "100"), filename="a", sha256="a" * 64)
    with pytest.raises(DuplicateScanError):
        import_scan(db, one_host_scan(T1, "100"), filename="a", sha256="a" * 64)


def test_demo_scans_tell_the_expected_story(client):
    results = [upload(client, path).json() for path in DEMO_SCANS]

    assert [(r["new"], r["fixed"], r["reopened"]) for r in results] == [
        (26, 0, 0),  # 20 findings plus one informational item on each of 6 hosts
        (0, 1, 0),  # Log4Shell patched
        (1, 2, 0),  # default credentials found; RDP and router TLS fixed
    ]
    assert [r["open"]["critical"] for r in results] == [2, 1, 2]
    assert [r["open"]["high"] for r in results] == [4, 4, 4]
    assert [r["open"]["medium"] for r in results] == [10, 10, 8]
    assert [r["open"]["low"] for r in results] == [4, 4, 4]
    assert upload(client, DEMO_SCANS[0]).status_code == 409
