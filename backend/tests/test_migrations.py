from datetime import datetime

from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.db import Base, make_engine, migration_config, upgrade_database
from app.main import create_app

from .conftest import OPENVAS_DEMOS, TEST_DATABASE_URL, make_settings, upload


def test_schema_matches_the_models():
    engine = make_engine(TEST_DATABASE_URL)
    upgrade_database(engine)
    upgrade_database(engine)  # running it again changes nothing
    with engine.connect() as connection:
        assert compare_metadata(MigrationContext.configure(connection), Base.metadata) == []
    engine.dispose()


def make_v01_database(url: str) -> None:
    """A database exactly as version 0.1 left it: tables, data, no migration record."""
    engine = make_engine(url)
    config = migration_config()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "0001")
        connection.execute(text("DROP TABLE alembic_version"))
        # Passed as text: the sqlite3 driver's own datetime conversion is deprecated.
        t1, t2 = str(datetime(2026, 9, 6, 9, 30)), str(datetime(2026, 9, 13, 9, 30))
        for scan_id, when, opened in ((1, t1, 2), (2, t2, 1)):
            connection.execute(
                text(
                    "INSERT INTO scans (id, source, filename, sha256, report_name, scan_time,"
                    " imported_at, host_count, item_count, new_count, fixed_count, reopened_count,"
                    " open_critical, open_high, open_medium, open_low) VALUES (:id, 'nessus',"
                    " :name, :sha, '', :when, :when, 1, 2, 0, 0, 0, :open, 0, 0, 0)"
                ),
                {"id": scan_id, "name": f"old-{scan_id}.html", "sha": str(scan_id) * 64,
                 "when": when, "open": opened},
            )
        connection.execute(
            text(
                "INSERT INTO hosts (id, ip, hostname, fqdn, os, mac, criticality, first_seen,"
                " last_seen) VALUES (1, '192.168.1.5', 'OLDBOX', '', 'Windows 11', '', 3, :t1, :t2)"
            ),
            {"t1": t1, "t2": t2},
        )
        for fid, status, last_scan, fixed_at in ((1, "open", 2, None), (2, "fixed", 1, t2)):
            connection.execute(
                text(
                    "INSERT INTO findings (id, host_id, last_scan_id, source, plugin_id,"
                    " plugin_name, plugin_family, severity, port, protocol, service, cvss_base,"
                    " cvss_vector, exploit_available, synopsis, description, solution,"
                    " plugin_output, status, first_seen, last_seen, fixed_at, risk_score, epss,"
                    " in_kev) VALUES (:id, 1, :scan, 'nessus', :pid, :name, '', 3, 445, 'tcp', '',"
                    " 8.1, '', false, '', '', '', '', :status, :t1, :t2, :fixed, 48.6, NULL, false)"
                ),
                {"id": fid, "scan": last_scan, "pid": str(1000 + fid), "name": f"Old issue {fid}",
                 "status": status, "t1": t1, "t2": t2, "fixed": fixed_at},
            )
    engine.dispose()


def test_version_01_database_is_upgraded_in_place(tmp_path):
    url = f"sqlite:///{tmp_path / 'v01.db'}"
    make_v01_database(url)

    with TestClient(create_app(make_settings(database_url=url))) as client:
        scans = client.get("/api/scans").json()
        assert [(s["has_history"], s["open"]["critical"]) for s in scans] == [(False, 2), (False, 1)]
        old_open = client.get("/api/findings", params={"q": "Old issue 1"}).json()["items"][0]
        detail = client.get(f"/api/findings/{old_open['id']}").json()
        assert [e["kind"] for e in detail["timeline"]["events"]] == ["new"]
        old_fixed = client.get("/api/findings", params={"q": "Old issue 2", "status": "fixed"}).json()
        fixed_detail = client.get(f"/api/findings/{old_fixed['items'][0]['id']}").json()
        assert [e["kind"] for e in fixed_detail["timeline"]["events"]] == ["new", "fixed"]

        # New scans of other hosts carry the old host's open finding forward.
        assert upload(client, OPENVAS_DEMOS[0]).status_code == 201
        latest = client.get("/api/scans").json()[-1]
        assert latest["open"]["high"] == 4 + 1 and latest["has_history"] is True
