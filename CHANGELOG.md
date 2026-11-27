# Changelog

## 0.2.0 (2026-11-27)

OpenVAS replaces Nessus as the main scanner, and the dashboard now keeps the full history
of every scan.

### Added

- OpenVAS (Greenbone Community Edition) runs next to the dashboard: `start.bat` starts
  Greenbone's official containers alongside it.
- Create OpenVAS scans from the dashboard, run them now or every day or week, start
  existing tasks and follow their progress.
- Finished OpenVAS reports are imported automatically, oldest first and once each.
- Import of OpenVAS XML reports by hand, and of several reports at once.
- Scan history: the hosts each scan covered, every finding it reported, every status
  change, and a compressed copy of the original report, which can be downloaded.
- Trends view: open findings, found and fixed per scan, total risk, days to fix, age of
  open findings and per-host change, over 30 days, 90 days, a year or all time.
- Scans view with the OpenVAS status, tasks and the scan history, and a detail view of
  what each scan changed.
- A history timeline on every finding.
- `backup.bat` and `restore.bat`.
- Database migrations with Alembic. Version 0.1 databases are upgraded in place.
- CI runs the tests on PostgreSQL as well as SQLite.

### Changed

- Findings that a scan could not re-check (host not finished, check errored) stay open
  instead of being marked fixed.
- Times are stored in UTC and shown in the browser's time zone.
- The Nessus demo files moved to `backend/tests/fixtures/nessus/`. `sample-data/` now
  holds eight synthetic OpenVAS reports.

## 0.1.0 (2026-11-26)

First release: Nessus import, finding tracking, CISA KEV and EPSS enrichment, risk
ranking and local AI triage.
