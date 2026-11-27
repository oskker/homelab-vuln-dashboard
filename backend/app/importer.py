"""Turn a parsed scan into database state and history.

Tracking rules, per host in the scan:
- A finding seen for the first time is created as open.
- A finding seen again keeps its first_seen date (that is its age) and updates last_seen.
- An open finding that the new scan no longer reports is marked fixed, unless the scan
  could not have re-checked it: the host was not finished, or that check errored on the
  host. Those stay open and are recorded as carried forward.
- A fixed finding that shows up again is reopened.

History, per import:
- scan_hosts: every host the scan covered, even the ones with nothing to report.
- scan_findings: every finding the scan reported (or carried forward).
- finding_events: each new, fixed and reopened change, with the scan that caused it.
- scan_archives: the original report, compressed.

Known limitation: "not reported" is otherwise treated as "fixed". Scanning the same
hosts with the same scan configuration each time keeps this honest.
"""

import gzip
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from .db import utcnow
from .models import (
    EVENT_FIXED,
    EVENT_NEW,
    EVENT_REOPENED,
    ORIGIN_UPLOAD,
    STATUS_FIXED,
    STATUS_OPEN,
    Finding,
    FindingCve,
    FindingEvent,
    Host,
    Observation,
    Scan,
    ScanArchive,
    ScanHost,
)
from .parsers import ParsedFinding, ParsedHost, ParsedScan
from .risk import recompute_risk


class DuplicateScanError(ValueError):
    """This exact report was imported before."""


@dataclass
class ImportResult:
    scan: Scan
    new: int
    fixed: int
    reopened: int
    carried: int


def _apply_details(finding: Finding, parsed: ParsedFinding) -> None:
    finding.plugin_name = parsed.plugin_name
    finding.plugin_family = parsed.plugin_family
    finding.severity = parsed.severity
    finding.service = parsed.service
    finding.cvss_base = parsed.cvss_base
    finding.cvss_vector = parsed.cvss_vector
    finding.exploit_available = parsed.exploit_available
    finding.qod = parsed.qod
    finding.synopsis = parsed.synopsis
    finding.description = parsed.description
    finding.solution = parsed.solution
    finding.plugin_output = parsed.plugin_output

    wanted = set(parsed.cves)
    have = {c.cve_id for c in finding.cves}
    finding.cves = [c for c in finding.cves if c.cve_id in wanted] + [
        FindingCve(cve_id=cve) for cve in parsed.cves if cve not in have
    ]


def _upsert_host(db: Session, parsed: ParsedHost, seen_at: datetime) -> tuple[Host, bool]:
    """Return the host row and whether this scan is older than data we already hold."""
    host = db.scalar(select(Host).where(Host.ip == parsed.ip).options(selectinload(Host.findings)))
    if host is None:
        host = Host(ip=parsed.ip, first_seen=seen_at, last_seen=seen_at)
        db.add(host)
        stale = False
    else:
        stale = seen_at < host.last_seen
        host.first_seen = min(host.first_seen, seen_at)
        host.last_seen = max(host.last_seen, seen_at)

    if not stale:
        host.hostname = parsed.hostname or host.hostname or ""
        host.fqdn = parsed.fqdn or host.fqdn or ""
        host.os = parsed.os or host.os or ""
        host.mac = parsed.mac or host.mac or ""
    return host, stale


def _known_host(db: Session, ip: str) -> bool:
    return db.scalar(select(Host.id).where(Host.ip == ip)) is not None


def _move_first_sighting(db: Session, finding: Finding, scan: Scan, seen_at: datetime) -> None:
    """An older scan imported late saw this finding earlier than we thought."""
    first = db.scalar(
        select(FindingEvent)
        .where(FindingEvent.finding_id == finding.id, FindingEvent.kind == EVENT_NEW)
        .order_by(FindingEvent.at.asc())
        .limit(1)
    )
    if first is not None and first.at > seen_at:
        first.at = seen_at
        first.scan_id = scan.id


def _scan_time(parsed: ParsedScan, now: datetime) -> datetime:
    host_times = [h.scan_end or h.scan_start for h in parsed.hosts]
    known = [t for t in host_times if t is not None]
    if known:
        return max(known)
    return parsed.scan_end or parsed.scan_start or now


def import_scan(
    db: Session,
    parsed: ParsedScan,
    *,
    filename: str,
    sha256: str,
    raw: bytes | None = None,
    media_type: str = "application/octet-stream",
    origin: str = ORIGIN_UPLOAD,
    now: datetime | None = None,
) -> ImportResult:
    now = now or utcnow()
    if db.scalar(select(Scan.id).where(Scan.sha256 == sha256)) is not None:
        raise DuplicateScanError("This scan file was already imported.")
    if parsed.external_id and db.scalar(
        select(Scan.id).where(Scan.external_id == parsed.external_id)
    ):
        raise DuplicateScanError("This report was already imported.")

    scan_time = _scan_time(parsed, now)
    scan = Scan(
        source=parsed.source,
        filename=filename[:255],
        sha256=sha256,
        report_name=parsed.report_name,
        scan_time=scan_time,
        imported_at=now,
        external_id=parsed.external_id,
        origin=origin,
        task_name=parsed.task_name,
        has_history=True,
        host_count=0,
        item_count=sum(len(h.findings) for h in parsed.hosts),
    )
    db.add(scan)
    db.flush()

    new = fixed = reopened = carried = 0
    touched: list[Finding] = []
    observed: list[tuple[Finding, bool]] = []

    def observe(finding: Finding, was_carried: bool = False) -> None:
        observed.append((finding, was_carried))

    def event(finding: Finding, kind: str, at: datetime, scan_id: int | None) -> None:
        db.add(FindingEvent(finding=finding, kind=kind, at=at, scan_id=scan_id))

    for parsed_host in parsed.hosts:
        if not parsed_host.findings and not _known_host(db, parsed_host.ip):
            # A network sweep lists every address it tried. An address with nothing to
            # report and no history is not worth a row.
            continue
        seen_at = parsed_host.scan_end or parsed_host.scan_start or scan_time
        host, stale = _upsert_host(db, parsed_host, seen_at)
        newer_seen = host.last_seen  # only meaningful when stale
        db.flush()
        db.add(ScanHost(scan_id=scan.id, host_id=host.id, complete=parsed_host.complete))
        scan.host_count += 1

        existing = {
            (f.plugin_id, f.port, f.protocol): f for f in host.findings if f.source == parsed.source
        }
        reported: set[tuple[str, int, str]] = set()

        for item in parsed_host.findings:
            key = (item.plugin_id, item.port, item.protocol)
            if key in reported:
                continue
            reported.add(key)

            finding = existing.get(key)
            if finding is None:
                finding = Finding(
                    host=host,
                    source=parsed.source,
                    plugin_id=item.plugin_id,
                    port=item.port,
                    protocol=item.protocol,
                    first_seen=seen_at,
                    last_seen=seen_at,
                    last_scan_id=scan.id,
                    status=STATUS_OPEN,
                )
                _apply_details(finding, item)
                db.add(finding)
                event(finding, EVENT_NEW, seen_at, scan.id)
                if stale:
                    # An older scan reported it and the newer scan we already hold did not.
                    finding.status = STATUS_FIXED
                    finding.fixed_at = newer_seen
                    event(finding, EVENT_FIXED, newer_seen, None)
                else:
                    new += 1
            elif stale:
                if seen_at < finding.first_seen:
                    finding.first_seen = seen_at
                    _move_first_sighting(db, finding, scan, seen_at)
            else:
                if finding.status == STATUS_FIXED:
                    finding.status = STATUS_OPEN
                    finding.fixed_at = None
                    reopened += 1
                    event(finding, EVENT_REOPENED, seen_at, scan.id)
                finding.last_seen = seen_at
                finding.last_scan_id = scan.id
                _apply_details(finding, item)
            observe(finding)
            touched.append(finding)

        if stale:
            # The older scan does not change current state, but its own record should
            # still show findings it could not re-check that were open at the time.
            for key, finding in existing.items():
                if key in reported or finding.first_seen > seen_at:
                    continue
                was_open = finding.fixed_at is None or finding.fixed_at > seen_at
                skipped = not parsed_host.complete or finding.plugin_id in parsed_host.unchecked
                if was_open and skipped:
                    observe(finding, was_carried=True)
            continue
        for key, finding in existing.items():
            if key in reported or finding.status != STATUS_OPEN:
                continue
            if not parsed_host.complete or finding.plugin_id in parsed_host.unchecked:
                # The scan could not have re-checked it: keep it open, note that it was
                # carried forward rather than seen.
                observe(finding, was_carried=True)
                carried += 1
                continue
            finding.status = STATUS_FIXED
            finding.fixed_at = seen_at
            event(finding, EVENT_FIXED, seen_at, scan.id)
            fixed += 1

    db.flush()
    recompute_risk(db, touched)
    for finding, was_carried in observed:
        db.add(
            Observation(
                scan_id=scan.id,
                finding_id=finding.id,
                severity=finding.severity,
                carried=was_carried,
            )
        )

    if raw is not None:
        db.add(
            ScanArchive(
                scan_id=scan.id,
                media_type=media_type[:64],
                size_bytes=len(raw),
                gzip_data=gzip.compress(raw, compresslevel=6, mtime=0),
            )
        )

    scan.new_count, scan.fixed_count, scan.reopened_count = new, fixed, reopened
    db.flush()
    counts = dict(
        db.execute(
            select(Finding.severity, func.count())
            .where(Finding.status == STATUS_OPEN)
            .group_by(Finding.severity)
        ).all()
    )
    scan.open_critical = counts.get(4, 0)
    scan.open_high = counts.get(3, 0)
    scan.open_medium = counts.get(2, 0)
    scan.open_low = counts.get(1, 0)

    db.commit()
    return ImportResult(scan=scan, new=new, fixed=fixed, reopened=reopened, carried=carried)
