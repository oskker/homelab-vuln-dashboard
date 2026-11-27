"""Turn a parsed scan into database state.

Tracking rules, per host in the scan:
- A finding seen for the first time is created as open.
- A finding seen again keeps its first_seen date (that is its age) and updates last_seen.
- An open finding that the new scan no longer reports is marked fixed.
- A fixed finding that shows up again is reopened.

Known limitation: "not reported" is treated as "fixed". Tenable Security Center is
stricter and also checks that the plugin actually ran against that port. Scanning the
same hosts with the same policy each time keeps this honest.
"""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from .models import STATUS_FIXED, STATUS_OPEN, Finding, FindingCve, Host, Scan
from .parsers import ParsedFinding, ParsedHost, ParsedScan
from .risk import recompute_risk


class DuplicateScanError(ValueError):
    """This exact file was imported before."""


@dataclass
class ImportResult:
    scan: Scan
    new: int
    fixed: int
    reopened: int


def _apply_details(finding: Finding, parsed: ParsedFinding) -> None:
    finding.plugin_name = parsed.plugin_name
    finding.plugin_family = parsed.plugin_family
    finding.severity = parsed.severity
    finding.service = parsed.service
    finding.cvss_base = parsed.cvss_base
    finding.cvss_vector = parsed.cvss_vector
    finding.exploit_available = parsed.exploit_available
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


def import_scan(
    db: Session,
    parsed: ParsedScan,
    *,
    filename: str,
    sha256: str,
    now: datetime | None = None,
) -> ImportResult:
    now = now or datetime.now()  # noqa: DTZ005 - scan times are scanner-local and naive
    if db.scalar(select(Scan.id).where(Scan.sha256 == sha256)) is not None:
        raise DuplicateScanError("This scan file was already imported.")

    host_times = [h.scan_end or h.scan_start for h in parsed.hosts]
    known_times = [t for t in host_times if t is not None]
    scan_time = max(known_times) if known_times else now

    scan = Scan(
        source=parsed.source,
        filename=filename[:255],
        sha256=sha256,
        report_name=parsed.report_name,
        scan_time=scan_time,
        imported_at=now,
        host_count=len(parsed.hosts),
        item_count=sum(len(h.findings) for h in parsed.hosts),
    )
    db.add(scan)
    db.flush()

    new = fixed = reopened = 0
    touched: list[Finding] = []

    for parsed_host in parsed.hosts:
        seen_at = parsed_host.scan_end or parsed_host.scan_start or scan_time
        host, stale = _upsert_host(db, parsed_host, seen_at)
        newer_seen = host.last_seen  # only meaningful when stale

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
                if stale:
                    # An older scan reported it and the newer scan we already hold did not.
                    finding.status = STATUS_FIXED
                    finding.fixed_at = newer_seen
                else:
                    new += 1
                db.add(finding)
            elif stale:
                finding.first_seen = min(finding.first_seen, seen_at)
            else:
                if finding.status == STATUS_FIXED:
                    finding.status = STATUS_OPEN
                    finding.fixed_at = None
                    reopened += 1
                finding.last_seen = seen_at
                finding.last_scan_id = scan.id
                _apply_details(finding, item)
            touched.append(finding)

        if not stale:
            for key, finding in existing.items():
                if key not in reported and finding.status == STATUS_OPEN:
                    finding.status = STATUS_FIXED
                    finding.fixed_at = seen_at
                    fixed += 1

    db.flush()
    recompute_risk(db, touched)

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
    return ImportResult(scan=scan, new=new, fixed=fixed, reopened=reopened)
