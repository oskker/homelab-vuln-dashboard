"""Trends computed from scan history.

"Open after a scan" is rebuilt from what each scan saw rather than read from a stored
total. For every host, the latest scan that covered it (at or before a given scan)
decides which of its findings were open at that moment. That keeps the chart right
when scans cover different hosts, and when an older report is imported after a newer
one. Scans from version 0.1 have no history, so their stored totals are used as they are.

Risk totals use each finding's current risk score, so a threat-intel update re-scores
the past as well as the present.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from statistics import median

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
    EVENT_FIXED,
    EVENT_NEW,
    EVENT_REOPENED,
    STATUS_OPEN,
    Finding,
    FindingEvent,
    Host,
    Observation,
    Scan,
    ScanHost,
)

SEVERITY_KEYS = {4: "critical", 3: "high", 2: "medium", 1: "low"}
AGE_BUCKETS = ((30, "0-30 days"), (90, "31-90 days"), (None, "Over 90 days"))


@dataclass
class Tally:
    """Open findings for one host as one scan saw them."""

    counts: dict[int, int] = field(default_factory=lambda: dict.fromkeys(SEVERITY_KEYS, 0))
    risk: float = 0.0
    kev: int = 0

    def add(self, severity: int, risk: float, in_kev: bool) -> None:
        if severity not in SEVERITY_KEYS:
            return  # informational items are not counted as open findings
        self.counts[severity] += 1
        self.risk += risk
        self.kev += int(in_kev)

    def merge(self, other: "Tally", sign: int = 1) -> None:
        for level in SEVERITY_KEYS:
            self.counts[level] += sign * other.counts[level]
        self.risk += sign * other.risk
        self.kev += sign * other.kev

    def as_dict(self) -> dict:
        return {SEVERITY_KEYS[level]: self.counts[level] for level in SEVERITY_KEYS}


def _scan_row(scan: Scan) -> dict:
    return {
        "id": scan.id,
        "scan_time": scan.scan_time,
        "source": scan.source,
        "task_name": scan.task_name,
        "new": scan.new_count,
        "fixed": scan.fixed_count,
        "reopened": scan.reopened_count,
    }


def _load(db: Session):
    scans = db.scalars(select(Scan).order_by(Scan.scan_time.asc(), Scan.id.asc())).all()
    covered: dict[int, list[int]] = defaultdict(list)
    for scan_id, host_id in db.execute(select(ScanHost.scan_id, ScanHost.host_id)).all():
        covered[scan_id].append(host_id)
    tallies: dict[tuple[int, int], Tally] = defaultdict(Tally)
    rows = db.execute(
        select(
            Observation.scan_id,
            Finding.host_id,
            Observation.severity,
            Finding.risk_score,
            Finding.in_kev,
        ).join(Finding, Finding.id == Observation.finding_id)
    ).all()
    for scan_id, host_id, severity, risk, in_kev in rows:
        tallies[(scan_id, host_id)].add(severity, risk or 0.0, bool(in_kev))
    return scans, covered, tallies


def open_series(db: Session) -> tuple[list[dict], dict[int, list[dict]]]:
    """Open findings after every scan, overall and per host.

    Each scanner keeps its own findings (an OpenVAS scan does not close a Nessus finding),
    so "the latest scan of a host" is tracked per scanner.
    """
    scans, covered, tallies = _load(db)
    latest: dict[tuple[int, str], int] = {}  # (host, scanner) -> scan that last covered it
    by_host: dict[int, Tally] = defaultdict(Tally)  # open now per host, all scanners
    total = Tally()
    points: list[dict] = []
    per_host: dict[int, list[dict]] = defaultdict(list)

    for scan in scans:
        for host_id in covered.get(scan.id, []):
            key = (host_id, scan.source)
            previous = latest.get(key)
            if previous is not None:
                old = tallies.get((previous, host_id), Tally())
                total.merge(old, sign=-1)
                by_host[host_id].merge(old, sign=-1)
            latest[key] = scan.id
            new = tallies.get((scan.id, host_id), Tally())
            total.merge(new)
            by_host[host_id].merge(new)
            per_host[host_id].append(
                {
                    "scan_id": scan.id,
                    "scan_time": scan.scan_time,
                    "open": by_host[host_id].as_dict(),
                    "risk": round(by_host[host_id].risk, 1),
                }
            )

        point = _scan_row(scan)
        if scan.has_history:
            point["open"] = total.as_dict()
            point["risk_total"] = round(total.risk, 1)
            point["kev_open"] = total.kev
        else:
            point["open"] = {
                "critical": scan.open_critical,
                "high": scan.open_high,
                "medium": scan.open_medium,
                "low": scan.open_low,
            }
            point["risk_total"] = None
            point["kev_open"] = None
        points.append(point)
    return points, per_host


def fix_times(db: Session, since: datetime | None = None) -> dict:
    """How long findings stayed open before they were fixed, by severity.

    A finding that was fixed, reopened and fixed again counts twice, each time from the
    moment it was (re)opened.
    """
    rows = db.execute(
        select(FindingEvent.finding_id, FindingEvent.kind, FindingEvent.at, Finding.severity)
        .join(Finding, Finding.id == FindingEvent.finding_id)
        .order_by(FindingEvent.finding_id, FindingEvent.at, FindingEvent.id)
    ).all()
    durations: dict[int, list[float]] = defaultdict(list)
    opened: dict[int, datetime] = {}
    for finding_id, kind, at, severity in rows:
        if kind == EVENT_NEW:
            opened.setdefault(finding_id, at)
        elif kind == EVENT_REOPENED:
            opened[finding_id] = at
        elif kind == EVENT_FIXED and finding_id in opened:
            start = opened.pop(finding_id)
            if since is None or at >= since:
                durations[severity].append(max(0.0, (at - start).total_seconds() / 86400))

    def stats(values: list[float]) -> dict:
        return {
            "fixed": len(values),
            "median_days": round(median(values), 1) if values else None,
            "mean_days": round(sum(values) / len(values), 1) if values else None,
        }

    result = {key: stats(durations.get(level, [])) for level, key in SEVERITY_KEYS.items()}
    result["critical_and_high"] = stats(durations.get(4, []) + durations.get(3, []))
    return result


def open_by_age(db: Session, now: datetime) -> list[dict]:
    """Open findings grouped by how long they have been open."""
    buckets = [
        {"label": label, "max_days": limit, "open": dict.fromkeys(SEVERITY_KEYS.values(), 0)}
        for limit, label in AGE_BUCKETS
    ]
    rows = db.execute(
        select(Finding.severity, Finding.first_seen).where(
            Finding.status == STATUS_OPEN, Finding.severity > 0
        )
    ).all()
    for severity, first_seen in rows:
        age = (now - first_seen).days
        for bucket in buckets:
            if bucket["max_days"] is None or age <= bucket["max_days"]:
                bucket["open"][SEVERITY_KEYS[min(severity, 4)]] += 1
                break
    return buckets


def trends(db: Session, now: datetime, days: int | None) -> dict:
    points, per_host = open_series(db)
    start = now - timedelta(days=days) if days else None
    shown = [p for p in points if start is None or p["scan_time"] >= start]
    before = [p for p in points if start is not None and p["scan_time"] < start]
    baseline = before[-1] if before else (shown[0] if shown else None)

    hosts = {h.id: h for h in db.scalars(select(Host)).all()}
    host_rows = []
    for host_id, series in per_host.items():
        host = hosts.get(host_id)
        if host is None:
            continue
        in_range = [p for p in series if start is None or p["scan_time"] >= start]
        earlier = [p for p in series if start is not None and p["scan_time"] < start]
        reference = earlier[-1] if earlier else (in_range[0] if in_range else None)
        if not in_range and not earlier:
            continue
        current = (in_range or earlier)[-1]
        host_rows.append(
            {
                "id": host.id,
                "ip": host.ip,
                "hostname": host.hostname,
                "points": in_range,
                "open_now": current["open"],
                "open_then": reference["open"] if reference else None,
            }
        )
    host_rows.sort(key=lambda r: (-sum(r["open_now"].values()), r["ip"]))

    def total(point: dict | None) -> int | None:
        return sum(point["open"].values()) if point else None

    # Everything the very first scan reports is "new", which says nothing about change.
    # It is marked so charts and totals of found findings can leave it out.
    for point in points:
        point["first_scan"] = point is points[0]
    found_in = [p for p in shown if not p["first_scan"]]

    return {
        "range_days": days,
        "points": shown,
        "summary": {
            "scans": len(shown),
            "open_now": total(points[-1] if points else None),
            "open_at_start": total(baseline),
            "new": sum(p["new"] for p in found_in),
            "fixed": sum(p["fixed"] for p in shown),
            "reopened": sum(p["reopened"] for p in shown),
            "includes_first_scan": len(found_in) < len(shown),
        },
        "fix_times": fix_times(db, since=start),
        "open_by_age": open_by_age(db, now),
        "hosts": host_rows,
    }


def scan_changes(db: Session, scan_id: int) -> dict:
    """What one scan changed: findings it found, fixed, reopened or could not re-check."""
    events = db.execute(
        select(FindingEvent.kind, Finding)
        .join(Finding, Finding.id == FindingEvent.finding_id)
        .where(FindingEvent.scan_id == scan_id)
    ).all()
    carried = db.scalars(
        select(Finding)
        .join(Observation, Observation.finding_id == Finding.id)
        .where(Observation.scan_id == scan_id, Observation.carried)
    ).all()
    seen = db.scalar(
        select(Observation.scan_id).where(Observation.scan_id == scan_id).limit(1)
    )
    grouped: dict[str, list[Finding]] = {EVENT_NEW: [], EVENT_FIXED: [], EVENT_REOPENED: []}
    for kind, finding in events:
        grouped.setdefault(kind, []).append(finding)
    hosts = db.execute(
        select(Host, ScanHost.complete)
        .join(ScanHost, ScanHost.host_id == Host.id)
        .where(ScanHost.scan_id == scan_id)
    ).all()
    return {
        "groups": grouped,
        "carried": list(carried),
        "has_observations": seen is not None,
        "hosts": hosts,
    }


def finding_timeline(db: Session, finding_id: int) -> dict:
    events = db.execute(
        select(FindingEvent.kind, FindingEvent.at, FindingEvent.scan_id)
        .where(FindingEvent.finding_id == finding_id)
        .order_by(FindingEvent.at, FindingEvent.id)
    ).all()
    sightings = db.execute(
        select(Scan.id, Scan.scan_time, Observation.severity, Observation.carried)
        .join(Observation, Observation.scan_id == Scan.id)
        .where(Observation.finding_id == finding_id)
        .order_by(Scan.scan_time)
    ).all()
    return {
        "events": [{"kind": k, "at": at, "scan_id": s} for k, at, s in events],
        "sightings": [
            {"scan_id": sid, "scan_time": when, "severity": sev, "carried": bool(carried)}
            for sid, when, sev, carried in sightings
        ],
    }
