"""Risk scoring.

The score is deterministic and explainable on purpose. The language model is never
allowed to set or change it; it only explains the breakdown produced here.

    score = (CVSS x 6) + (EPSS x 25) + (15 if on the CISA KEV list)
    then scaled by host criticality and capped at 100

- CVSS (0-10) says how bad exploitation would be.            up to 60 points
- EPSS (0-1) is the modelled chance of exploitation soon.    up to 25 points
- KEV means exploitation has already been seen in the wild.  15 points
"""

from collections.abc import Iterable
from dataclasses import asdict, dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from .models import CveIntel, Finding

SEVERITY_LABELS = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

# Used when a finding has no CVSS score of its own.
SEVERITY_FALLBACK_CVSS = {0: 0.0, 1: 2.0, 2: 5.0, 3: 7.5, 4: 9.5}

CRITICALITY_MULTIPLIER = {1: 0.8, 2: 0.9, 3: 1.0, 4: 1.1, 5: 1.2}

CVSS_WEIGHT = 6.0
EPSS_WEIGHT = 25.0
KEV_POINTS = 15.0


@dataclass(frozen=True)
class RiskBreakdown:
    cvss_used: float
    cvss_points: float
    epss_points: float
    kev_points: float
    criticality_multiplier: float
    score: float

    def as_dict(self) -> dict:
        return asdict(self)


def score_finding(
    severity: int,
    cvss: float | None,
    epss: float | None,
    in_kev: bool,
    criticality: int = 3,
) -> RiskBreakdown:
    if severity <= 0:
        return RiskBreakdown(0.0, 0.0, 0.0, 0.0, 1.0, 0.0)

    cvss_used = cvss if cvss is not None else SEVERITY_FALLBACK_CVSS.get(severity, 0.0)
    cvss_points = cvss_used * CVSS_WEIGHT
    epss_points = (epss or 0.0) * EPSS_WEIGHT
    kev_points = KEV_POINTS if in_kev else 0.0
    multiplier = CRITICALITY_MULTIPLIER.get(criticality, 1.0)
    score = min(100.0, (cvss_points + epss_points + kev_points) * multiplier)
    return RiskBreakdown(
        cvss_used=round(cvss_used, 1),
        cvss_points=round(cvss_points, 1),
        epss_points=round(epss_points, 1),
        kev_points=kev_points,
        criticality_multiplier=multiplier,
        score=round(score, 1),
    )


def recompute_risk(db: Session, findings: Iterable[Finding] | None = None) -> int:
    """Refresh risk_score, epss, in_kev and kev_due_date on findings from the intel table."""
    if findings is None:
        findings = db.scalars(
            select(Finding).options(selectinload(Finding.cves), selectinload(Finding.host))
        ).all()
    intel = {row.cve_id: row for row in db.scalars(select(CveIntel)).all()}

    count = 0
    for finding in findings:
        rows = [intel[c.cve_id] for c in finding.cves if c.cve_id in intel]
        epss_values = [r.epss for r in rows if r.epss is not None]
        kev_rows = [r for r in rows if r.in_kev]
        due_dates = [r.kev_due_date for r in kev_rows if r.kev_due_date is not None]

        finding.epss = max(epss_values) if epss_values else None
        finding.in_kev = bool(kev_rows)
        finding.kev_due_date = min(due_dates) if due_dates else None
        finding.risk_score = score_finding(
            finding.severity,
            finding.cvss_base,
            finding.epss,
            finding.in_kev,
            finding.host.criticality,
        ).score
        count += 1
    return count
