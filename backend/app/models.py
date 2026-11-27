"""Database schema.

Two kinds of data live here:

- Current state. The findings table is cumulative: one row per (host, scanner, check,
  port, protocol). Each import updates that row instead of adding a copy, which is what
  makes aging, "fixed" and "reopened" tracking possible.
- History. Every import also records what that scan saw (scan_hosts, scan_findings),
  every status change (finding_events) and a compressed copy of the original report
  (scan_archives). Trends are computed from this history, so a scan imported late still
  lands in the right place on every chart.

Times are stored as naive UTC.
"""

from datetime import date, datetime

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base

STATUS_OPEN = "open"
STATUS_FIXED = "fixed"

EVENT_NEW = "new"
EVENT_FIXED = "fixed"
EVENT_REOPENED = "reopened"

ORIGIN_UPLOAD = "upload"
ORIGIN_SYNC = "openvas-sync"


class Scan(Base):
    """One imported scan report."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(32))
    filename: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64), unique=True)
    report_name: Mapped[str] = mapped_column(String(255), default="")
    scan_time: Mapped[datetime] = mapped_column(DateTime, index=True)
    imported_at: Mapped[datetime] = mapped_column(DateTime)

    # The scanner's own ID for the report (the OpenVAS report UUID). Stops the automatic
    # sync from importing the same report twice.
    external_id: Mapped[str | None] = mapped_column(String(64))
    origin: Mapped[str] = mapped_column(String(16), default=ORIGIN_UPLOAD)
    task_name: Mapped[str] = mapped_column(String(255), default="")
    # False only for scans imported before history was recorded (version 0.1).
    has_history: Mapped[bool] = mapped_column(Boolean, default=True)

    host_count: Mapped[int] = mapped_column(Integer, default=0)
    item_count: Mapped[int] = mapped_column(Integer, default=0)
    new_count: Mapped[int] = mapped_column(Integer, default=0)
    fixed_count: Mapped[int] = mapped_column(Integer, default=0)
    reopened_count: Mapped[int] = mapped_column(Integer, default=0)

    # Open findings across all hosts right after the import. Kept for scans from
    # version 0.1, which have no per-scan history to compute trends from.
    open_critical: Mapped[int] = mapped_column(Integer, default=0)
    open_high: Mapped[int] = mapped_column(Integer, default=0)
    open_medium: Mapped[int] = mapped_column(Integer, default=0)
    open_low: Mapped[int] = mapped_column(Integer, default=0)

    __table_args__ = (Index("ix_scans_external_id", "external_id", unique=True),)


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    ip: Mapped[str] = mapped_column(String(64), unique=True)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    fqdn: Mapped[str] = mapped_column(String(255), default="")
    os: Mapped[str] = mapped_column(String(255), default="")
    mac: Mapped[str] = mapped_column(String(64), default="")
    # 1 (lab toy) to 5 (holds data you cannot lose). Feeds the risk score.
    criticality: Mapped[int] = mapped_column(Integer, default=3)
    first_seen: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime)

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="host", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("host_id", "source", "plugin_id", "port", "protocol"),
        Index("ix_findings_status_risk", "status", "risk_score"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    last_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    source: Mapped[str] = mapped_column(String(32))

    # The scanner's check ID: a Nessus plugin ID or an OpenVAS NVT OID.
    plugin_id: Mapped[str] = mapped_column(String(64))
    plugin_name: Mapped[str] = mapped_column(String(512))
    plugin_family: Mapped[str] = mapped_column(String(255), default="")
    severity: Mapped[int] = mapped_column(Integer)  # 0 info, 1 low, 2 medium, 3 high, 4 critical
    port: Mapped[int] = mapped_column(Integer, default=0)
    protocol: Mapped[str] = mapped_column(String(16), default="")
    service: Mapped[str] = mapped_column(String(64), default="")

    cvss_base: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str] = mapped_column(String(128), default="")
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False)
    # OpenVAS quality of detection, 0 to 100. Empty for Nessus.
    qod: Mapped[int | None] = mapped_column(Integer)
    synopsis: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    solution: Mapped[str] = mapped_column(Text, default="")
    plugin_output: Mapped[str] = mapped_column(Text, default="")

    status: Mapped[str] = mapped_column(String(16), default=STATUS_OPEN)
    first_seen: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime)
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime)

    # Filled in by risk.recompute_risk() from the CVE intel table.
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    epss: Mapped[float | None] = mapped_column(Float)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_due_date: Mapped[date | None] = mapped_column(Date)

    host: Mapped[Host] = relationship(back_populates="findings")
    cves: Mapped[list["FindingCve"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    triages: Mapped[list["AiTriage"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )
    events: Mapped[list["FindingEvent"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="FindingEvent.at"
    )


class FindingCve(Base):
    __tablename__ = "finding_cves"

    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True
    )
    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True, index=True)

    finding: Mapped[Finding] = relationship(back_populates="cves")


class ScanHost(Base):
    """A host that a scan covered, even if the scan found nothing on it."""

    __tablename__ = "scan_hosts"

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    host_id: Mapped[int] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    # False when the scanner did not finish this host. Nothing is marked fixed for it.
    complete: Mapped[bool] = mapped_column(Boolean, default=True)


class Observation(Base):
    """One finding as one scan saw it."""

    __tablename__ = "scan_findings"

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    severity: Mapped[int] = mapped_column(Integer)
    # True when the scan could not re-check this finding (the check errored or the host
    # did not finish), so it stays open on the strength of the previous scan.
    carried: Mapped[bool] = mapped_column(Boolean, default=False)


class FindingEvent(Base):
    """A status change: first seen, fixed or reopened."""

    __tablename__ = "finding_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), index=True
    )
    kind: Mapped[str] = mapped_column(String(16))
    at: Mapped[datetime] = mapped_column(DateTime, index=True)

    finding: Mapped[Finding] = relationship(back_populates="events")


class ScanArchive(Base):
    """The original report file, gzip-compressed, kept as evidence."""

    __tablename__ = "scan_archives"

    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    media_type: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    gzip_data: Mapped[bytes] = mapped_column(LargeBinary)


class CveIntel(Base):
    """Threat intel per CVE: CISA KEV membership and the FIRST EPSS score."""

    __tablename__ = "cve_intel"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_date_added: Mapped[date | None] = mapped_column(Date)
    kev_due_date: Mapped[date | None] = mapped_column(Date)
    kev_ransomware: Mapped[bool] = mapped_column(Boolean, default=False)
    epss: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    updated_at: Mapped[datetime] = mapped_column(DateTime)


class AiTriage(Base):
    """Stored model output, kept so every AI answer can be audited later."""

    __tablename__ = "ai_triage"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime)
    prompt_sha256: Mapped[str] = mapped_column(String(64))
    result_json: Mapped[str] = mapped_column(Text)

    finding: Mapped[Finding] = relationship(back_populates="triages")
