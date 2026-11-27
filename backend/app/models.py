"""Database schema.

The findings table is cumulative: one row per (host, plugin, port, protocol). Each import
updates that row instead of adding a copy, which is what makes aging, "fixed" and
"reopened" tracking possible.
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
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base

STATUS_OPEN = "open"
STATUS_FIXED = "fixed"


class Scan(Base):
    """One imported scan file, plus a snapshot of open findings right after the import."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(32))
    filename: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64), unique=True)
    report_name: Mapped[str] = mapped_column(String(255), default="")
    scan_time: Mapped[datetime] = mapped_column(DateTime, index=True)
    imported_at: Mapped[datetime] = mapped_column(DateTime)

    host_count: Mapped[int] = mapped_column(Integer, default=0)
    item_count: Mapped[int] = mapped_column(Integer, default=0)
    new_count: Mapped[int] = mapped_column(Integer, default=0)
    fixed_count: Mapped[int] = mapped_column(Integer, default=0)
    reopened_count: Mapped[int] = mapped_column(Integer, default=0)

    # Open findings across all hosts after this import (drives the trend chart).
    open_critical: Mapped[int] = mapped_column(Integer, default=0)
    open_high: Mapped[int] = mapped_column(Integer, default=0)
    open_medium: Mapped[int] = mapped_column(Integer, default=0)
    open_low: Mapped[int] = mapped_column(Integer, default=0)


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


class FindingCve(Base):
    __tablename__ = "finding_cves"

    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True
    )
    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True, index=True)

    finding: Mapped[Finding] = relationship(back_populates="cves")


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
