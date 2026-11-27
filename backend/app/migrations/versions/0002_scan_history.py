"""Scan history: what each scan saw, every status change, and the original reports.

Scans imported before this revision keep their stored totals for the trend chart. Their
findings get a "first seen" event, a "fixed" event where they were fixed, and the open
ones are linked to the last scan that reported them so later scans carry them forward.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-27
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("external_id", sa.String(64)))
    op.add_column(
        "scans",
        sa.Column("origin", sa.String(16), nullable=False, server_default="upload"),
    )
    op.add_column(
        "scans",
        sa.Column("task_name", sa.String(255), nullable=False, server_default=""),
    )
    # Existing rows were imported without history.
    op.add_column(
        "scans",
        sa.Column("has_history", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_scans_external_id", "scans", ["external_id"], unique=True)
    op.add_column("findings", sa.Column("qod", sa.Integer()))

    op.create_table(
        "scan_hosts",
        sa.Column(
            "scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "host_id", sa.Integer(), sa.ForeignKey("hosts.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("complete", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_scan_hosts_host_id", "scan_hosts", ["host_id"])

    op.create_table(
        "scan_findings",
        sa.Column(
            "scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("carried", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_scan_findings_finding_id", "scan_findings", ["finding_id"])

    op.create_table(
        "finding_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "finding_id", sa.Integer(), sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="SET NULL")),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_finding_events_finding_id", "finding_events", ["finding_id"])
    op.create_index("ix_finding_events_scan_id", "finding_events", ["scan_id"])
    op.create_index("ix_finding_events_at", "finding_events", ["at"])

    op.create_table(
        "scan_archives",
        sa.Column(
            "scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("media_type", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("gzip_data", sa.LargeBinary(), nullable=False),
    )

    _backfill()


def _backfill() -> None:
    findings = sa.table(
        "findings",
        sa.column("id", sa.Integer),
        sa.column("host_id", sa.Integer),
        sa.column("last_scan_id", sa.Integer),
        sa.column("severity", sa.Integer),
        sa.column("status", sa.String),
        sa.column("first_seen", sa.DateTime),
        sa.column("fixed_at", sa.DateTime),
    )
    events = sa.table(
        "finding_events",
        sa.column("finding_id", sa.Integer),
        sa.column("scan_id", sa.Integer),
        sa.column("kind", sa.String),
        sa.column("at", sa.DateTime),
    )
    scan_hosts = sa.table(
        "scan_hosts",
        sa.column("scan_id", sa.Integer),
        sa.column("host_id", sa.Integer),
        sa.column("complete", sa.Boolean),
    )
    observations = sa.table(
        "scan_findings",
        sa.column("scan_id", sa.Integer),
        sa.column("finding_id", sa.Integer),
        sa.column("severity", sa.Integer),
        sa.column("carried", sa.Boolean),
    )

    op.execute(
        events.insert().from_select(
            ["finding_id", "scan_id", "kind", "at"],
            sa.select(findings.c.id, sa.null(), sa.literal("new"), findings.c.first_seen),
        )
    )
    op.execute(
        events.insert().from_select(
            ["finding_id", "scan_id", "kind", "at"],
            sa.select(
                findings.c.id, sa.null(), sa.literal("fixed"), findings.c.fixed_at
            ).where(findings.c.status == "fixed", findings.c.fixed_at.is_not(None)),
        )
    )

    # An open finding was reported by its host's latest scan, so linking it there is
    # enough for later scans to carry the right open set forward.
    still_open = (findings.c.status == "open") & findings.c.last_scan_id.is_not(None)
    op.execute(
        scan_hosts.insert().from_select(
            ["scan_id", "host_id", "complete"],
            sa.select(findings.c.last_scan_id, findings.c.host_id, sa.true())
            .where(still_open)
            .distinct(),
        )
    )
    op.execute(
        observations.insert().from_select(
            ["scan_id", "finding_id", "severity", "carried"],
            sa.select(
                findings.c.last_scan_id, findings.c.id, findings.c.severity, sa.false()
            ).where(still_open),
        )
    )


def downgrade() -> None:
    op.drop_table("scan_archives")
    op.drop_table("finding_events")
    op.drop_table("scan_findings")
    op.drop_table("scan_hosts")
    op.drop_column("findings", "qod")
    op.drop_index("ix_scans_external_id", table_name="scans")
    for column in ("has_history", "task_name", "origin", "external_id"):
        op.drop_column("scans", column)
