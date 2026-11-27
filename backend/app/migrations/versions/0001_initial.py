"""Version 0.1 schema.

Databases created by version 0.1 already have these tables; startup stamps them with
this revision instead of running it.

Revision ID: 0001
Revises:
Create Date: 2026-11-22
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("report_name", sa.String(255), nullable=False),
        sa.Column("scan_time", sa.DateTime(), nullable=False),
        sa.Column("imported_at", sa.DateTime(), nullable=False),
        sa.Column("host_count", sa.Integer(), nullable=False),
        sa.Column("item_count", sa.Integer(), nullable=False),
        sa.Column("new_count", sa.Integer(), nullable=False),
        sa.Column("fixed_count", sa.Integer(), nullable=False),
        sa.Column("reopened_count", sa.Integer(), nullable=False),
        sa.Column("open_critical", sa.Integer(), nullable=False),
        sa.Column("open_high", sa.Integer(), nullable=False),
        sa.Column("open_medium", sa.Integer(), nullable=False),
        sa.Column("open_low", sa.Integer(), nullable=False),
    )
    op.create_index("ix_scans_scan_time", "scans", ["scan_time"])

    op.create_table(
        "hosts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("ip", sa.String(64), nullable=False, unique=True),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("fqdn", sa.String(255), nullable=False),
        sa.Column("os", sa.String(255), nullable=False),
        sa.Column("mac", sa.String(64), nullable=False),
        sa.Column("criticality", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "host_id", sa.Integer(), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "last_scan_id", sa.Integer(), sa.ForeignKey("scans.id", ondelete="SET NULL")
        ),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("plugin_id", sa.String(64), nullable=False),
        sa.Column("plugin_name", sa.String(512), nullable=False),
        sa.Column("plugin_family", sa.String(255), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(16), nullable=False),
        sa.Column("service", sa.String(64), nullable=False),
        sa.Column("cvss_base", sa.Float()),
        sa.Column("cvss_vector", sa.String(128), nullable=False),
        sa.Column("exploit_available", sa.Boolean(), nullable=False),
        sa.Column("synopsis", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("solution", sa.Text(), nullable=False),
        sa.Column("plugin_output", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("fixed_at", sa.DateTime()),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("epss", sa.Float()),
        sa.Column("in_kev", sa.Boolean(), nullable=False),
        sa.Column("kev_due_date", sa.Date()),
        sa.UniqueConstraint("host_id", "source", "plugin_id", "port", "protocol"),
    )
    op.create_index("ix_findings_host_id", "findings", ["host_id"])
    op.create_index("ix_findings_status_risk", "findings", ["status", "risk_score"])

    op.create_table(
        "finding_cves",
        sa.Column(
            "finding_id",
            sa.Integer(),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("cve_id", sa.String(32), primary_key=True),
    )
    op.create_index("ix_finding_cves_cve_id", "finding_cves", ["cve_id"])

    op.create_table(
        "cve_intel",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("in_kev", sa.Boolean(), nullable=False),
        sa.Column("kev_date_added", sa.Date()),
        sa.Column("kev_due_date", sa.Date()),
        sa.Column("kev_ransomware", sa.Boolean(), nullable=False),
        sa.Column("epss", sa.Float()),
        sa.Column("epss_percentile", sa.Float()),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "ai_triage",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "finding_id",
            sa.Integer(),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("model", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("prompt_sha256", sa.String(64), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
    )
    op.create_index("ix_ai_triage_finding_id", "ai_triage", ["finding_id"])


def downgrade() -> None:
    for table in ("ai_triage", "cve_intel", "finding_cves", "findings", "hosts", "scans"):
        op.drop_table(table)
