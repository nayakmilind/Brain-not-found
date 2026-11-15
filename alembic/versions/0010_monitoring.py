from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0010_monitoring"
down_revision: str | None = "0008_reports_audit"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "monitor_jobs",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("baseline_scan_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("last_scan_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("pending_scan_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("cadence", sa.String(length=16), nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("pause_reason", sa.String(length=32), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "cadence IN ('DAILY', 'WEEKLY')",
            name=op.f("ck_monitor_jobs_valid_cadence"),
        ),
        sa.CheckConstraint(
            "pause_reason IS NULL OR pause_reason IN ('CONSENT_REVOKED', 'SOURCE_NOT_ELIGIBLE')",
            name=op.f("ck_monitor_jobs_valid_pause_reason"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_monitor_jobs_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_monitor_jobs")),
        sa.UniqueConstraint(
            "pending_scan_id",
            name=op.f("uq_monitor_jobs_pending_scan_id"),
        ),
    )
    op.create_index(op.f("ix_monitor_jobs_user_id"), "monitor_jobs", ["user_id"], unique=False)

    op.create_table(
        "monitor_sources",
        sa.Column("monitor_job_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("source_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["monitor_job_id"],
            ["monitor_jobs.id"],
            name=op.f("fk_monitor_sources_monitor_job_id_monitor_jobs"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["sources.id"],
            name=op.f("fk_monitor_sources_source_id_sources"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "monitor_job_id",
            "source_id",
            name=op.f("pk_monitor_sources"),
        ),
    )
    op.create_index(
        op.f("ix_monitor_sources_source_id"),
        "monitor_sources",
        ["source_id"],
        unique=False,
    )

    op.create_table(
        "scan_diffs",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("monitor_job_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("from_scan_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("to_scan_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("added_json", sa.JSON(), nullable=False),
        sa.Column("removed_json", sa.JSON(), nullable=False),
        sa.Column("score_delta", sa.Integer(), nullable=False),
        sa.Column("truncated", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["monitor_job_id"],
            ["monitor_jobs.id"],
            name=op.f("fk_scan_diffs_monitor_job_id_monitor_jobs"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["from_scan_id"],
            ["scans.id"],
            name=op.f("fk_scan_diffs_from_scan_id_scans"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["to_scan_id"],
            ["scans.id"],
            name=op.f("fk_scan_diffs_to_scan_id_scans"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_diffs")),
        sa.UniqueConstraint("to_scan_id", name=op.f("uq_scan_diffs_to_scan_id")),
    )
    op.create_index(
        op.f("ix_scan_diffs_monitor_job_id"),
        "scan_diffs",
        ["monitor_job_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_scan_diffs_from_scan_id"),
        "scan_diffs",
        ["from_scan_id"],
        unique=False,
    )

    scan_monitor_column = sa.Column(
        "monitor_job_id",
        sa.Uuid(as_uuid=True),
        sa.ForeignKey(
            "monitor_jobs.id",
            name=op.f("fk_scans_monitor_job_id_monitor_jobs"),
            ondelete="SET NULL",
        ),
        nullable=True,
    )
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("scans", recreate="always") as batch_op:
            batch_op.add_column(scan_monitor_column)
    else:
        op.add_column("scans", scan_monitor_column)
    op.create_index(op.f("ix_scans_monitor_job_id"), "scans", ["monitor_job_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_scans_monitor_job_id"), table_name="scans")
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("scans", recreate="always") as batch_op:
            batch_op.drop_column("monitor_job_id")
    else:
        op.drop_column("scans", "monitor_job_id")
    op.drop_index(op.f("ix_scan_diffs_from_scan_id"), table_name="scan_diffs")
    op.drop_index(op.f("ix_scan_diffs_monitor_job_id"), table_name="scan_diffs")
    op.drop_table("scan_diffs")
    op.drop_index(op.f("ix_monitor_sources_source_id"), table_name="monitor_sources")
    op.drop_table("monitor_sources")
    op.drop_index(op.f("ix_monitor_jobs_user_id"), table_name="monitor_jobs")
    op.drop_table("monitor_jobs")
