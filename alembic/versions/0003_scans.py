from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0003_scans"
down_revision: str | None = "0002_consent_sources"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="QUEUED", nullable=False),
        sa.Column(
            "stage_checkpoint",
            sa.String(length=24),
            server_default="QUEUED",
            nullable=False,
        ),
        sa.Column("mode", sa.String(length=16), nullable=False),
        sa.Column("idempotency_key_hash", sa.String(length=64), nullable=False),
        sa.Column("request_fingerprint", sa.String(length=64), nullable=False),
        sa.Column(
            "result_state",
            sa.String(length=24),
            server_default="NOT_GENERATED",
            nullable=False,
        ),
        sa.Column("event_sequence", sa.Integer(), server_default="0", nullable=False),
        sa.Column("queue_generation", sa.Integer(), server_default="1", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.CheckConstraint(
            "status IN ('QUEUED', 'FETCHING', 'ANALYZING', 'SCORING', "
            "'DONE', 'FAILED', 'CANCELLED')",
            name=op.f("ck_scans_valid_status"),
        ),
        sa.CheckConstraint("mode IN ('STANDARD', 'EPHEMERAL')", name=op.f("ck_scans_valid_mode")),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_scans_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scans")),
        sa.UniqueConstraint(
            "user_id",
            "idempotency_key_hash",
            name=op.f("uq_scans_user_id"),
        ),
    )
    op.create_index(op.f("ix_scans_user_id"), "scans", ["user_id"], unique=False)

    op.create_table(
        "scan_sources",
        sa.Column("scan_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("source_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "fetch_status",
            sa.String(length=16),
            server_default="NOT_STARTED",
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_scan_sources_scan_id_scans"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["sources.id"],
            name=op.f("fk_scan_sources_source_id_sources"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("scan_id", "source_id", name=op.f("pk_scan_sources")),
    )

    op.create_table(
        "scan_events",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("stage_checkpoint", sa.String(length=24), nullable=False),
        sa.Column("message", sa.String(length=120), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_scan_events_scan_id_scans"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_events")),
        sa.UniqueConstraint(
            "scan_id",
            "sequence",
            name=op.f("uq_scan_events_scan_id"),
        ),
    )
    op.create_index(op.f("ix_scan_events_scan_id"), "scan_events", ["scan_id"], unique=False)

    op.create_table(
        "scan_dead_letters",
        sa.Column("scan_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_scan_dead_letters_scan_id_scans"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("scan_id", name=op.f("pk_scan_dead_letters")),
    )


def downgrade() -> None:
    op.drop_table("scan_dead_letters")
    op.drop_index(op.f("ix_scan_events_scan_id"), table_name="scan_events")
    op.drop_table("scan_events")
    op.drop_table("scan_sources")
    op.drop_index(op.f("ix_scans_user_id"), table_name="scans")
    op.drop_table("scans")
