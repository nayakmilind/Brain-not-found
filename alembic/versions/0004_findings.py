from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0004_findings"
down_revision: str | None = "0003_scans"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("source_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("type", sa.String(length=48), nullable=False),
        sa.Column("category", sa.String(length=24), nullable=False),
        sa.Column("masked_preview", sa.String(length=256), nullable=False),
        sa.Column("value_hmac", sa.String(length=64), nullable=False),
        sa.Column("value_enc", sa.LargeBinary(), nullable=True),
        sa.Column("span_start", sa.Integer(), nullable=False),
        sa.Column("span_end", sa.Integer(), nullable=False),
        sa.Column("detector", sa.String(length=64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence_class", sa.String(length=16), nullable=False),
        sa.Column("visibility", sa.String(length=16), nullable=False),
        sa.Column("sensitivity", sa.Integer(), nullable=False),
        sa.Column("context_flags_json", sa.JSON(), nullable=False),
        sa.CheckConstraint(
            "category IN ('CONTACT', 'IDENTITY', 'LOCATION', 'FINANCIAL', "
            "'EDUCATION', 'EMPLOYMENT', 'BIOMETRIC_HINT', 'HANDLE')",
            name=op.f("ck_findings_valid_category"),
        ),
        sa.CheckConstraint(
            "evidence_class IN ('VERIFIED', 'INFERRED', 'UNCERTAIN')",
            name=op.f("ck_findings_valid_evidence_class"),
        ),
        sa.CheckConstraint(
            "(visibility = 'MASKED' AND value_enc IS NULL) OR "
            "(visibility = 'REVEALABLE' AND value_enc IS NOT NULL)",
            name=op.f("ck_findings_valid_visibility"),
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name=op.f("ck_findings_valid_confidence"),
        ),
        sa.CheckConstraint(
            "sensitivity >= 1 AND sensitivity <= 5",
            name=op.f("ck_findings_valid_sensitivity"),
        ),
        sa.CheckConstraint(
            "span_start >= 0 AND span_end > span_start",
            name=op.f("ck_findings_valid_span"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_id", "source_id"],
            ["scan_sources.scan_id", "scan_sources.source_id"],
            name=op.f("fk_findings_scan_id_scan_sources"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
        sa.UniqueConstraint(
            "scan_id",
            "source_id",
            "type",
            "span_start",
            "span_end",
            name=op.f("uq_findings_source_span"),
        ),
    )
    op.create_index(op.f("ix_findings_scan_id"), "findings", ["scan_id"], unique=False)
    op.create_index(op.f("ix_findings_source_id"), "findings", ["source_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_findings_source_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_scan_id"), table_name="findings")
    op.drop_table("findings")
