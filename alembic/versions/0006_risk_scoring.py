from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0006_risk_scoring"
down_revision: str | None = "0005_exposure_graph"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "risk_scores",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("band", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("factors_json", sa.JSON(), nullable=False),
        sa.Column("combination_json", sa.JSON(), nullable=False),
        sa.Column("method_version", sa.String(length=32), nullable=False),
        sa.CheckConstraint(
            "total >= 0 AND total <= 100",
            name=op.f("ck_risk_scores_valid_total"),
        ),
        sa.CheckConstraint(
            "band IN ('LOW', 'MODERATE', 'HIGH', 'CRITICAL')",
            name=op.f("ck_risk_scores_valid_band"),
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name=op.f("ck_risk_scores_valid_confidence"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_risk_scores_scan_id_scans"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_risk_scores")),
        sa.UniqueConstraint("scan_id", name=op.f("uq_risk_scores_scan_id")),
    )
    op.create_index(op.f("ix_risk_scores_scan_id"), "risk_scores", ["scan_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_risk_scores_scan_id"), table_name="risk_scores")
    op.drop_table("risk_scores")
