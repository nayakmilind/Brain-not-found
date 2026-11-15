from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0007_recommendations"
down_revision: str | None = "0006_risk_scoring"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_STATUS_CHECK = (
    "status IN ('QUEUED', 'FETCHING', 'ANALYZING', 'SCORING', 'RECOMMENDING', "
    "'DONE', 'FAILED', 'CANCELLED')"
)
_PREVIOUS_STATUS_CHECK = (
    "status IN ('QUEUED', 'FETCHING', 'ANALYZING', 'SCORING', 'DONE', 'FAILED', 'CANCELLED')"
)


def upgrade() -> None:
    _replace_scan_status_check(_STATUS_CHECK)
    op.create_table(
        "recommendations",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("playbook_id", sa.String(length=64), nullable=False),
        sa.Column("priority", sa.String(length=16), nullable=False),
        sa.Column("effort_minutes", sa.Integer(), nullable=False),
        sa.Column("expected_score_gain", sa.Integer(), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("evidence_previews_json", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=16), server_default="OPEN", nullable=False),
        sa.CheckConstraint(
            "priority IN ('LOW', 'MEDIUM', 'HIGH')",
            name=op.f("ck_recommendations_valid_priority"),
        ),
        sa.CheckConstraint(
            "status IN ('OPEN', 'DONE', 'DISMISSED')",
            name=op.f("ck_recommendations_valid_status"),
        ),
        sa.CheckConstraint("effort_minutes > 0", name=op.f("ck_recommendations_valid_effort")),
        sa.CheckConstraint(
            "expected_score_gain >= 0",
            name=op.f("ck_recommendations_valid_score_gain"),
        ),
        sa.CheckConstraint(
            "finding_count > 0",
            name=op.f("ck_recommendations_valid_finding_count"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_recommendations_scan_id_scans"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_recommendations")),
        sa.UniqueConstraint(
            "scan_id",
            "playbook_id",
            name=op.f("uq_recommendations_scan_id"),
        ),
    )
    op.create_index(
        op.f("ix_recommendations_scan_id"),
        "recommendations",
        ["scan_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_recommendations_scan_id"), table_name="recommendations")
    op.drop_table("recommendations")
    _replace_scan_status_check(_PREVIOUS_STATUS_CHECK)


def _replace_scan_status_check(expression: str) -> None:
    check_name = op.f("ck_scans_valid_status")
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("scans", recreate="always") as batch_op:
            batch_op.drop_constraint(check_name, type_="check")
            batch_op.create_check_constraint(check_name, expression)
        return
    op.drop_constraint(check_name, "scans", type_="check")
    op.create_check_constraint(check_name, "scans", expression)
