from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0008_reports_audit"
down_revision: str | None = "0007_recommendations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("format", sa.String(length=8), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "format IN ('json', 'html', 'pdf')",
            name=op.f("ck_reports_valid_format"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_reports_scan_id_scans"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_reports")),
    )
    op.create_index(op.f("ix_reports_scan_id"), "reports", ["scan_id"], unique=False)

    op.create_table(
        "audit_entries",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("actor_hash", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=48), nullable=False),
        sa.Column("object_type", sa.String(length=32), nullable=False),
        sa.Column("object_hash", sa.String(length=64), nullable=False),
        sa.Column("ip_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("entry_hash", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_entries")),
        sa.UniqueConstraint("sequence", name=op.f("uq_audit_entries_sequence")),
    )
    op.create_index(
        op.f("ix_audit_entries_sequence"),
        "audit_entries",
        ["sequence"],
        unique=True,
    )
    op.create_index(
        op.f("ix_audit_entries_actor_hash"),
        "audit_entries",
        ["actor_hash"],
        unique=False,
    )

    op.create_table(
        "audit_chain_heads",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("last_sequence", sa.Integer(), nullable=False),
        sa.Column("last_hash", sa.String(length=64), nullable=False),
        sa.CheckConstraint("id = 1", name=op.f("ck_audit_chain_heads_singleton")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_chain_heads")),
    )
    op.bulk_insert(
        sa.table(
            "audit_chain_heads",
            sa.column("id", sa.Integer()),
            sa.column("last_sequence", sa.Integer()),
            sa.column("last_hash", sa.String()),
        ),
        [{"id": 1, "last_sequence": 0, "last_hash": "0" * 64}],
    )


def downgrade() -> None:
    op.drop_table("audit_chain_heads")
    op.drop_index(op.f("ix_audit_entries_actor_hash"), table_name="audit_entries")
    op.drop_index(op.f("ix_audit_entries_sequence"), table_name="audit_entries")
    op.drop_table("audit_entries")
    op.drop_index(op.f("ix_reports_scan_id"), table_name="reports")
    op.drop_table("reports")
