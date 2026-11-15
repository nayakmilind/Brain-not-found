from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002_consent_sources"
down_revision: str | None = "0001_auth_tables"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "consents",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("scope_json", sa.JSON(), nullable=False),
        sa.Column("ip_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "accepted_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_consents_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_consents")),
    )
    op.create_index(op.f("ix_consents_user_id"), "consents", ["user_id"], unique=False)

    op.create_table(
        "sources",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("kind", sa.String(length=24), nullable=False),
        sa.Column("label_preview", sa.String(length=64), nullable=False),
        sa.Column("label_enc", sa.LargeBinary(), nullable=False),
        sa.Column("uri_enc", sa.LargeBinary(), nullable=True),
        sa.Column("content_enc", sa.LargeBinary(), nullable=True),
        sa.Column("content_media_type", sa.String(length=128), nullable=True),
        sa.Column("content_size", sa.Integer(), server_default="0", nullable=False),
        sa.Column("status", sa.String(length=16), server_default="ACTIVE", nullable=False),
        sa.Column(
            "ownership_status",
            sa.String(length=16),
            server_default="UNVERIFIED",
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_sources_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sources")),
    )
    op.create_index(op.f("ix_sources_user_id"), "sources", ["user_id"], unique=False)

    op.create_table(
        "ownership_challenges",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("source_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("method", sa.String(length=24), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["sources.id"],
            name=op.f("fk_ownership_challenges_source_id_sources"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ownership_challenges")),
    )
    op.create_index(
        op.f("ix_ownership_challenges_source_id"),
        "ownership_challenges",
        ["source_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        op.f("ix_ownership_challenges_source_id"),
        table_name="ownership_challenges",
    )
    op.drop_table("ownership_challenges")
    op.drop_index(op.f("ix_sources_user_id"), table_name="sources")
    op.drop_table("sources")
    op.drop_index(op.f("ix_consents_user_id"), table_name="consents")
    op.drop_table("consents")
