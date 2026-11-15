from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0005_exposure_graph"
down_revision: str | None = "0004_findings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("graph_truncated", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.create_table(
        "entities",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("canonical_hmac", sa.String(length=64), nullable=False),
        sa.Column("label_masked", sa.String(length=256), nullable=False),
        sa.CheckConstraint(
            "kind IN ('PERSON', 'EMAIL', 'PHONE', 'ORG', 'LOCATION', 'HANDLE', 'ID')",
            name=op.f("ck_entities_valid_kind"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
            name=op.f("fk_entities_scan_id_scans"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_entities")),
        sa.UniqueConstraint(
            "scan_id",
            "id",
            name=op.f("uq_entities_scan_id_id"),
        ),
        sa.UniqueConstraint(
            "scan_id",
            "kind",
            "canonical_hmac",
            name=op.f("uq_scan_entity_hmac"),
        ),
    )
    op.create_index(op.f("ix_entities_scan_id"), "entities", ["scan_id"], unique=False)

    op.create_table(
        "entity_mentions",
        sa.Column("entity_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("finding_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["entity_id"],
            ["entities.id"],
            name=op.f("fk_entity_mentions_entity_id_entities"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name=op.f("fk_entity_mentions_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "entity_id",
            "finding_id",
            name=op.f("pk_entity_mentions"),
        ),
    )

    op.create_table(
        "graph_edges",
        sa.Column("id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("source_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("src_entity_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("dst_entity_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("relation", sa.String(length=16), nullable=False),
        sa.Column("weight", sa.Float(), nullable=False),
        sa.Column("evidence_finding_ids", sa.JSON(), nullable=False),
        sa.CheckConstraint("relation = 'CO_OCCURS'", name=op.f("ck_graph_edges_valid_relation")),
        sa.CheckConstraint("weight >= 0 AND weight <= 1", name=op.f("ck_graph_edges_valid_weight")),
        sa.ForeignKeyConstraint(
            ["scan_id", "source_id"],
            ["scan_sources.scan_id", "scan_sources.source_id"],
            name=op.f("fk_graph_edges_scan_source_scan_sources"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["scan_id", "src_entity_id"],
            ["entities.scan_id", "entities.id"],
            name=op.f("fk_graph_edges_src_entity_scan"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["scan_id", "dst_entity_id"],
            ["entities.scan_id", "entities.id"],
            name=op.f("fk_graph_edges_dst_entity_scan"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_graph_edges")),
        sa.UniqueConstraint(
            "scan_id",
            "source_id",
            "src_entity_id",
            "dst_entity_id",
            "relation",
            name=op.f("uq_graph_edge_source_pair"),
        ),
    )
    op.create_index(op.f("ix_graph_edges_scan_id"), "graph_edges", ["scan_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_graph_edges_scan_id"), table_name="graph_edges")
    op.drop_table("graph_edges")
    op.drop_table("entity_mentions")
    op.drop_index(op.f("ix_entities_scan_id"), table_name="entities")
    op.drop_table("entities")
    op.drop_column("scans", "graph_truncated")
