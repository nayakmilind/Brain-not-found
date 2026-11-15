from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Entity(Base):
    __tablename__ = "entities"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('PERSON', 'EMAIL', 'PHONE', 'ORG', 'LOCATION', 'HANDLE', 'ID')",
            name="valid_kind",
        ),
        UniqueConstraint("scan_id", "id", name="uq_entities_scan_id_id"),
        UniqueConstraint("scan_id", "kind", "canonical_hmac", name="uq_scan_entity_hmac"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    canonical_hmac: Mapped[str] = mapped_column(String(64), nullable=False)
    label_masked: Mapped[str] = mapped_column(String(256), nullable=False)


class EntityMention(Base):
    __tablename__ = "entity_mentions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["entity_id"],
            ["entities.id"],
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            ondelete="CASCADE",
        ),
    )

    entity_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    finding_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)


class GraphEdge(Base):
    __tablename__ = "graph_edges"
    __table_args__ = (
        CheckConstraint("relation = 'CO_OCCURS'", name="valid_relation"),
        CheckConstraint("weight >= 0 AND weight <= 1", name="valid_weight"),
        ForeignKeyConstraint(
            ["scan_id", "src_entity_id"],
            ["entities.scan_id", "entities.id"],
            name="fk_graph_edges_src_entity_scan",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["scan_id", "dst_entity_id"],
            ["entities.scan_id", "entities.id"],
            name="fk_graph_edges_dst_entity_scan",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["scan_id", "source_id"],
            ["scan_sources.scan_id", "scan_sources.source_id"],
            name="fk_graph_edges_scan_source_scan_sources",
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "scan_id",
            "source_id",
            "src_entity_id",
            "dst_entity_id",
            "relation",
            name="uq_graph_edge_source_pair",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, index=True)
    source_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    src_entity_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    dst_entity_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        nullable=False,
    )
    relation: Mapped[str] = mapped_column(String(16), nullable=False)
    weight: Mapped[float] = mapped_column(Float, nullable=False)
    evidence_finding_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
