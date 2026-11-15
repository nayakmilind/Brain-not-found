from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Float,
    ForeignKeyConstraint,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(
            "category IN ('CONTACT', 'IDENTITY', 'LOCATION', 'FINANCIAL', "
            "'EDUCATION', 'EMPLOYMENT', 'BIOMETRIC_HINT', 'HANDLE')",
            name="valid_category",
        ),
        CheckConstraint(
            "evidence_class IN ('VERIFIED', 'INFERRED', 'UNCERTAIN')",
            name="valid_evidence_class",
        ),
        CheckConstraint(
            "(visibility = 'MASKED' AND value_enc IS NULL) OR "
            "(visibility = 'REVEALABLE' AND value_enc IS NOT NULL)",
            name="valid_visibility",
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="valid_confidence"),
        CheckConstraint(
            "sensitivity >= 1 AND sensitivity <= 5",
            name="valid_sensitivity",
        ),
        CheckConstraint("span_start >= 0 AND span_end > span_start", name="valid_span"),
        ForeignKeyConstraint(
            ["scan_id", "source_id"],
            ["scan_sources.scan_id", "scan_sources.source_id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "scan_id",
            "source_id",
            "type",
            "span_start",
            "span_end",
            name="uq_findings_source_span",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, index=True)
    source_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(48), nullable=False)
    category: Mapped[str] = mapped_column(String(24), nullable=False)
    masked_preview: Mapped[str] = mapped_column(String(256), nullable=False)
    value_hmac: Mapped[str] = mapped_column(String(64), nullable=False)
    value_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    span_start: Mapped[int] = mapped_column(Integer, nullable=False)
    span_end: Mapped[int] = mapped_column(Integer, nullable=False)
    detector: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    evidence_class: Mapped[str] = mapped_column(String(16), nullable=False)
    visibility: Mapped[str] = mapped_column(String(16), nullable=False)
    sensitivity: Mapped[int] = mapped_column(Integer, nullable=False)
    context_flags_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
