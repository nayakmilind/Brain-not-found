from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    CheckConstraint,
    Float,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RiskScore(Base):
    __tablename__ = "risk_scores"
    __table_args__ = (
        CheckConstraint("total >= 0 AND total <= 100", name="valid_total"),
        CheckConstraint(
            "band IN ('LOW', 'MODERATE', 'HIGH', 'CRITICAL')",
            name="valid_band",
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="valid_confidence"),
        UniqueConstraint("scan_id", name="uq_risk_scores_scan_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    total: Mapped[int] = mapped_column(Integer, nullable=False)
    band: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    factors_json: Mapped[list[dict[str, object]]] = mapped_column(JSON, nullable=False)
    combination_json: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    method_version: Mapped[str] = mapped_column(String(32), nullable=False)
