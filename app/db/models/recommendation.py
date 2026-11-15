from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    CheckConstraint,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Recommendation(Base):
    __tablename__ = "recommendations"
    __table_args__ = (
        CheckConstraint(
            "priority IN ('LOW', 'MEDIUM', 'HIGH')",
            name="valid_priority",
        ),
        CheckConstraint(
            "status IN ('OPEN', 'DONE', 'DISMISSED')",
            name="valid_status",
        ),
        CheckConstraint("effort_minutes > 0", name="valid_effort"),
        CheckConstraint("expected_score_gain >= 0", name="valid_score_gain"),
        CheckConstraint("finding_count > 0", name="valid_finding_count"),
        UniqueConstraint("scan_id", "playbook_id"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    playbook_id: Mapped[str] = mapped_column(String(64), nullable=False)
    priority: Mapped[str] = mapped_column(String(16), nullable=False)
    effort_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    expected_score_gain: Mapped[int] = mapped_column(Integer, nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence_previews_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="OPEN")
