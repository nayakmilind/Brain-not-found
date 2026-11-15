from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    String,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class MonitorJob(Base):
    __tablename__ = "monitor_jobs"
    __table_args__ = (
        CheckConstraint("cadence IN ('DAILY', 'WEEKLY')", name="valid_cadence"),
        CheckConstraint(
            "pause_reason IS NULL OR pause_reason IN ('CONSENT_REVOKED', 'SOURCE_NOT_ELIGIBLE')",
            name="valid_pause_reason",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    baseline_scan_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    last_scan_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    pending_scan_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), unique=True)
    cadence: Mapped[str] = mapped_column(String(16), nullable=False)
    next_run_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    pause_reason: Mapped[str | None] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class MonitorSource(Base):
    __tablename__ = "monitor_sources"
    __table_args__ = (
        ForeignKeyConstraint(
            ["monitor_job_id"],
            ["monitor_jobs.id"],
            name="fk_monitor_sources_monitor_job_id_monitor_jobs",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["source_id"],
            ["sources.id"],
            name="fk_monitor_sources_source_id_sources",
            ondelete="CASCADE",
        ),
    )

    monitor_job_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    source_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)


class ScanDiff(Base):
    __tablename__ = "scan_diffs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["monitor_job_id"],
            ["monitor_jobs.id"],
            name="fk_scan_diffs_monitor_job_id_monitor_jobs",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["from_scan_id"],
            ["scans.id"],
            name="fk_scan_diffs_from_scan_id_scans",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["to_scan_id"],
            ["scans.id"],
            name="fk_scan_diffs_to_scan_id_scans",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    monitor_job_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, index=True)
    from_scan_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    to_scan_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, unique=True)
    added_json: Mapped[list[dict[str, object]]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    removed_json: Mapped[list[dict[str, object]]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    score_delta: Mapped[int] = mapped_column(Integer, nullable=False)
    truncated: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
