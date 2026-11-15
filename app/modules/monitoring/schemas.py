from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

MonitorCadence = Literal["DAILY", "WEEKLY"]
MonitorPauseReason = Literal["CONSENT_REVOKED", "SOURCE_NOT_ELIGIBLE"]


class MonitoringCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: UUID
    cadence: MonitorCadence = "WEEKLY"


class MonitoringResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    baseline_scan_id: UUID
    cadence: MonitorCadence
    next_run_at: datetime
    active: bool
    pause_reason: MonitorPauseReason | None
    created_at: datetime


class ScanDiffResponse(BaseModel):
    id: UUID
    from_scan_id: UUID
    to_scan_id: UUID
    added: list[dict[str, object]]
    removed: list[dict[str, object]]
    new_exposure_count: int
    score_delta: int
    truncated: bool
    created_at: datetime


class MonitoringTimelineResponse(BaseModel):
    monitor: MonitoringResponse
    diffs: list[ScanDiffResponse]
