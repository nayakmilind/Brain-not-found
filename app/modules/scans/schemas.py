from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

ScanMode = Literal["STANDARD", "EPHEMERAL"]
ScanStatus = Literal[
    "QUEUED",
    "FETCHING",
    "ANALYZING",
    "SCORING",
    "RECOMMENDING",
    "DONE",
    "FAILED",
    "CANCELLED",
]


class ScanCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_ids: list[UUID] = Field(min_length=1, max_length=20)
    mode: ScanMode = "STANDARD"

    @field_validator("source_ids")
    @classmethod
    def require_unique_sources(cls, value: list[UUID]) -> list[UUID]:
        if len(set(value)) != len(value):
            raise ValueError("Source IDs must be unique")
        return value


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: ScanStatus
    stage_checkpoint: str
    mode: ScanMode
    result_state: Literal["NOT_GENERATED", "GENERATED"]
    attempts: int
    error_code: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class ScanEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    sequence: int
    status: ScanStatus
    stage_checkpoint: str
    message: str
    created_at: datetime
