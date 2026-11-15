from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

RecommendationStatus = Literal["OPEN", "DONE", "DISMISSED"]


class RecommendationStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: RecommendationStatus


class RecommendationStatusResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: RecommendationStatus


class RecommendationResponse(BaseModel):
    id: UUID
    playbook_id: str
    platform: str
    title: str
    description: str
    finding_types: list[str]
    evidence_previews: list[str]
    finding_count: int
    steps: list[str]
    priority: Literal["LOW", "MEDIUM", "HIGH"]
    effort_minutes: int
    expected_score_gain: int
    status: RecommendationStatus
