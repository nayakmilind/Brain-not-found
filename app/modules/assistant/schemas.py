from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.modules.recommendations.schemas import RecommendationResponse

FallbackReason = Literal[
    "disabled",
    "external_processing_not_approved",
    "provider_unavailable",
    "invalid_output",
    "pii_detected",
]


class AssistantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: UUID
    question: str = Field(min_length=1, max_length=2000)
    allow_external_processing: bool = False

    @field_validator("question")
    @classmethod
    def require_nonblank_question(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Question cannot be blank")
        return normalized


class AssistantModelOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    answer_focus: Literal["score", "findings", "combination", "confidence"]
    playbook_ids: list[str] = Field(max_length=10)

    @field_validator("playbook_ids")
    @classmethod
    def require_unique_playbooks(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("Playbook IDs must be unique")
        return value


class AssistantResponse(BaseModel):
    answer: str
    recommendations: list[RecommendationResponse]
    used_fallback: bool
    fallback_reason: FallbackReason | None
    disclaimer: str
