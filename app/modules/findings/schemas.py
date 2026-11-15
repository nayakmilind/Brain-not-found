from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

FindingCategory = Literal[
    "CONTACT",
    "IDENTITY",
    "LOCATION",
    "FINANCIAL",
    "EDUCATION",
    "EMPLOYMENT",
    "BIOMETRIC_HINT",
    "HANDLE",
]
EvidenceClass = Literal["VERIFIED", "INFERRED", "UNCERTAIN"]


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    source_id: UUID
    type: str
    category: FindingCategory
    masked_preview: str
    span_start: int
    span_end: int
    detector: str
    confidence: float
    evidence_class: EvidenceClass
    visibility: Literal["MASKED", "REVEALABLE"]
    sensitivity: int
    context_flags_json: list[str]


class FindingsPage(BaseModel):
    items: list[FindingResponse]
    next_cursor: UUID | None
