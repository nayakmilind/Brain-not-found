from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.modules.graph.schemas import GraphResponse

RiskBand = Literal["LOW", "MODERATE", "HIGH", "CRITICAL"]
RiskRating = Literal["LOW", "MEDIUM", "HIGH"]
RISK_BAND_VALUES: dict[str, RiskBand] = {
    "LOW": "LOW",
    "MODERATE": "MODERATE",
    "HIGH": "HIGH",
    "CRITICAL": "CRITICAL",
}


class RiskFactorResponse(BaseModel):
    finding_id: UUID
    type: str
    evidence_class: Literal["VERIFIED", "INFERRED", "UNCERTAIN"]
    visibility_basis: str
    S: float
    V: float
    C: float
    K: float
    risk: float


class CombinationResponse(BaseModel):
    multiplier: float
    reasons: list[str]
    truncated: bool


class ScoreResponse(BaseModel):
    risk_score: int
    privacy_score: int
    band: RiskBand
    confidence: float
    factors: list[RiskFactorResponse]
    combination: CombinationResponse
    method_version: str
    disclaimer: str


class UniquenessResponse(BaseModel):
    estimated_candidate_count: int
    reference_cohort_size: int
    estimated_uniqueness: float
    quasi_identifier_types: list[str]
    confidence: Literal["VERY_LOW"]
    method_version: str
    disclaimer: str


class AttackerFactorResponse(BaseModel):
    finding_id: UUID
    type: str
    masked_preview: str


class AttackerScenarioResponse(BaseModel):
    scenario: str
    title: str
    rating: RiskRating
    rationale: str
    factors: list[AttackerFactorResponse]
    defensive_fix: str


class AttackerViewResponse(BaseModel):
    scenarios: list[AttackerScenarioResponse]
    disclaimer: str


class SimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    remove_findings: list[UUID] = Field(default_factory=list, max_length=500)

    @field_validator("remove_findings")
    @classmethod
    def require_unique_findings(cls, value: list[UUID]) -> list[UUID]:
        if len(set(value)) != len(value):
            raise ValueError("Finding IDs must be unique")
        return value


class SimulationResponse(BaseModel):
    score: ScoreResponse
    graph: GraphResponse
