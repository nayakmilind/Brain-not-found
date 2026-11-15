from __future__ import annotations

from dataclasses import dataclass
from math import prod

from app.db.models.finding import Finding
from app.modules.graph.schemas import GraphResponse
from app.modules.scoring.schemas import (
    RISK_BAND_VALUES,
    CombinationResponse,
    RiskBand,
    RiskFactorResponse,
    ScoreResponse,
)

SCORE_METHOD_VERSION = "score-v1"
SCORE_DISCLAIMER = (
    "Estimate based only on supplied sources and this documented method. "
    "A low-risk or clean result does not prove complete safety."
)
_EVIDENCE_MULTIPLIERS = {"VERIFIED": 1.0, "INFERRED": 0.8, "UNCERTAIN": 0.5}
_SOURCE_VISIBILITY = {
    "URL": (1.0, "FETCHABLE_URL_INDEXING_UNKNOWN"),
    "TEXT": (0.7, "SELF_DECLARED_VISIBILITY_UNKNOWN"),
    "FILE": (0.7, "SELF_DECLARED_VISIBILITY_UNKNOWN"),
    "PLATFORM_EXPORT": (0.7, "SELF_DECLARED_VISIBILITY_UNKNOWN"),
}
_CONTEXT_FLAGS = {
    "CONTACT_CONTEXT",
    "ADDRESS_CONTEXT",
    "BIRTH_CONTEXT",
    "PROFILE_CONTEXT",
}


@dataclass(frozen=True)
class FindingExposure:
    finding: Finding
    source_kind: str


@dataclass(frozen=True)
class ScoreCalculation:
    total: int
    band: RiskBand
    confidence: float
    factors_json: list[dict[str, object]]
    combination_json: dict[str, object]
    method_version: str


def calculate_score(
    exposures: list[FindingExposure],
    graph: GraphResponse,
) -> ScoreCalculation:
    factors: list[dict[str, object]] = []
    risks: list[float] = []
    confidence_values: list[float] = []

    for exposure in exposures:
        finding = exposure.finding
        sensitivity = finding.sensitivity / 5
        visibility, visibility_basis = _SOURCE_VISIBILITY.get(
            exposure.source_kind,
            (0.7, "UNKNOWN_SOURCE_VISIBILITY_DEFAULT"),
        )
        context = _context_factor(finding.context_flags_json)
        evidence_multiplier = _EVIDENCE_MULTIPLIERS[finding.evidence_class]
        confidence_factor = finding.confidence * evidence_multiplier
        risk = sensitivity * visibility * context * confidence_factor
        risks.append(risk)
        confidence_values.append(confidence_factor)
        factors.append(
            {
                "finding_id": str(finding.id),
                "type": finding.type,
                "evidence_class": finding.evidence_class,
                "visibility_basis": visibility_basis,
                "S": sensitivity,
                "V": visibility,
                "C": context,
                "K": confidence_factor,
                "risk": risk,
            }
        )

    base_risk = aggregate_risk(risks)
    raw_risk = min(1.0, base_risk * graph.combination_multiplier)
    total = min(100, max(0, round(raw_risk * 100)))
    confidence = sum(confidence_values) / len(confidence_values) if confidence_values else 0.0
    band = risk_band(total)
    combination = {
        "multiplier": graph.combination_multiplier,
        "reasons": graph.combination_reasons,
        "truncated": graph.truncated,
    }
    return ScoreCalculation(
        total=total,
        band=band,
        confidence=confidence,
        factors_json=factors,
        combination_json=combination,
        method_version=SCORE_METHOD_VERSION,
    )


def aggregate_risk(finding_risks: list[float]) -> float:
    if any(risk < 0 or risk > 1 for risk in finding_risks):
        raise ValueError("Finding risk values must be between zero and one")
    return 1.0 - prod(1.0 - risk for risk in finding_risks)


def risk_band(risk_score: int) -> RiskBand:
    if risk_score < 25:
        return "LOW"
    if risk_score < 50:
        return "MODERATE"
    if risk_score < 75:
        return "HIGH"
    return "CRITICAL"


def score_response(calculation: ScoreCalculation) -> ScoreResponse:
    combination = calculation.combination_json
    multiplier = combination.get("multiplier")
    reasons = combination.get("reasons")
    truncated = combination.get("truncated")
    if not isinstance(multiplier, (int, float)):
        raise ValueError("Stored combination multiplier is invalid")
    if not isinstance(reasons, list) or not all(isinstance(reason, str) for reason in reasons):
        raise ValueError("Stored combination reasons are invalid")
    if not isinstance(truncated, bool):
        raise ValueError("Stored graph truncation state is invalid")
    return ScoreResponse(
        risk_score=calculation.total,
        privacy_score=100 - calculation.total,
        band=calculation.band,
        confidence=calculation.confidence,
        factors=[RiskFactorResponse.model_validate(factor) for factor in calculation.factors_json],
        combination=CombinationResponse(
            multiplier=float(multiplier),
            reasons=reasons,
            truncated=truncated,
        ),
        method_version=calculation.method_version,
        disclaimer=SCORE_DISCLAIMER,
    )


def score_response_from_record(
    *,
    total: int,
    band: str,
    confidence: float,
    factors_json: list[dict[str, object]],
    combination_json: dict[str, object],
    method_version: str,
) -> ScoreResponse:
    return score_response(
        ScoreCalculation(
            total=total,
            band=RISK_BAND_VALUES[band],
            confidence=confidence,
            factors_json=factors_json,
            combination_json=combination_json,
            method_version=method_version,
        )
    )


def _context_factor(context_flags: list[str]) -> float:
    factor = 0.6
    flags = set(context_flags)
    if flags & _CONTEXT_FLAGS:
        factor += 0.2
    if flags & {"TITLE", "METADATA"}:
        factor += 0.1
    if "VISIBLE_TEXT" in flags:
        factor += 0.1
    factor = min(1.0, factor)
    if "HIDDEN_TEXT" in flags and not flags & {"TITLE", "METADATA"}:
        factor = min(0.5, factor)
    return factor
