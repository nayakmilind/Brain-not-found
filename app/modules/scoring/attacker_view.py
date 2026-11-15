from app.modules.scoring.calculation import FindingExposure
from app.modules.scoring.schemas import (
    AttackerFactorResponse,
    AttackerScenarioResponse,
    AttackerViewResponse,
    RiskRating,
)

_SCENARIO_RULES = (
    (
        "phishing_personalisation",
        "Phishing personalisation readiness",
        {"EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "ORGANIZATION", "SOCIAL_HANDLE"},
        "Remove unnecessary contact details from public sources and use platform privacy controls.",
    ),
    (
        "sim_swap_kyc_answer",
        "SIM-swap / KYC-answer readiness (defensive)",
        {"PHONE_NUMBER", "DOB_DATE", "DATE_TIME", "US_SSN", "US_ZIP_CODE"},
        "Remove phone and identity details from public sources; enable carrier account PIN "
        "and port-out protections.",
    ),
    (
        "impersonation",
        "Impersonation readiness",
        {"PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "SOCIAL_HANDLE"},
        "Restrict profile visibility, avoid reusing public identifiers, and report impersonation "
        "through official platform channels.",
    ),
)

_DISCLAIMER = (
    "Rule-based defensive indicators based only on detected findings. They do not predict "
    "that an attack will occur and do not perform or enable real-world actions."
)


def build_attacker_view(exposures: list[FindingExposure]) -> AttackerViewResponse:
    finding_by_type: dict[str, FindingExposure] = {}
    for exposure in sorted(
        exposures,
        key=lambda item: (
            -item.finding.sensitivity,
            -item.finding.confidence,
            item.finding.type,
            item.finding.id.hex,
        ),
    ):
        finding_by_type.setdefault(exposure.finding.type, exposure)

    present_types = set(finding_by_type)
    scenarios: list[AttackerScenarioResponse] = []
    for scenario_id, title, considered_types, defensive_fix in _SCENARIO_RULES:
        matched_types = present_types & considered_types
        rating = _scenario_rating(scenario_id, present_types)
        factors = [
            AttackerFactorResponse(
                finding_id=finding_by_type[entity_type].finding.id,
                type=entity_type,
                masked_preview=finding_by_type[entity_type].finding.masked_preview,
            )
            for entity_type in sorted(matched_types)
        ]
        scenarios.append(
            AttackerScenarioResponse(
                scenario=scenario_id,
                title=title,
                rating=rating,
                rationale=_rationale(scenario_id, rating, matched_types),
                factors=factors,
                defensive_fix=defensive_fix,
            )
        )
    return AttackerViewResponse(scenarios=scenarios, disclaimer=_DISCLAIMER)


def _scenario_rating(scenario: str, types: set[str]) -> RiskRating:
    if scenario == "phishing_personalisation":
        if "EMAIL_ADDRESS" in types and types & {"PERSON", "ORGANIZATION", "SOCIAL_HANDLE"}:
            return "HIGH"
        if types & {"EMAIL_ADDRESS", "PHONE_NUMBER", "SOCIAL_HANDLE", "ORGANIZATION"}:
            return "MEDIUM"
        return "LOW"
    if scenario == "sim_swap_kyc_answer":
        identity_types = {"DOB_DATE", "DATE_TIME", "US_SSN", "US_ZIP_CODE"}
        if "PHONE_NUMBER" in types and types & identity_types:
            return "HIGH"
        if "PHONE_NUMBER" in types or types & identity_types:
            return "MEDIUM"
        return "LOW"
    if "PERSON" in types and types & {"EMAIL_ADDRESS", "PHONE_NUMBER", "SOCIAL_HANDLE"}:
        return "HIGH"
    if types & {"PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "SOCIAL_HANDLE"}:
        return "MEDIUM"
    return "LOW"


def _rationale(scenario: str, rating: str, matched_types: set[str]) -> str:
    if rating == "LOW":
        return "No matching high-sensitivity combination was detected in the supplied findings."
    type_list = ", ".join(sorted(matched_types))
    if scenario == "phishing_personalisation":
        return f"Detected masked contact/profile categories: {type_list}."
    if scenario == "sim_swap_kyc_answer":
        return f"Detected masked phone or identity categories: {type_list}."
    return f"Detected masked identity/profile categories: {type_list}."
