import hashlib
from uuid import UUID, uuid4

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.db.models.finding import Finding
from app.modules.graph import builder as graph_builder
from app.modules.graph.presentation import present_graph
from app.modules.scoring.attacker_view import build_attacker_view
from app.modules.scoring.calculation import (
    FindingExposure,
    aggregate_risk,
    calculate_score,
    risk_band,
)
from app.modules.scoring.uniqueness import estimate_uniqueness


def _finding(
    entity_type: str,
    *,
    evidence_class: str = "VERIFIED",
    context_flags: list[str] | None = None,
    sensitivity: int = 4,
    confidence: float = 0.85,
    preview: str = "m*******@e******.test",
    scan_id: UUID | None = None,
    source_id: UUID | None = None,
) -> Finding:
    return Finding(
        id=uuid4(),
        scan_id=scan_id or uuid4(),
        source_id=source_id or uuid4(),
        type=entity_type,
        category="CONTACT",
        masked_preview=preview,
        value_hmac=hashlib.sha256(f"{entity_type}:{uuid4()}".encode()).hexdigest(),
        value_enc=None,
        span_start=0,
        span_end=1,
        detector="synthetic_test",
        confidence=confidence,
        evidence_class=evidence_class,
        visibility="MASKED",
        sensitivity=sensitivity,
        context_flags_json=context_flags or [],
    )


@given(
    risks=st.lists(st.floats(min_value=0, max_value=1, allow_nan=False, allow_infinity=False)),
    added=st.floats(min_value=0, max_value=1, allow_nan=False, allow_infinity=False),
)
def test_aggregate_risk_never_decreases_when_a_finding_is_added(
    risks: list[float],
    added: float,
) -> None:
    assert aggregate_risk([*risks, added]) >= aggregate_risk(risks)


def test_scoring_explains_each_factor_and_applies_source_visibility() -> None:
    finding = _finding(
        "EMAIL_ADDRESS",
        context_flags=["CONTACT_CONTEXT", "VISIBLE_TEXT"],
    )
    graph = present_graph([], [], {}, truncated=False)

    url_score = calculate_score([FindingExposure(finding, "URL")], graph)
    declared_score = calculate_score([FindingExposure(finding, "TEXT")], graph)
    factor = url_score.factors_json[0]

    assert factor["S"] == 0.8
    assert factor["V"] == 1.0
    assert factor["C"] == 0.9
    assert factor["K"] == 0.85
    assert factor["visibility_basis"] == "FETCHABLE_URL_INDEXING_UNKNOWN"
    assert url_score.total > declared_score.total
    assert url_score.method_version == "score-v1"
    assert url_score.band == "HIGH"


def test_empty_findings_are_not_presented_as_high_confidence() -> None:
    result = calculate_score([], present_graph([], [], {}, truncated=False))

    assert result.total == 0
    assert result.confidence == 0.0
    assert result.band == "LOW"


def test_adding_a_finding_cannot_lower_score_when_it_truncates_the_graph(
    monkeypatch,
) -> None:
    scan_id = uuid4()
    source_id = uuid4()
    findings = [
        _finding("PERSON", scan_id=scan_id, source_id=source_id, preview="M***** E******"),
        _finding("EMAIL_ADDRESS", scan_id=scan_id, source_id=source_id),
        _finding("CREDIT_CARD", scan_id=scan_id, source_id=source_id, sensitivity=5),
    ]
    monkeypatch.setattr(graph_builder, "MAX_GRAPH_NODES", 2)

    before_graph = graph_builder.build_graph(scan_id, findings[:2])
    after_graph = graph_builder.build_graph(scan_id, findings)
    before = calculate_score(
        [FindingExposure(finding, "TEXT") for finding in findings[:2]],
        present_graph(
            before_graph.entities,
            before_graph.edges,
            before_graph.source_ids,
            truncated=before_graph.truncated,
        ),
    )
    after = calculate_score(
        [FindingExposure(finding, "TEXT") for finding in findings],
        present_graph(
            after_graph.entities,
            after_graph.edges,
            after_graph.source_ids,
            truncated=after_graph.truncated,
        ),
    )

    assert before_graph.truncated is False
    assert after_graph.truncated is True
    assert after.combination_json["multiplier"] == 1.6
    assert after.total >= before.total


@pytest.mark.parametrize(
    ("score", "expected_band"),
    [(24, "LOW"), (25, "MODERATE"), (50, "HIGH"), (75, "CRITICAL")],
)
def test_score_bands_follow_documented_thresholds(score: int, expected_band: str) -> None:
    assert risk_band(score) == expected_band


def test_uniqueness_is_labeled_as_a_type_only_estimate() -> None:
    result = estimate_uniqueness({"PERSON", "EMAIL_ADDRESS"})

    assert result.estimated_candidate_count < result.reference_cohort_size
    assert result.confidence == "VERY_LOW"
    assert result.method_version == "uniqueness-type-proxy-v1"
    assert "does not use or compare actual names" in result.disclaimer


def test_attacker_view_is_defensive_and_uses_masked_factors() -> None:
    exposures = [
        FindingExposure(_finding("PERSON", preview="M***** E******"), "TEXT"),
        FindingExposure(_finding("EMAIL_ADDRESS"), "TEXT"),
    ]

    result = build_attacker_view(exposures)
    phishing = next(
        scenario for scenario in result.scenarios if scenario.scenario == "phishing_personalisation"
    )

    assert phishing.rating == "HIGH"
    assert phishing.factors
    assert all("*" in factor.masked_preview for factor in phishing.factors)
    assert "do not perform or enable real-world actions" in result.disclaimer
