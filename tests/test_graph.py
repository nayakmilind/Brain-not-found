from uuid import UUID, uuid4

from app.db.models.finding import Finding
from app.modules.graph import builder


def _finding(
    scan_id: UUID,
    source_id: UUID,
    entity_type: str,
    value_hmac: str,
    preview: str,
    *,
    sensitivity: int = 3,
) -> Finding:
    return Finding(
        id=uuid4(),
        scan_id=scan_id,
        source_id=source_id,
        type=entity_type,
        category="IDENTITY",
        masked_preview=preview,
        value_hmac=value_hmac,
        value_enc=None,
        span_start=0,
        span_end=1,
        detector="synthetic_test",
        confidence=0.9,
        evidence_class="INFERRED",
        visibility="MASKED",
        sensitivity=sensitivity,
        context_flags_json=[],
    )


def test_build_graph_resolves_same_hmac_and_is_deterministic() -> None:
    scan_id = UUID("f63ef8a7-6e9a-4879-a972-f849a6ed34f4")
    first_source = UUID("4f4c5787-7824-456e-a6ee-a61d64465b07")
    second_source = UUID("4c1f98f1-3303-46a2-bbd5-04ea59d57575")
    findings = [
        _finding(scan_id, first_source, "PERSON", "person-hmac", "M***** E******"),
        _finding(scan_id, first_source, "EMAIL_ADDRESS", "email-hmac", "m*******@e******.test"),
        _finding(scan_id, second_source, "EMAIL_ADDRESS", "email-hmac", "m*******@e******.test"),
    ]

    graph = builder.build_graph(scan_id, findings)
    repeated = builder.build_graph(scan_id, findings)

    assert len(graph.entities) == 2
    assert len(graph.mentions) == 3
    assert len(graph.edges) == 1
    assert graph.truncated is False
    email_entity = next(entity for entity in graph.entities if entity.kind == "EMAIL")
    assert email_entity.canonical_hmac == "email-hmac"
    assert email_entity.id == next(
        entity.id for entity in repeated.entities if entity.kind == "EMAIL"
    )
    assert all(
        "morgan@example.test" not in entity.label_masked
        and "morgan@example.test" not in entity.canonical_hmac
        for entity in graph.entities
    )


def test_build_graph_reports_node_and_edge_limits(monkeypatch) -> None:
    scan_id = uuid4()
    source_id = uuid4()
    findings = [
        _finding(scan_id, source_id, "PERSON", "person-hmac", "M***** E******"),
        _finding(scan_id, source_id, "EMAIL_ADDRESS", "email-hmac", "m*******@e******.test"),
        _finding(scan_id, source_id, "PHONE_NUMBER", "phone-hmac", "***0142"),
    ]

    monkeypatch.setattr(builder, "MAX_GRAPH_NODES", 2)
    node_limited = builder.build_graph(scan_id, findings)
    assert len(node_limited.entities) == 2
    assert node_limited.truncated is True

    monkeypatch.setattr(builder, "MAX_GRAPH_NODES", 10)
    monkeypatch.setattr(builder, "MAX_GRAPH_EDGES", 1)
    edge_limited = builder.build_graph(scan_id, findings)
    assert len(edge_limited.entities) == 3
    assert len(edge_limited.edges) == 1
    assert edge_limited.truncated is True


def test_build_graph_reports_finding_limit(monkeypatch) -> None:
    scan_id = uuid4()
    source_id = uuid4()
    findings = [
        _finding(scan_id, source_id, "PERSON", "person-hmac", "M***** E******"),
        _finding(scan_id, source_id, "EMAIL_ADDRESS", "email-hmac", "m*******@e******.test"),
        _finding(scan_id, source_id, "PHONE_NUMBER", "phone-hmac", "***0142"),
    ]
    monkeypatch.setattr(builder, "MAX_GRAPH_FINDINGS", 2)

    graph = builder.build_graph(scan_id, findings)

    assert len(graph.mentions) == 2
    assert graph.truncated is True
