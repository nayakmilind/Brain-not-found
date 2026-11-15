from uuid import UUID

from app.db.models.graph import Entity, GraphEdge
from app.modules.graph.schemas import (
    GRAPH_KIND_VALUES,
    GraphEdgeResponse,
    GraphNodeResponse,
    GraphResponse,
)

_KIND_LABELS = {
    "PERSON": "person",
    "EMAIL": "email address",
    "PHONE": "phone number",
    "ORG": "organization",
    "LOCATION": "location",
    "HANDLE": "social handle",
    "ID": "identity or financial detail",
}


def present_graph(
    entities: list[Entity],
    edges: list[GraphEdge],
    source_ids: dict[UUID, list[UUID]],
    *,
    truncated: bool,
) -> GraphResponse:
    entity_by_id = {entity.id: entity for entity in entities}
    nodes = [
        GraphNodeResponse(
            id=entity.id,
            kind=GRAPH_KIND_VALUES[entity.kind],
            masked_label=entity.label_masked,
            source_ids=source_ids.get(entity.id, []),
            source_count=len(source_ids.get(entity.id, [])),
        )
        for entity in entities
    ]

    response_edges: list[GraphEdgeResponse] = []
    reasons: set[str] = set()
    kind_pairs: set[frozenset[str]] = set()
    for edge in edges:
        source_entity = entity_by_id[edge.src_entity_id]
        target_entity = entity_by_id[edge.dst_entity_id]
        left_label = _KIND_LABELS[source_entity.kind]
        right_label = _KIND_LABELS[target_entity.kind]
        reason = (
            f"The masked value {source_entity.label_masked} ({left_label}) and "
            f"{target_entity.label_masked} ({right_label}) appeared together in "
            "one authorized source."
        )
        reasons.add(reason)
        kind_pairs.add(frozenset((source_entity.kind, target_entity.kind)))
        response_edges.append(
            GraphEdgeResponse(
                id=edge.id,
                source_entity_id=edge.src_entity_id,
                target_entity_id=edge.dst_entity_id,
                relation=edge.relation,
                source_id=edge.source_id,
                weight=edge.weight,
                evidence_finding_ids=[UUID(value) for value in edge.evidence_finding_ids],
                reason=reason,
            )
        )

    multi_source_entities = 0
    for entity in entities:
        entity_sources = source_ids.get(entity.id, [])
        if len(entity_sources) > 1:
            multi_source_entities += 1
            reasons.add(
                f"The same masked value {entity.label_masked} "
                f"({_KIND_LABELS[entity.kind]}) appears in "
                f"{len(entity_sources)} authorized sources, linking them."
            )

    if truncated:
        reasons.add(
            "The graph was truncated; the maximum combination multiplier is used conservatively."
        )
        multiplier = 1.6
    else:
        multiplier_units = min(6, len(kind_pairs) + multi_source_entities)
        multiplier = round(1.0 + multiplier_units * 0.1, 2)
    return GraphResponse(
        nodes=nodes,
        edges=response_edges,
        combination_multiplier=multiplier,
        combination_reasons=sorted(reasons),
        truncated=truncated,
    )
