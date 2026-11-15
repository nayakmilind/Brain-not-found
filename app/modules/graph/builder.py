from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from heapq import nsmallest
from itertools import combinations
from uuid import UUID, uuid5

from app.db.models.finding import Finding
from app.db.models.graph import Entity, EntityMention, GraphEdge

MAX_GRAPH_FINDINGS = 50_000
MAX_GRAPH_NODES = 2_000
MAX_GRAPH_EDGES = 10_000

_KIND_BY_FINDING_TYPE = {
    "CREDIT_CARD": "ID",
    "DATE_TIME": "ID",
    "DOB_DATE": "ID",
    "EMAIL_ADDRESS": "EMAIL",
    "IBAN_CODE": "ID",
    "LOCATION": "LOCATION",
    "ORGANIZATION": "ORG",
    "PERSON": "PERSON",
    "PHONE_NUMBER": "PHONE",
    "SOCIAL_HANDLE": "HANDLE",
    "US_SSN": "ID",
    "US_ZIP_CODE": "LOCATION",
}


@dataclass(frozen=True)
class BuiltGraph:
    entities: list[Entity]
    mentions: list[EntityMention]
    edges: list[GraphEdge]
    source_ids: dict[UUID, list[UUID]]
    truncated: bool


def build_graph(scan_id: UUID, findings: list[Finding]) -> BuiltGraph:
    selected_findings = nsmallest(MAX_GRAPH_FINDINGS, findings, key=_finding_priority)
    truncated = len(findings) > MAX_GRAPH_FINDINGS
    grouped: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for finding in selected_findings:
        kind = _KIND_BY_FINDING_TYPE.get(finding.type)
        if kind is not None:
            grouped[(kind, finding.value_hmac)].append(finding)

    ordered_groups = sorted(
        grouped.items(),
        key=lambda item: (
            -max(finding.sensitivity for finding in item[1]),
            -max(finding.confidence for finding in item[1]),
            -len({finding.source_id for finding in item[1]}),
            -len(item[1]),
            item[0],
        ),
    )
    truncated = truncated or len(ordered_groups) > MAX_GRAPH_NODES
    kept_groups = ordered_groups[:MAX_GRAPH_NODES]
    entities: list[Entity] = []
    mentions: list[EntityMention] = []
    findings_by_source: dict[UUID, dict[UUID, list[Finding]]] = defaultdict(
        lambda: defaultdict(list)
    )
    source_ids_by_entity: dict[UUID, set[UUID]] = defaultdict(set)

    for (kind, canonical_hmac), group_findings in kept_groups:
        entity_id = uuid5(scan_id, f"entity:{kind}:{canonical_hmac}")
        representative = min(
            group_findings,
            key=lambda finding: (
                -finding.sensitivity,
                -finding.confidence,
                finding.source_id.hex,
                finding.span_start,
                finding.id.hex,
            ),
        )
        entities.append(
            Entity(
                id=entity_id,
                scan_id=scan_id,
                kind=kind,
                canonical_hmac=canonical_hmac,
                label_masked=representative.masked_preview,
            )
        )
        for finding in group_findings:
            mentions.append(EntityMention(entity_id=entity_id, finding_id=finding.id))
            findings_by_source[finding.source_id][entity_id].append(finding)
            source_ids_by_entity[entity_id].add(finding.source_id)

    edges: list[GraphEdge] = []
    for source_id in sorted(findings_by_source, key=lambda value: value.hex):
        source_entities = findings_by_source[source_id]
        entity_ids = sorted(source_entities, key=lambda value: value.hex)
        for left_id, right_id in combinations(entity_ids, 2):
            if len(edges) >= MAX_GRAPH_EDGES:
                truncated = True
                break
            left_finding = _representative(source_entities[left_id])
            right_finding = _representative(source_entities[right_id])
            evidence_ids = sorted((str(left_finding.id), str(right_finding.id)))
            edges.append(
                GraphEdge(
                    id=uuid5(
                        scan_id,
                        f"edge:{source_id}:{left_id}:{right_id}:CO_OCCURS",
                    ),
                    scan_id=scan_id,
                    source_id=source_id,
                    src_entity_id=left_id,
                    dst_entity_id=right_id,
                    relation="CO_OCCURS",
                    weight=1.0,
                    evidence_finding_ids=evidence_ids,
                )
            )
        if truncated and len(edges) >= MAX_GRAPH_EDGES:
            break

    return BuiltGraph(
        entities=entities,
        mentions=mentions,
        edges=edges,
        source_ids={
            entity_id: sorted(source_ids, key=lambda value: value.hex)
            for entity_id, source_ids in source_ids_by_entity.items()
        },
        truncated=truncated,
    )


def _representative(findings: list[Finding]) -> Finding:
    return min(
        findings,
        key=lambda finding: (
            -finding.sensitivity,
            -finding.confidence,
            finding.span_start,
            finding.id.hex,
        ),
    )


def _finding_priority(finding: Finding) -> tuple[float, float, str, int, str]:
    return (
        -finding.sensitivity,
        -finding.confidence,
        finding.source_id.hex,
        finding.span_start,
        finding.id.hex,
    )
