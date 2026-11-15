from typing import Literal
from uuid import UUID

from pydantic import BaseModel

GraphKind = Literal["PERSON", "EMAIL", "PHONE", "ORG", "LOCATION", "HANDLE", "ID"]

GRAPH_KIND_VALUES: dict[str, GraphKind] = {
    "PERSON": "PERSON",
    "EMAIL": "EMAIL",
    "PHONE": "PHONE",
    "ORG": "ORG",
    "LOCATION": "LOCATION",
    "HANDLE": "HANDLE",
    "ID": "ID",
}


class GraphNodeResponse(BaseModel):
    id: UUID
    kind: GraphKind
    masked_label: str
    source_ids: list[UUID]
    source_count: int


class GraphEdgeResponse(BaseModel):
    id: UUID
    source_entity_id: UUID
    target_entity_id: UUID
    relation: Literal["CO_OCCURS"]
    source_id: UUID
    weight: float
    evidence_finding_ids: list[UUID]
    reason: str


class GraphResponse(BaseModel):
    nodes: list[GraphNodeResponse]
    edges: list[GraphEdgeResponse]
    combination_multiplier: float
    combination_reasons: list[str]
    truncated: bool
