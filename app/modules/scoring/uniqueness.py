from __future__ import annotations

from functools import lru_cache
from importlib.resources import files
from math import prod
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.modules.scoring.schemas import UniquenessResponse

_DISCLAIMER = (
    "Very-low-confidence, type-only heuristic using an illustrative reference cohort. "
    "It does not use or compare actual names, locations, colleges, or demographic records."
)


class UniquenessLookup(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method_version: str
    reference_cohort_size: int = Field(gt=0)
    type_selectivity: dict[str, float]

    @model_validator(mode="after")
    def validate_selectivity(self) -> UniquenessLookup:
        if any(value <= 0 or value > 1 for value in self.type_selectivity.values()):
            raise ValueError("Type selectivity values must be greater than zero and at most one")
        return self


@lru_cache(maxsize=1)
def _lookup() -> UniquenessLookup:
    lookup_path = files("app.data").joinpath("uniqueness_lookup.yaml")
    lookup_data: Any = yaml.safe_load(lookup_path.read_text(encoding="utf-8"))
    return UniquenessLookup.model_validate(lookup_data)


def estimate_uniqueness(finding_types: set[str]) -> UniquenessResponse:
    lookup = _lookup()
    quasi_identifier_types = sorted(finding_types & lookup.type_selectivity.keys())
    selectivity = prod(lookup.type_selectivity[item] for item in quasi_identifier_types)
    estimated_candidates = max(
        1,
        round(lookup.reference_cohort_size * selectivity),
    )
    return UniquenessResponse(
        estimated_candidate_count=estimated_candidates,
        reference_cohort_size=lookup.reference_cohort_size,
        estimated_uniqueness=round(1 - estimated_candidates / lookup.reference_cohort_size, 6),
        quasi_identifier_types=quasi_identifier_types,
        confidence="VERY_LOW",
        method_version=lookup.method_version,
        disclaimer=_DISCLAIMER,
    )
