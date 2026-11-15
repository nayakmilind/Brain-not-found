from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class Playbook(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(min_length=1, max_length=64)
    platform: str = Field(min_length=1, max_length=32)
    title: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=256)
    finding_types: tuple[str, ...] = Field(min_length=1)
    steps: tuple[str, ...] = Field(min_length=1, max_length=8)
    effort_minutes: int = Field(gt=0, le=240)
    expected_score_gain: int = Field(ge=0, le=100)

    @model_validator(mode="after")
    def require_unique_finding_types(self) -> Playbook:
        if len(self.finding_types) != len(set(self.finding_types)):
            raise ValueError("Playbook finding types must be unique")
        return self


@lru_cache(maxsize=1)
def load_playbooks() -> tuple[Playbook, ...]:
    path = Path(__file__).parents[2] / "data" / "playbooks.yaml"
    content = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(content, list):
        raise ValueError("The playbook catalog must be a YAML list")
    playbooks = tuple(Playbook.model_validate(item) for item in content)
    ids = [playbook.id for playbook in playbooks]
    if len(ids) != len(set(ids)):
        raise ValueError("Playbook IDs must be unique")
    if not playbooks:
        raise ValueError("The playbook catalog cannot be empty")
    return playbooks


def playbooks_by_id() -> dict[str, Playbook]:
    return {playbook.id: playbook for playbook in load_playbooks()}
