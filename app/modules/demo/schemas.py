from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.modules.scans.schemas import ScanStatus

PersonaPattern = Literal["contact", "profile", "all"]


class PersonaCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seed: int = Field(ge=0, le=2_147_483_647)
    pattern: PersonaPattern = "all"


class PersonaScanResponse(BaseModel):
    synthetic: Literal[True] = True
    source_id: UUID
    scan_id: UUID
    status: ScanStatus
    pattern: PersonaPattern
