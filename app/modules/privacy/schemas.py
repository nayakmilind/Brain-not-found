from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AuditEntryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    sequence: int
    action: str
    object_type: str
    object_hash: str
    created_at: datetime
    prev_hash: str
    entry_hash: str


class AuditPageResponse(BaseModel):
    items: list[AuditEntryResponse]
    next_cursor: int | None


class AuditIntegrityResponse(BaseModel):
    valid: bool
    checked_entries: int
    first_invalid_sequence: int | None
