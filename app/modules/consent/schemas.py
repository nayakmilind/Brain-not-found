from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.modules.consent.service import CONSENT_VERSION


class ConsentAcceptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: str
    accepted: bool


class ConsentStateResponse(BaseModel):
    accepted: bool
    version: str
    scope: dict[str, bool]
    accepted_at: datetime | None


class ConsentRevocationResponse(BaseModel):
    revoked: bool
    revoked_at: datetime | None


class ConsentCurrentVersionResponse(BaseModel):
    version: str = CONSENT_VERSION
    scope: dict[str, bool]
    statements: tuple[str, ...]
