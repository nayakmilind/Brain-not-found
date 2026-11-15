from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

OwnershipMethod = Literal["BIO_TOKEN", "META_TAG", "DNS_TXT", "EMAIL_OTP", "SELF_DECLARE"]


class OwnershipChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    method: OwnershipMethod
    email: EmailStr | None = None


class OwnershipChallengeResponse(BaseModel):
    challenge_id: UUID | None
    method: OwnershipMethod
    ownership_status: Literal["PENDING", "VERIFIED", "SELF_DECLARED"]
    token: str | None
    instructions: str
    expires_at: datetime | None


class OwnershipVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: UUID
    proof: str | None = Field(default=None, min_length=1, max_length=128)


class OwnershipVerifyResponse(BaseModel):
    verified: bool
    ownership_status: Literal["VERIFIED"]


class OwnershipMethodInfo(BaseModel):
    methods: tuple[OwnershipMethod, ...]
