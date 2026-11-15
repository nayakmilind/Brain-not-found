from typing import Literal
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field


class CredentialsRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class TokenResponse(BaseModel):
    user_id: UUID
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
