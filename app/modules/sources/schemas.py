from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field


class URLSourceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    kind: Literal["URL"]
    label: str = Field(min_length=1, max_length=120)
    uri: AnyHttpUrl


class TextSourceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    kind: Literal["TEXT", "PLATFORM_EXPORT"]
    label: str = Field(min_length=1, max_length=120)
    content: str = Field(min_length=1, max_length=5_242_880)


SourceCreate = Annotated[
    URLSourceCreate | TextSourceCreate,
    Field(discriminator="kind"),
]


class SourceResponse(BaseModel):
    id: UUID
    kind: str
    label_preview: str
    status: str
    ownership_status: str
    created_at: datetime


class SourceListResponse(BaseModel):
    items: list[SourceResponse]
    limit: int
    offset: int
