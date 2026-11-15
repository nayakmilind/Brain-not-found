from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

ReportFormat = Literal["json", "html", "pdf"]


class ReportCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: ReportFormat


class ReportCreatedResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_id: UUID
    format: ReportFormat
    created_at: datetime
