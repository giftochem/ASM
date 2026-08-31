import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.core.enums import ReportFormat, ReportStatus


class ReportCreate(BaseModel):
    scan_id: uuid.UUID
    format: ReportFormat


class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    generated_by: uuid.UUID
    format: ReportFormat
    status: ReportStatus
    storage_path: str | None
    generated_at: datetime | None
    error_message: str | None
    created_at: datetime
