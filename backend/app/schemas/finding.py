import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.core.enums import FindingSeverity


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    scan_id: uuid.UUID
    asset_id: uuid.UUID
    module: str
    title: str
    description: str | None
    severity: FindingSeverity
    confidence: float
    exposure: float
    exploitability: float
    evidence: dict | None
    created_at: datetime
