import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.core.enums import AuditOutcome


class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID | None
    organization_id: uuid.UUID | None
    action: str
    resource_type: str
    resource_id: uuid.UUID | None
    outcome: AuditOutcome
    details: dict | None
    ip_address: str | None
    created_at: datetime
