import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.core.enums import AlertPriority, AlertStatus, AlertType, AssetType


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    asset_id: uuid.UUID | None
    # Step 9.13: denormalized from the Alert.asset relationship (see
    # app/models/alert.py's asset_value/asset_type properties) so a
    # frontend list of alerts doesn't need a second lookup per row to
    # show which asset each one is about -- mirrors ActivityFeedItem's
    # identical existing precedent.
    asset_value: str | None = None
    asset_type: AssetType | None = None
    relationship_id: uuid.UUID | None
    discovery_run_id: uuid.UUID | None
    source_observation_id: uuid.UUID | None
    alert_type: AlertType
    priority: AlertPriority
    title: str
    description: str
    evidence: dict | None
    status: AlertStatus
    fingerprint: str
    first_seen_at: datetime
    last_seen_at: datetime
    occurrence_count: int
    acknowledged_at: datetime | None
    acknowledged_by: uuid.UUID | None
    resolved_at: datetime | None
    resolved_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
