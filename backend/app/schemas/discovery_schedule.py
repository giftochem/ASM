import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import AssetType, DiscoveryRunStatus
from app.services.discovery_schedule_service import MAX_INTERVAL_HOURS, MIN_INTERVAL_HOURS


class DiscoveryScheduleCreate(BaseModel):
    seed_asset_id: uuid.UUID
    provider_name: str
    interval_hours: int = Field(ge=MIN_INTERVAL_HOURS, le=MAX_INTERVAL_HOURS)


class DiscoveryScheduleUpdate(BaseModel):
    """Both fields optional -- a PATCH may change either independently.
    At least one should be provided in practice, but an empty body is
    harmless (a no-op update), not rejected."""

    enabled: bool | None = None
    interval_hours: int | None = Field(default=None, ge=MIN_INTERVAL_HOURS, le=MAX_INTERVAL_HOURS)


class DiscoveryScheduleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    seed_asset_id: uuid.UUID
    # Step 9.13: denormalized from the seed_asset/last_run relationships
    # (see app/models/discovery_schedule.py) so a frontend list of
    # schedules doesn't need N extra lookups to show the asset name and
    # whether the last run failed -- mirrors ActivityFeedItem/AlertRead's
    # identical existing precedent.
    seed_asset_value: str
    seed_asset_type: AssetType
    last_run_status: DiscoveryRunStatus | None = None
    provider_name: str
    enabled: bool
    interval_hours: int
    next_run_at: datetime
    last_run_at: datetime | None
    last_run_id: uuid.UUID | None
    disabled_reason: str | None
    created_at: datetime
    updated_at: datetime
