import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.core.enums import AssetType, DiscoveryResultOutcome, DiscoveryRunStatus, RelationshipType


class DiscoveryRunCreate(BaseModel):
    seed_asset_id: uuid.UUID
    # Not an enum: validated against the provider registry in
    # discovery_service, not here, mirroring ScanCreate.modules staying
    # unvalidated at the schema layer to avoid schemas importing the
    # providers package.
    provider_name: str


class DiscoveryRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    seed_asset_id: uuid.UUID
    initiated_by: uuid.UUID
    provider_name: str
    status: DiscoveryRunStatus
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    created_at: datetime
    updated_at: datetime


class DiscoveryResultRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    discovery_run_id: uuid.UUID
    candidate_asset_type: AssetType
    candidate_value: str
    relationship_type: RelationshipType | None
    confidence: float
    evidence: dict | None
    outcome: DiscoveryResultOutcome
    resulting_asset_id: uuid.UUID | None
    created_at: datetime


class DiscoveryProviderInfo(BaseModel):
    """Step 9.13: a pure read over the existing, already-registered
    DISCOVERY_PROVIDER_REGISTRY (app/discovery/registry.py) -- no new
    provider logic, just making what already exists server-side
    discoverable to a client instead of forcing the frontend to
    hand-mirror provider names and their seed-type compatibility (the
    exact drift risk already logged as debt for the Scans module
    picker; this closes the equivalent gap for Discovery before it
    accrues the same way).
    """

    name: str
    applicable_seed_types: list[AssetType]
    depends_on: list[str]
