import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.config import settings
from app.core.enums import (
    AssetCriticality,
    AssetEnvironment,
    AssetSource,
    AssetType,
    ChangeType,
    LifecycleStatus,
    RelationshipType,
)
from app.core.exceptions import InvalidTargetError
from app.core.validation import normalize_asset_value


class AssetCreate(BaseModel):
    asset_type: AssetType
    value: str = Field(min_length=1, max_length=255)
    notes: str | None = None

    @model_validator(mode="after")
    def _validate_and_normalize_value(self) -> "AssetCreate":
        try:
            self.value = normalize_asset_value(
                self.asset_type, self.value, settings.max_ip_range_prefix_length
            )
        except InvalidTargetError as exc:
            raise ValueError(str(exc)) from exc
        return self


class AssetUpdate(BaseModel):
    """PATCH /assets/{asset_id} (Stage A.1). Deliberately narrow: only the
    human-set business context -- criticality and environment -- can be
    changed here. Any other field is rejected (extra="forbid") rather than
    ignored, so a request can't even appear to change an asset's identity,
    organization, authorization status, lifecycle or discovery evidence.
    An absent field is left untouched; a field sent as null clears the
    value back to unset."""

    model_config = ConfigDict(extra="forbid")

    criticality: AssetCriticality | None = None
    environment: AssetEnvironment | None = None

    @model_validator(mode="after")
    def _require_a_field(self) -> "AssetUpdate":
        if not self.model_fields_set:
            raise ValueError("provide at least one of: criticality, environment")
        return self


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    organization_id: uuid.UUID
    asset_type: AssetType
    value: str
    parent_asset_id: uuid.UUID | None
    authorization_confirmed: bool
    authorization_confirmed_by: uuid.UUID | None
    authorization_confirmed_at: datetime | None
    notes: str | None
    is_active: bool
    created_at: datetime
    updated_at: datetime
    # --- Step 8.1 fields, exposed for the first time here ---
    status: LifecycleStatus
    source: AssetSource
    confidence: float
    environment: AssetEnvironment | None
    criticality: AssetCriticality | None
    owner: str | None
    tags: list[str]
    first_seen: datetime
    last_seen: datetime


class AssetAuthorizationConfirm(BaseModel):
    """The client must explicitly send authorization_confirmed=true; there
    is no implicit/default path to True. Kept as its own schema/endpoint
    (rather than allowing this field on AssetCreate) so the audit log
    always captures a deliberate confirmation action, distinct from asset
    creation.
    """

    authorization_confirmed: bool = Field(
        ..., description="Must be true; attests you own or are authorized to test this target."
    )
    attestation_note: str | None = Field(
        default=None, description="Optional free-text note, e.g. a reference to the engagement/scope doc."
    )


class AssetAuthorizationRevoke(BaseModel):
    reason: str | None = Field(
        default=None, description="Optional free-text reason for revoking authorization."
    )


class AssetRelationshipCreate(BaseModel):
    target_asset_id: uuid.UUID
    relationship_type: RelationshipType
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    notes: str | None = None


class AssetRelationshipRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_asset_id: uuid.UUID
    target_asset_id: uuid.UUID
    relationship_type: RelationshipType
    status: LifecycleStatus
    source: AssetSource
    confidence: float
    first_seen: datetime
    last_seen: datetime
    notes: str | None
    created_at: datetime
    updated_at: datetime


class ObservationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    observed_at: datetime
    change_type: ChangeType
    field_name: str | None
    previous_value: str | None
    current_value: str | None
    source: AssetSource
    confidence: float
    created_at: datetime
