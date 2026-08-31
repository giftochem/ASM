import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.core.enums import (
    AssetCriticality,
    AssetEnvironment,
    AssetSource,
    AssetType,
    ChangeType,
    LifecycleStatus,
    RelationshipType,
)


class GraphNode(BaseModel):
    """One asset in a graph response. Mirrors AssetRead's field naming
    (`value`, not "normalized_value" -- Asset.value is already
    normalized at write time via normalize_asset_value, so this is the
    same value, just named consistently with the existing schema) but
    deliberately narrower: excludes organization_id (redundant -- every
    node in a response is already known to belong to the requesting
    org), authorization_confirmed*/notes/parent_asset_id/is_active
    (internal-authorization and free-text fields with no clear
    visualization purpose -- "do not expose sensitive/internal fields
    unnecessarily").
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_type: AssetType
    value: str
    status: LifecycleStatus
    source: AssetSource
    confidence: float
    environment: AssetEnvironment | None
    criticality: AssetCriticality | None
    owner: str | None
    tags: list[str]
    first_seen: datetime
    last_seen: datetime


class GraphEdge(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_asset_id: uuid.UUID
    target_asset_id: uuid.UUID
    relationship_type: RelationshipType
    status: LifecycleStatus
    confidence: float
    created_at: datetime
    updated_at: datetime


class GraphTraversalMetadata(BaseModel):
    seed_asset_id: uuid.UUID
    depth: int
    node_count: int
    edge_count: int


class AssetGraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    metadata: GraphTraversalMetadata


class ActivityFeedItem(BaseModel):
    """One Observation, denormalized with just enough Asset context
    (asset_type/asset_value) to be understandable without a second
    request -- both come from Asset via the join in
    graph_service.get_activity_feed, not stored on Observation itself.
    `source` is Observation's own existing AssetSource field
    (manual/discovery) -- the closest already-available "provider
    information"; no per-provider-name field exists on Observation, so
    none is invented here.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    asset_type: AssetType
    asset_value: str
    change_type: ChangeType
    field_name: str | None
    previous_value: str | None
    current_value: str | None
    observed_at: datetime
    source: AssetSource
    confidence: float


class AttackSurfaceSummary(BaseModel):
    """Descriptive inventory statistics only -- explicitly not a risk
    score. See graph_service.get_attack_surface_summary's docstring.
    """

    total_assets: int
    assets_by_type: dict[str, int]
    assets_by_status: dict[str, int]
    assets_by_criticality: dict[str, int]
    total_relationships: int
    relationships_by_type: dict[str, int]
    total_observations: int
    recent_observations_last_7_days: int
    isolated_asset_count: int


class SharedInfrastructureAssetRef(BaseModel):
    asset_id: uuid.UUID
    value: str


class SharedInfrastructureGroup(BaseModel):
    provider: str
    asn: str | None
    assets: list[SharedInfrastructureAssetRef]
