"""GET /assets/exposure-paths (Stage B) -- observed exposure paths, not
verified exploit chains. Deliberately carries no severity, score,
exploit probability or confidence value: nothing here has been
assessed for exploitability. Mirrors GraphNode's narrowness -- no
internal-authorization or free-text asset fields."""

import uuid
from datetime import datetime

from pydantic import BaseModel

from app.core.enums import AssetCriticality, AssetEnvironment, AssetSource, AssetType, RelationshipType
from app.services.attack_path_service import PathBasis, StepBasis


class PathAssetRef(BaseModel):
    asset_id: uuid.UUID
    asset_type: AssetType
    value: str
    criticality: AssetCriticality | None
    environment: AssetEnvironment | None


class EntryEvidenceRef(BaseModel):
    """One piece of the entry point's qualifying exposure evidence -- see
    exposure_evidence_service for what each field means."""

    evidence_type: str  # http_response | tls_handshake | open_port
    source: str
    subject: str
    freshness: str  # always "current" here: only current evidence qualifies
    first_confirmed_at: datetime | None
    last_confirmed_at: datetime | None
    latest_attempt_at: datetime | None
    inconclusive_attempts: int
    latest_inconclusive_at: datetime | None
    discovery_run_id: uuid.UUID | None
    scan_id: uuid.UUID | None
    result_id: uuid.UUID | None
    observation_id: uuid.UUID | None
    limitations: list[str]


class DnsEvidenceRef(BaseModel):
    """The dns discovery result behind an observed resolves_to step --
    no older than the freshness window at the assessment time."""

    result_id: uuid.UUID
    discovery_run_id: uuid.UUID
    observed_at: datetime
    record_type: str | None
    freshness: str  # always "current" here


class AnalystAssertionRef(BaseModel):
    """The audit record behind an analyst-asserted step. Who entered it
    is in that audit record (admin-only), not repeated here."""

    audit_log_id: uuid.UUID
    asserted_at: datetime


class PathStepRead(BaseModel):
    relationship_id: uuid.UUID
    relationship_type: RelationshipType
    from_asset_id: uuid.UUID
    to_asset_id: uuid.UUID
    direction: str  # always "forward": relationships are never walked in reverse
    basis: StepBasis
    relationship_source: AssetSource
    rule: str
    reason: str
    dns_evidence: DnsEvidenceRef | None
    analyst_assertion: AnalystAssertionRef | None


class ExposurePathRead(BaseModel):
    entry_point: PathAssetRef
    target: PathAssetRef
    hop_count: int
    is_zero_hop: bool
    basis: PathBasis
    nodes: list[PathAssetRef]  # entry point first, target last
    steps: list[PathStepRead]  # in path order; empty for a zero-hop path
    entry_evidence: list[EntryEvidenceRef]
    interpretation: str
    limitations: list[str]


class ExposurePathLimits(BaseModel):
    max_hops: int
    max_targets: int
    max_paths: int
    max_nodes: int


class PathTruncation(BaseModel):
    limit: str
    detail: str


class ExposurePathsResponse(BaseModel):
    disclaimer: str
    organization_id: uuid.UUID
    assessed_at: datetime
    freshness_window_seconds: int
    limits: ExposurePathLimits
    path_count: int
    eligible_target_count: int
    examined_target_count: int
    examined_node_count: int
    evaluated_relationship_count: int
    entry_point_count: int
    truncated: bool
    truncation_reasons: list[PathTruncation]
    limitations: list[str]
    paths: list[ExposurePathRead]
