import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.core.enums import AssetType
from app.services.prioritization_service import PriorityLevel


class PriorityReason(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    signal: str
    impact: str
    description: str
    evidence: dict | None = None


class PriorityDimensions(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    exposure: str
    business_criticality: str
    change_recency: str
    connectivity_relevance: str
    evidence_confidence: str


class AssetPriority(BaseModel):
    """One asset's explainable priority. `confidence_value` is the raw
    underlying minimum numeric confidence this was derived from (never
    hidden behind the qualitative `confidence_label`) -- see
    prioritization_service's module docstring for why this is not a
    single opaque risk score.
    """

    asset_id: uuid.UUID
    asset_type: AssetType
    asset_value: str
    priority: PriorityLevel
    confidence_label: str
    confidence_value: float
    dimensions: PriorityDimensions
    reasons: list[PriorityReason]
    evaluated_at: datetime
