import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.core.enums import RiskSeverityBand, ScanStatus
from app.schemas.finding import FindingRead


class ScanCreate(BaseModel):
    asset_id: uuid.UUID
    # None => run every module that supports the target asset_type.
    # Explicit list lets a caller run a subset; validated against the
    # module registry in scan_service, not here, to avoid schemas
    # importing the scanners package.
    modules: list[str] | None = None


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    initiated_by: uuid.UUID
    status: ScanStatus
    modules_requested: list[str]
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    risk_score: float | None
    risk_severity_band: RiskSeverityBand | None
    created_at: datetime


class ScanResult(ScanRead):
    """Returned by POST/GET /scans — the scan's current state plus any
    findings produced so far. Under real async execution the scan may
    still be `queued`/`running` with empty findings at response time;
    poll GET /scans/{id} until status is completed/failed/cancelled.
    """

    findings: list[FindingRead] = []
