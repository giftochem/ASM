from sqlalchemy.orm import Session

from app.core.enums import AssetSource, ChangeType
from app.models.asset import Asset
from app.models.observation import Observation


def record_observation(
    db: Session,
    asset: Asset,
    change_type: ChangeType,
    *,
    field_name: str | None = None,
    previous_value: str | None = None,
    current_value: str | None = None,
    source: AssetSource = AssetSource.manual,
    confidence: float = 1.0,
) -> Observation:
    """Adds an Observation row without committing — same convention as
    audit_service.log_action: the caller commits as part of the same
    transaction as the change being recorded, so an observation never
    survives a rolled-back write (or vice versa).
    """
    observation = Observation(
        asset_id=asset.id,
        change_type=change_type,
        field_name=field_name,
        previous_value=previous_value,
        current_value=current_value,
        source=source,
        confidence=confidence,
    )
    db.add(observation)
    db.flush()
    return observation
