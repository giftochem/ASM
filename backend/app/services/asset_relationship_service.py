import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.enums import AssetSource, ChangeType, LifecycleStatus, RelationshipType
from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.services import observation_service


def create_relationship(
    db: Session,
    *,
    source_asset: Asset,
    target_asset: Asset,
    relationship_type: RelationshipType,
    confidence: float = 1.0,
    source: AssetSource = AssetSource.manual,
    notes: str | None = None,
) -> AssetRelationship:
    """Creates a relationship, or refreshes (dedup-or-refresh, mirroring
    Service/Certificate's upsert-shaped uniqueness from Step 8.1) if one
    already exists for this (source, target, relationship_type) triple —
    re-observing an existing relationship updates last_seen/confidence
    and revives it from stale/disappeared back to active, rather than
    creating a duplicate row.

    The route layer resolves both assets via the existing
    _get_org_asset_or_404 helper, which already 404s a cross-org target —
    this check is defense in depth for any future caller (e.g. a
    discovery task) that doesn't go through that same lookup.
    """
    if source_asset.organization_id != target_asset.organization_id:
        raise ValueError("source_asset and target_asset must belong to the same organization")

    existing = (
        db.query(AssetRelationship)
        .filter(
            AssetRelationship.source_asset_id == source_asset.id,
            AssetRelationship.target_asset_id == target_asset.id,
            AssetRelationship.relationship_type == relationship_type,
        )
        .first()
    )
    now = datetime.now(timezone.utc)

    if existing is not None:
        # Step 9.9.3: "a relationship that returns" -- an Observation is
        # written ONLY when this re-confirmation actually revives the
        # relationship from stale/disappeared back to active. A plain
        # re-confirmation of an already-active relationship (the common
        # case on every re-discovery run) writes nothing, matching the
        # same "don't record a meaningless duplicate" principle Step
        # 9.9.2 applies to assets and Steps 9.5-9.7 already apply to
        # their own observation types. Confidence is deliberately not
        # part of this comparison either, for the same reason it's
        # excluded from asset-state comparison (see
        # discovery_normalization_service._MEANINGFUL_ASSET_FIELDS).
        was_disappeared_or_stale = existing.status in (LifecycleStatus.stale, LifecycleStatus.disappeared)
        existing.last_seen = now
        existing.confidence = confidence
        existing.status = LifecycleStatus.active
        if notes is not None:
            existing.notes = notes
        db.flush()

        if was_disappeared_or_stale:
            observation_service.record_observation(
                db,
                source_asset,
                ChangeType.relationship_updated,
                field_name=relationship_type.value,
                previous_value=json.dumps({"status": "disappeared_or_stale", "target_asset_id": str(target_asset.id)}),
                current_value=json.dumps({"status": "active", "target_asset_id": str(target_asset.id)}),
                source=source,
                confidence=confidence,
            )
        return existing

    relationship = AssetRelationship(
        source_asset_id=source_asset.id,
        target_asset_id=target_asset.id,
        relationship_type=relationship_type,
        confidence=confidence,
        source=source,
        first_seen=now,
        last_seen=now,
        notes=notes,
    )
    db.add(relationship)
    db.flush()

    observation_service.record_observation(
        db,
        source_asset,
        ChangeType.relationship_created,
        field_name=relationship_type.value,
        current_value=str(target_asset.id),
        source=source,
        confidence=confidence,
    )
    return relationship


def mark_relationship_disappeared(db: Session, relationship: AssetRelationship) -> AssetRelationship:
    """Soft-removes a relationship (status=disappeared) rather than
    deleting the row — preserves history, matching the lifecycle
    philosophy the rest of Step 8 already follows.
    """
    relationship.status = LifecycleStatus.disappeared
    db.flush()

    observation_service.record_observation(
        db,
        relationship.source_asset,
        ChangeType.relationship_removed,
        field_name=relationship.relationship_type.value,
        previous_value=str(relationship.target_asset_id),
        source=relationship.source,
    )
    return relationship
