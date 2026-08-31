"""Tests for Step 9.9's change-detection improvements:
canonicalize_for_comparison (pure), asset-state unchanged/changed
detection (via the real normalize_candidate pipeline), and relationship
revival ("returns") detection.
"""

import uuid

from app.core.enums import AssetSource, AssetType, ChangeType, DiscoveryResultOutcome, LifecycleStatus, RelationshipType
from app.discovery.base import DiscoveryCandidate
from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.models.user import User
from app.services import asset_relationship_service, discovery_normalization_service, discovery_service


# --- canonicalize_for_comparison (pure, no I/O) -----------------------------


def test_dict_key_order_does_not_affect_equality():
    a = {"b": 1, "a": 2}
    b = {"a": 2, "b": 1}
    assert discovery_normalization_service.canonicalize_for_comparison(a) == discovery_normalization_service.canonicalize_for_comparison(b)


def test_list_of_primitives_reordered_compares_equal():
    a = [3, 1, 2]
    b = [1, 2, 3]
    assert discovery_normalization_service.canonicalize_for_comparison(a) == discovery_normalization_service.canonicalize_for_comparison(b)


def test_list_of_dicts_reordered_compares_equal():
    a = [{"signal": "asn", "detail": "x"}, {"signal": "ptr", "detail": "y"}]
    b = [{"signal": "ptr", "detail": "y"}, {"signal": "asn", "detail": "x"}]
    assert discovery_normalization_service.canonicalize_for_comparison(a) == discovery_normalization_service.canonicalize_for_comparison(b)


def test_nested_structures_canonicalized_recursively():
    a = {"evidence": [{"tags": [3, 1, 2]}, {"tags": ["b", "a"]}]}
    b = {"evidence": [{"tags": ["a", "b"]}, {"tags": [1, 2, 3]}]}
    assert discovery_normalization_service.canonicalize_for_comparison(a) == discovery_normalization_service.canonicalize_for_comparison(b)


def test_genuinely_different_values_still_compare_different():
    a = {"status_code": 200}
    b = {"status_code": 503}
    assert discovery_normalization_service.canonicalize_for_comparison(a) != discovery_normalization_service.canonicalize_for_comparison(b)


def test_genuinely_different_list_contents_still_compare_different():
    a = [{"signal": "asn", "detail": "x"}]
    b = [{"signal": "asn", "detail": "x"}, {"signal": "ptr", "detail": "y"}]
    assert discovery_normalization_service.canonicalize_for_comparison(a) != discovery_normalization_service.canonicalize_for_comparison(b)


def test_scalars_and_none_passed_through_unchanged():
    assert discovery_normalization_service.canonicalize_for_comparison("x") == "x"
    assert discovery_normalization_service.canonicalize_for_comparison(None) is None
    assert discovery_normalization_service.canonicalize_for_comparison(42) == 42


def test_empty_list_and_dict_handled():
    assert discovery_normalization_service.canonicalize_for_comparison([]) == []
    assert discovery_normalization_service.canonicalize_for_comparison({}) == {}


# --- Asset-state change detection (via the real normalize_candidate pipeline) ---


def _create_and_authorize_asset(client, headers, value, asset_type="domain"):
    resp = client.post("/assets", json={"asset_type": asset_type, "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    asset = resp.json()
    confirm = client.post(
        f"/assets/{asset['id']}/confirm-authorization", json={"authorization_confirmed": True}, headers=headers
    )
    assert confirm.status_code == 200, confirm.text
    return asset


def test_identical_redescovery_is_unchanged_and_writes_no_observation(client, register_user, db):
    headers = register_user(email="cd-unchanged@example.com")
    seed_resp = _create_and_authorize_asset(client, headers, "cd-unchanged-seed.example.com")
    seed_asset = db.get(Asset, uuid.UUID(seed_resp["id"]))
    admin_user = db.query(User).filter(User.email == "cd-unchanged@example.com").first()
    run = discovery_service.create_run(db, seed_asset, "stub", admin_user)
    db.commit()

    candidate = DiscoveryCandidate(asset_type=AssetType.subdomain, value="cd-unchanged-target.example.com", confidence=0.9)

    first = discovery_normalization_service.normalize_candidate(db, run, seed_asset, candidate)
    db.commit()
    assert first.outcome == DiscoveryResultOutcome.created

    before_count = db.query(Asset).filter(Asset.value == "cd-unchanged-target.example.com").first()
    obs_count_before = len(
        client.get(f"/assets/{before_count.id}/observations", headers=headers).json()
    )

    second = discovery_normalization_service.normalize_candidate(db, run, seed_asset, candidate)
    db.commit()
    assert second.outcome == DiscoveryResultOutcome.unchanged

    obs_count_after = len(client.get(f"/assets/{before_count.id}/observations", headers=headers).json())
    assert obs_count_after == obs_count_before  # no new Observation for a no-op re-confirmation


def test_status_revival_from_stale_produces_refreshed_with_correct_diff(client, register_user, db):
    headers = register_user(email="cd-revival@example.com")
    seed_resp = _create_and_authorize_asset(client, headers, "cd-revival-seed.example.com")
    seed_asset = db.get(Asset, uuid.UUID(seed_resp["id"]))
    admin_user = db.query(User).filter(User.email == "cd-revival@example.com").first()
    run = discovery_service.create_run(db, seed_asset, "stub", admin_user)
    db.commit()

    candidate = DiscoveryCandidate(asset_type=AssetType.subdomain, value="cd-revival-target.example.com", confidence=0.9)
    result = discovery_normalization_service.normalize_candidate(db, run, seed_asset, candidate)
    db.commit()
    target_asset = db.get(Asset, result.resulting_asset_id)

    # Simulate the asset having gone stale (no code path sets this
    # automatically yet -- Step 8.3 territory -- so it's set directly).
    target_asset.status = LifecycleStatus.stale
    db.commit()

    second = discovery_normalization_service.normalize_candidate(db, run, seed_asset, candidate)
    db.commit()

    assert second.outcome == DiscoveryResultOutcome.refreshed
    db.refresh(target_asset)
    assert target_asset.status == LifecycleStatus.active

    observations = client.get(f"/assets/{target_asset.id}/observations", headers=headers).json()
    status_changed = [o for o in observations if o["change_type"] == "asset_status_changed"]
    assert len(status_changed) == 1
    assert '"status": "stale"' in status_changed[0]["previous_value"]
    assert '"status": "active"' in status_changed[0]["current_value"]


def test_confidence_fluctuation_alone_does_not_count_as_changed(client, register_user, db):
    headers = register_user(email="cd-confidence@example.com")
    seed_resp = _create_and_authorize_asset(client, headers, "cd-confidence-seed.example.com")
    seed_asset = db.get(Asset, uuid.UUID(seed_resp["id"]))
    admin_user = db.query(User).filter(User.email == "cd-confidence@example.com").first()
    run = discovery_service.create_run(db, seed_asset, "stub", admin_user)
    db.commit()

    first_candidate = DiscoveryCandidate(asset_type=AssetType.subdomain, value="cd-confidence-target.example.com", confidence=0.9)
    discovery_normalization_service.normalize_candidate(db, run, seed_asset, first_candidate)
    db.commit()

    # Same value/type, deliberately DIFFERENT confidence.
    second_candidate = DiscoveryCandidate(asset_type=AssetType.subdomain, value="cd-confidence-target.example.com", confidence=0.4)
    second = discovery_normalization_service.normalize_candidate(db, run, seed_asset, second_candidate)
    db.commit()

    assert second.outcome == DiscoveryResultOutcome.unchanged


def test_tags_reordering_does_not_count_as_changed(client, register_user, db):
    headers = register_user(email="cd-tags@example.com")
    seed_resp = _create_and_authorize_asset(client, headers, "cd-tags-seed.example.com")
    seed_asset = db.get(Asset, uuid.UUID(seed_resp["id"]))
    admin_user = db.query(User).filter(User.email == "cd-tags@example.com").first()
    run = discovery_service.create_run(db, seed_asset, "stub", admin_user)
    db.commit()

    candidate = DiscoveryCandidate(asset_type=AssetType.subdomain, value="cd-tags-target.example.com", confidence=0.9)
    result = discovery_normalization_service.normalize_candidate(db, run, seed_asset, candidate)
    db.commit()
    target_asset = db.get(Asset, result.resulting_asset_id)

    target_asset.tags = ["b", "a"]
    db.commit()
    target_asset.tags = ["a", "b"]  # same set, different order than a hypothetical re-read would compare against
    db.commit()

    second = discovery_normalization_service.normalize_candidate(db, run, seed_asset, candidate)
    db.commit()
    assert second.outcome == DiscoveryResultOutcome.unchanged


# --- Relationship revival ("a relationship that returns") -------------------


def test_plain_relationship_reconfirmation_writes_no_observation(client, register_user, db):
    headers = register_user()
    a = _create_and_authorize_asset(client, headers, "rel-plain-a.example.com")
    b = _create_and_authorize_asset(client, headers, "rel-plain-b.example.com")
    client.post(
        f"/assets/{a['id']}/relationships",
        json={"target_asset_id": b["id"], "relationship_type": "related_to"},
        headers=headers,
    )

    obs_before = len(client.get(f"/assets/{a['id']}/observations", headers=headers).json())

    # Re-confirm the SAME, still-active relationship again.
    client.post(
        f"/assets/{a['id']}/relationships",
        json={"target_asset_id": b["id"], "relationship_type": "related_to"},
        headers=headers,
    )
    obs_after = len(client.get(f"/assets/{a['id']}/observations", headers=headers).json())
    assert obs_after == obs_before  # no new Observation for re-confirming an already-active relationship


def test_relationship_revival_from_disappeared_writes_relationship_updated(client, register_user, db):
    headers = register_user()
    a_resp = _create_and_authorize_asset(client, headers, "rel-revive-a.example.com")
    b_resp = _create_and_authorize_asset(client, headers, "rel-revive-b.example.com")
    a = db.get(Asset, uuid.UUID(a_resp["id"]))
    b = db.get(Asset, uuid.UUID(b_resp["id"]))

    relationship = asset_relationship_service.create_relationship(
        db, source_asset=a, target_asset=b, relationship_type=RelationshipType.related_to, confidence=1.0
    )
    db.commit()
    asset_relationship_service.mark_relationship_disappeared(db, relationship)
    db.commit()

    obs_before = client.get(f"/assets/{a_resp['id']}/observations", headers=headers).json()
    assert any(o["change_type"] == "relationship_removed" for o in obs_before)

    # Re-confirm it -- this should revive it AND record that it returned.
    asset_relationship_service.create_relationship(
        db, source_asset=a, target_asset=b, relationship_type=RelationshipType.related_to, confidence=1.0
    )
    db.commit()

    db.refresh(relationship)
    assert relationship.status == LifecycleStatus.active

    observations = client.get(f"/assets/{a_resp['id']}/observations", headers=headers).json()
    revived = [o for o in observations if o["change_type"] == "relationship_updated"]
    assert len(revived) == 1
