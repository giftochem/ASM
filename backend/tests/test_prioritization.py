"""Unit/service-level tests for prioritization_service -- the
explainable, on-demand asset prioritization built in Step 9.10. These
call the service directly (not through HTTP) to assert on the SPECIFIC
reasons/dimensions produced, not just the final priority label.
"""

import uuid
from datetime import datetime, timedelta, timezone

import dns.resolver
import httpx
import pytest
from sqlalchemy import event

from app.core.enums import AssetCriticality, AssetEnvironment, AssetSource, ChangeType, LifecycleStatus
from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.models.observation import Observation
from app.services import prioritization_service
from tests.conftest import test_engine


def _create_and_authorize_asset(client, headers, value, asset_type="domain"):
    resp = client.post("/assets", json={"asset_type": asset_type, "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    asset = resp.json()
    confirm = client.post(
        f"/assets/{asset['id']}/confirm-authorization", json={"authorization_confirmed": True}, headers=headers
    )
    assert confirm.status_code == 200, confirm.text
    return asset


def _add_observation(db, asset_id, change_type, *, field_name=None, previous_value=None, current_value=None, confidence=1.0, observed_at=None):
    obs = Observation(
        asset_id=asset_id,
        change_type=change_type,
        field_name=field_name,
        previous_value=previous_value,
        current_value=current_value,
        source=AssetSource.discovery,
        confidence=confidence,
        observed_at=observed_at or datetime.now(timezone.utc),
    )
    db.add(obs)
    db.commit()
    return obs


def _get_org_id(db, email):
    from app.models.user import User

    return db.query(User).filter(User.email == email).first().organization_id


def test_deterministic_identical_input_produces_identical_output(client, register_user, db):
    headers = register_user(email="prio-det@example.com")
    _create_and_authorize_asset(client, headers, "prio-det.example.com")
    org_id = _get_org_id(db, "prio-det@example.com")

    first = prioritization_service.prioritize_assets(db, org_id)
    second = prioritization_service.prioritize_assets(db, org_id)

    assert [(r.asset.id, r.priority, r.confidence_label) for r in first] == [
        (r.asset.id, r.priority, r.confidence_label) for r in second
    ]
    assert [r.dimensions for r in first] == [r.dimensions for r in second]


def test_missing_criticality_and_environment_are_unknown_not_low(client, register_user, db):
    headers = register_user(email="prio-missing@example.com")
    _create_and_authorize_asset(client, headers, "prio-missing.example.com")
    org_id = _get_org_id(db, "prio-missing@example.com")

    results = prioritization_service.prioritize_assets(db, org_id)
    result = next(r for r in results if r.asset.value == "prio-missing.example.com")

    assert result.dimensions.business_criticality == "unknown"
    assert any(r.signal == "unknown_business_context" for r in result.reasons)
    assert not any(r.signal == "asset_criticality" for r in result.reasons)


def test_missing_owner_does_not_change_priority_or_reasons(client, register_user, db):
    """owner is descriptive context, not a scored signal in this model
    -- its presence/absence must not itself move the priority."""
    headers = register_user(email="prio-owner@example.com")
    asset_resp = _create_and_authorize_asset(client, headers, "prio-owner.example.com")
    org_id = _get_org_id(db, "prio-owner@example.com")

    before = prioritization_service.get_asset_priority(db, org_id, uuid.UUID(asset_resp["id"]))

    asset = db.get(Asset, uuid.UUID(asset_resp["id"]))
    asset.owner = "someone@example.com"
    db.commit()

    after = prioritization_service.get_asset_priority(db, org_id, uuid.UUID(asset_resp["id"]))
    assert before.priority == after.priority
    assert [r.signal for r in before.reasons] == [r.signal for r in after.reasons]


def test_missing_business_context_lowers_confidence(client, register_user, db):
    headers = register_user(email="prio-confidence-ctx@example.com")
    a = _create_and_authorize_asset(client, headers, "prio-ctx-a.example.com")
    b = _create_and_authorize_asset(client, headers, "prio-ctx-b.example.com")
    org_id = _get_org_id(db, "prio-confidence-ctx@example.com")

    b_asset = db.get(Asset, uuid.UUID(b["id"]))
    b_asset.criticality = AssetCriticality.high
    b_asset.confidence = 1.0
    db.commit()
    a_asset = db.get(Asset, uuid.UUID(a["id"]))
    a_asset.confidence = 1.0
    db.commit()

    result_a = prioritization_service.get_asset_priority(db, org_id, uuid.UUID(a["id"]))  # no criticality/environment
    result_b = prioritization_service.get_asset_priority(db, org_id, uuid.UUID(b["id"]))  # has criticality

    order = {"low": 0, "medium": 1, "high": 2}
    assert order[result_a.confidence_label] <= order[result_b.confidence_label]


def test_high_criticality_production_asset_with_change_is_critical(client, register_user, db):
    headers = register_user(email="prio-critical@example.com")
    asset_resp = _create_and_authorize_asset(client, headers, "prio-critical.example.com")
    org_id = _get_org_id(db, "prio-critical@example.com")
    asset_id = uuid.UUID(asset_resp["id"])

    asset = db.get(Asset, asset_id)
    asset.criticality = AssetCriticality.critical
    asset.environment = AssetEnvironment.production
    db.commit()

    _add_observation(
        db, asset_id, ChangeType.http_changed, field_name="http:https",
        previous_value='{"status_code": 200}', current_value='{"status_code": 503}',
    )

    result = prioritization_service.get_asset_priority(db, org_id, asset_id)
    assert result.priority == prioritization_service.PriorityLevel.critical
    assert any(r.signal == "http_changed" for r in result.reasons)
    assert any(r.signal == "asset_criticality" for r in result.reasons)


def test_non_exposed_asset_type_does_not_reach_critical_even_with_high_criticality(client, register_user, db):
    """Conflicting signals: high business criticality alone, on an
    asset type this model doesn't treat as inherently exposed, must not
    alone produce the top category -- exposure still gates it.
    """
    headers = register_user(email="prio-conflict@example.com")
    asset_resp = _create_and_authorize_asset(client, headers, "AS64500", asset_type="asn")
    org_id = _get_org_id(db, "prio-conflict@example.com")
    asset_id = uuid.UUID(asset_resp["id"])

    asset = db.get(Asset, asset_id)
    asset.criticality = AssetCriticality.critical
    db.commit()

    result = prioritization_service.get_asset_priority(db, org_id, asset_id)
    assert result.priority != prioritization_service.PriorityLevel.critical
    assert result.dimensions.exposure == "none"


def test_internet_facing_asset_type_shows_exposure_signal(client, register_user, db):
    headers = register_user(email="prio-exposed-type@example.com")
    asset_resp = _create_and_authorize_asset(client, headers, "93.184.216.99", asset_type="ip_address")
    org_id = _get_org_id(db, "prio-exposed-type@example.com")

    result = prioritization_service.get_asset_priority(db, org_id, uuid.UUID(asset_resp["id"]))
    assert any(r.signal == "publicly_routable_ip" for r in result.reasons)
    assert result.dimensions.exposure in ("low", "moderate", "high")


def test_http_reachable_asset_shows_http_exposed_reason(client, register_user, db):
    headers = register_user(email="prio-http@example.com")
    asset_resp = _create_and_authorize_asset(client, headers, "prio-http.example.com")
    org_id = _get_org_id(db, "prio-http@example.com")
    asset_id = uuid.UUID(asset_resp["id"])

    _add_observation(
        db, asset_id, ChangeType.http_observed, field_name="http:https",
        current_value='{"status_code": 200, "server": "nginx"}',
    )

    result = prioritization_service.get_asset_priority(db, org_id, asset_id)
    assert any(r.signal == "http_exposed" for r in result.reasons)
    assert result.dimensions.exposure in ("moderate", "high")


def test_newly_discovered_asset_is_flagged(client, register_user, db):
    headers = register_user(email="prio-new@example.com")
    asset_resp = _create_and_authorize_asset(client, headers, "prio-new.example.com")
    org_id = _get_org_id(db, "prio-new@example.com")
    asset_id = uuid.UUID(asset_resp["id"])

    asset = db.get(Asset, asset_id)
    asset.status = LifecycleStatus.first_seen
    asset.first_seen = datetime.now(timezone.utc) - timedelta(hours=2)
    db.commit()

    result = prioritization_service.get_asset_priority(db, org_id, asset_id)
    assert any(r.signal == "newly_discovered" for r in result.reasons)


def test_old_first_seen_asset_not_flagged_as_newly_discovered(client, register_user, db):
    headers = register_user(email="prio-old@example.com")
    asset_resp = _create_and_authorize_asset(client, headers, "prio-old.example.com")
    org_id = _get_org_id(db, "prio-old@example.com")
    asset_id = uuid.UUID(asset_resp["id"])

    asset = db.get(Asset, asset_id)
    asset.status = LifecycleStatus.first_seen
    asset.first_seen = datetime.now(timezone.utc) - timedelta(days=30)
    db.commit()

    result = prioritization_service.get_asset_priority(db, org_id, asset_id)
    assert not any(r.signal == "newly_discovered" for r in result.reasons)


def test_certificate_change_detected(client, register_user, db):
    headers = register_user(email="prio-cert@example.com")
    asset_resp = _create_and_authorize_asset(client, headers, "prio-cert.example.com")
    org_id = _get_org_id(db, "prio-cert@example.com")
    asset_id = uuid.UUID(asset_resp["id"])

    _add_observation(db, asset_id, ChangeType.certificate_observed, field_name="prio-cert.example.com:443", current_value="{}")
    _add_observation(
        db, asset_id, ChangeType.certificate_changed, field_name="prio-cert.example.com:443",
        previous_value="old-fingerprint", current_value="new-fingerprint",
    )

    result = prioritization_service.get_asset_priority(db, org_id, asset_id)
    assert any(r.signal == "certificate_changed" for r in result.reasons)
    assert result.dimensions.change_recency == "high"


def test_http_change_detected(client, register_user, db):
    headers = register_user(email="prio-httpchange@example.com")
    asset_resp = _create_and_authorize_asset(client, headers, "prio-httpchange.example.com")
    org_id = _get_org_id(db, "prio-httpchange@example.com")
    asset_id = uuid.UUID(asset_resp["id"])

    _add_observation(db, asset_id, ChangeType.http_observed, field_name="http:https", current_value='{"status_code": 200}')
    _add_observation(
        db, asset_id, ChangeType.http_changed, field_name="http:https",
        previous_value='{"status_code": 200}', current_value='{"status_code": 500}',
    )

    result = prioritization_service.get_asset_priority(db, org_id, asset_id)
    assert any(r.signal == "http_changed" for r in result.reasons)


def test_dns_change_detected_via_evidence_comparison(client, register_user, db):
    headers = register_user(email="prio-dns@example.com")
    asset_resp = _create_and_authorize_asset(client, headers, "prio-dns.example.com")
    org_id = _get_org_id(db, "prio-dns@example.com")
    asset_id = uuid.UUID(asset_resp["id"])

    _add_observation(
        db, asset_id, ChangeType.dns_records_observed, field_name="dns_metadata",
        current_value='{"txt_records": ["v=spf1 include:old.example.com"]}',
        observed_at=datetime.now(timezone.utc) - timedelta(hours=2),
    )
    _add_observation(
        db, asset_id, ChangeType.dns_records_observed, field_name="dns_metadata",
        current_value='{"txt_records": ["v=spf1 include:new.example.com"]}',
        observed_at=datetime.now(timezone.utc) - timedelta(minutes=5),
    )

    result = prioritization_service.get_asset_priority(db, org_id, asset_id)
    assert any(r.signal == "dns_changed" for r in result.reasons)


def test_identical_consecutive_dns_observations_not_flagged_as_changed(client, register_user, db):
    headers = register_user(email="prio-dns-same@example.com")
    asset_resp = _create_and_authorize_asset(client, headers, "prio-dns-same.example.com")
    org_id = _get_org_id(db, "prio-dns-same@example.com")
    asset_id = uuid.UUID(asset_resp["id"])

    identical_value = '{"txt_records": ["v=spf1 include:example.com"]}'
    _add_observation(
        db, asset_id, ChangeType.dns_records_observed, field_name="dns_metadata", current_value=identical_value,
        observed_at=datetime.now(timezone.utc) - timedelta(hours=2),
    )
    _add_observation(
        db, asset_id, ChangeType.dns_records_observed, field_name="dns_metadata", current_value=identical_value,
        observed_at=datetime.now(timezone.utc) - timedelta(minutes=5),
    )

    result = prioritization_service.get_asset_priority(db, org_id, asset_id)
    assert not any(r.signal == "dns_changed" for r in result.reasons)


def test_infrastructure_change_detected(client, register_user, db):
    headers = register_user(email="prio-infra@example.com")
    asset_resp = _create_and_authorize_asset(client, headers, "93.184.216.100", asset_type="ip_address")
    org_id = _get_org_id(db, "prio-infra@example.com")
    asset_id = uuid.UUID(asset_resp["id"])

    _add_observation(db, asset_id, ChangeType.infrastructure_observed, field_name="infrastructure", current_value='{"provider": "Amazon Web Services"}')
    _add_observation(
        db, asset_id, ChangeType.infrastructure_changed, field_name="infrastructure",
        previous_value='{"provider": "Amazon Web Services"}', current_value='{"provider": "Microsoft Azure"}',
    )

    result = prioritization_service.get_asset_priority(db, org_id, asset_id)
    assert any(r.signal == "infrastructure_changed" for r in result.reasons)


def test_high_connectivity_asset(client, register_user, db):
    headers = register_user(email="prio-connect@example.com")
    hub = _create_and_authorize_asset(client, headers, "prio-hub.example.com")
    org_id = _get_org_id(db, "prio-connect@example.com")

    for i in range(6):
        leaf = _create_and_authorize_asset(client, headers, f"prio-leaf-{i}.example.com")
        client.post(
            f"/assets/{hub['id']}/relationships",
            json={"target_asset_id": leaf["id"], "relationship_type": "related_to"},
            headers=headers,
        )

    result = prioritization_service.get_asset_priority(db, org_id, uuid.UUID(hub["id"]))
    assert result.dimensions.connectivity_relevance in ("moderate", "high")
    assert any(r.signal == "connectivity" and r.evidence["relationship_count"] == 6 for r in result.reasons)


def test_connection_to_critical_asset_flagged(client, register_user, db):
    headers = register_user(email="prio-critneighbor@example.com")
    seed = _create_and_authorize_asset(client, headers, "prio-critneighbor-seed.example.com")
    critical_neighbor = _create_and_authorize_asset(client, headers, "prio-critneighbor-target.example.com")
    org_id = _get_org_id(db, "prio-critneighbor@example.com")

    neighbor_asset = db.get(Asset, uuid.UUID(critical_neighbor["id"]))
    neighbor_asset.criticality = AssetCriticality.critical
    db.commit()

    client.post(
        f"/assets/{seed['id']}/relationships",
        json={"target_asset_id": critical_neighbor["id"], "relationship_type": "related_to"},
        headers=headers,
    )

    result = prioritization_service.get_asset_priority(db, org_id, uuid.UUID(seed["id"]))
    assert any(r.signal == "connects_to_critical_asset" for r in result.reasons)
    assert result.dimensions.connectivity_relevance == "high"


def test_isolated_asset_flagged(client, register_user, db):
    headers = register_user(email="prio-isolated@example.com")
    asset_resp = _create_and_authorize_asset(client, headers, "prio-isolated.example.com")
    org_id = _get_org_id(db, "prio-isolated@example.com")

    result = prioritization_service.get_asset_priority(db, org_id, uuid.UUID(asset_resp["id"]))
    assert result.dimensions.connectivity_relevance == "none"
    assert any(r.signal == "isolated_asset" for r in result.reasons)


def test_low_confidence_evidence_reflected_honestly(client, register_user, db):
    headers = register_user(email="prio-lowconf@example.com")
    asset_resp = _create_and_authorize_asset(client, headers, "prio-lowconf.example.com")
    org_id = _get_org_id(db, "prio-lowconf@example.com")
    asset_id = uuid.UUID(asset_resp["id"])

    _add_observation(
        db, asset_id, ChangeType.http_changed, field_name="http:https",
        previous_value="{}", current_value='{"status_code": 500}', confidence=0.3,
    )

    result = prioritization_service.get_asset_priority(db, org_id, asset_id)
    assert result.confidence_label == "low"
    assert result.confidence_value <= 0.3


def test_disappeared_asset_never_exceeds_informational(client, register_user, db):
    headers = register_user(email="prio-disappeared@example.com")
    asset_resp = _create_and_authorize_asset(client, headers, "prio-disappeared.example.com")
    org_id = _get_org_id(db, "prio-disappeared@example.com")
    asset_id = uuid.UUID(asset_resp["id"])

    asset = db.get(Asset, asset_id)
    asset.status = LifecycleStatus.disappeared
    asset.criticality = AssetCriticality.critical  # even with critical business value
    db.commit()

    result = prioritization_service.get_asset_priority(db, org_id, asset_id)
    assert result.priority == prioritization_service.PriorityLevel.informational


def test_reasons_contain_specific_descriptions_not_generic_labels(client, register_user, db):
    headers = register_user(email="prio-specific@example.com")
    asset_resp = _create_and_authorize_asset(client, headers, "prio-specific.example.com")
    org_id = _get_org_id(db, "prio-specific@example.com")
    asset_id = uuid.UUID(asset_resp["id"])

    asset = db.get(Asset, asset_id)
    asset.criticality = AssetCriticality.high
    asset.environment = AssetEnvironment.production
    db.commit()

    result = prioritization_service.get_asset_priority(db, org_id, asset_id)
    descriptions = [r.description for r in result.reasons]
    assert any("production" in d.lower() for d in descriptions)
    assert any("high" in d.lower() or "criticality" in d.lower() for d in descriptions)
    assert all(len(d) > 10 for d in descriptions)  # not just a bare code/label


def test_no_active_network_calls_during_evaluation(client, register_user, db, monkeypatch):
    def _fail(*args, **kwargs):
        raise AssertionError("prioritization must never make a network call")

    monkeypatch.setattr(httpx, "get", _fail)
    monkeypatch.setattr(httpx.Client, "stream", _fail)
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fail)

    headers = register_user(email="prio-nonetwork@example.com")
    _create_and_authorize_asset(client, headers, "prio-nonetwork.example.com")
    org_id = _get_org_id(db, "prio-nonetwork@example.com")

    results = prioritization_service.prioritize_assets(db, org_id)
    assert len(results) == 1  # completed without any network call being attempted


def test_no_secrets_in_reasons_or_evidence(client, register_user, db):
    headers = register_user(email="prio-secrets@example.com")
    asset_resp = _create_and_authorize_asset(client, headers, "prio-secrets.example.com")
    org_id = _get_org_id(db, "prio-secrets@example.com")
    asset_id = uuid.UUID(asset_resp["id"])

    _add_observation(
        db, asset_id, ChangeType.http_observed, field_name="http:https",
        current_value='{"status_code": 200, "cookie_security_flags": [{"secure": true, "httponly": true, "samesite": "Strict"}]}',
    )

    result = prioritization_service.get_asset_priority(db, org_id, asset_id)
    serialized = str(result.reasons)
    assert "session" not in serialized.lower()
    assert "authorization:" not in serialized.lower()
    assert "bearer" not in serialized.lower()


def test_query_count_does_not_scale_linearly_with_asset_count(client, register_user, db):
    """Step 9.10.13: prioritize_assets must batch its context queries
    (asset list, observations, relationships, neighbor criticalities,
    certificates) rather than issuing them per asset. Proven by counting
    actual SQL statements for two different asset-count sizes and
    confirming the query count doesn't grow proportionally.
    """
    headers = register_user(email="prio-perf@example.com")
    org_id = _get_org_id(db, "prio-perf@example.com")

    def _count_queries(n_assets: int) -> int:
        for i in range(n_assets):
            _create_and_authorize_asset(client, headers, f"prio-perf-{n_assets}-{i}.example.com")

        counts = {"n": 0}

        def _on_execute(*args, **kwargs):
            counts["n"] += 1

        event.listen(test_engine, "before_cursor_execute", _on_execute)
        try:
            prioritization_service.prioritize_assets(db, org_id, limit=200)
        finally:
            event.remove(test_engine, "before_cursor_execute", _on_execute)
        return counts["n"]

    small_batch_queries = _count_queries(3)
    large_batch_queries = _count_queries(15)

    # A per-asset (N+1) implementation would show large_batch_queries
    # growing by roughly (15-3) * (queries per asset) -- a batched
    # implementation's query count is independent of how many assets
    # were added between the two calls (the fixed set of batched
    # queries just scan more rows, not run more times).
    assert large_batch_queries <= small_batch_queries + 2
