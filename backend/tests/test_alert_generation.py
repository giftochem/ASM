"""Step 9.12 alert generation: per-type classification, non-creation for
ordinary/unchanged observations, and the alert-generation-safety
guarantees (failed runs, rejected candidates, zero-candidate suspicious
runs never produce alerts). Uses the same low-level pattern
test_change_detection.py/test_disappearance_detection.py already
established -- calling discovery_normalization_service's normalization
functions directly with synthetic provider dataclasses -- for precise,
fast, deterministic control over exactly which Observation gets
written, then exercises alert_service.evaluate_run_for_alerts directly
on top.
"""

import uuid
from datetime import datetime, timedelta, timezone

from app.core.enums import (
    AlertType,
    AssetCriticality,
    AssetEnvironment,
    AssetType,
    ChangeType,
    DiscoveryResultOutcome,
    DiscoveryRunStatus,
    RelationshipType,
)
from app.discovery.base import (
    CertificateObservation,
    DiscoveryCandidate,
    HttpObservation,
    InfrastructureProviderData,
    NetworkObservation,
)
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.user import User
from app.services import (
    alert_service,
    discovery_normalization_service,
    discovery_schedule_service,
    discovery_scheduler_executor,
    discovery_service,
)


def _create_and_authorize_asset(client, headers, value, asset_type="domain"):
    resp = client.post("/assets", json={"asset_type": asset_type, "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    asset = resp.json()
    confirm = client.post(
        f"/assets/{asset['id']}/confirm-authorization", json={"authorization_confirmed": True}, headers=headers
    )
    assert confirm.status_code == 200, confirm.text
    return asset


def _new_run(db, seed_asset, user):
    """discovery_service.create_run leaves started_at unset (only
    execute_run's real code path sets it) -- evaluate_run_for_alerts
    filters Observations by `observed_at >= run.started_at`, so every
    test run needs a real started_at stamped BEFORE any Observation it
    should see is written.
    """
    run = discovery_service.create_run(db, seed_asset, "stub", user)
    run.started_at = datetime.now(timezone.utc)
    db.commit()
    return run


def _seed_and_run(db, client, headers, email, value, asset_type="domain"):
    asset = _create_and_authorize_asset(client, headers, value, asset_type=asset_type)
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    user = db.query(User).filter(User.email == email).first()
    run = _new_run(db, seed_asset, user)
    return seed_asset, run, user


def _mark_completed(db, run):
    run.status = DiscoveryRunStatus.completed
    run.completed_at = datetime.now(timezone.utc)
    db.commit()


# --- new_externally_exposed_asset -------------------------------------------


def test_new_exposed_asset_creates_alert(client, register_user, db):
    email = "gen-new-exposed@example.com"
    headers = register_user(email=email)
    seed_asset, run, _ = _seed_and_run(db, client, headers, email, "gen-new-exposed.example.com")

    candidate = DiscoveryCandidate(asset_type=AssetType.subdomain, value="www.gen-new-exposed.example.com", confidence=0.9)
    discovery_normalization_service.normalize_candidate(db, run, seed_asset, candidate)
    db.commit()
    _mark_completed(db, run)

    new_alerts = alert_service.evaluate_run_for_alerts(db, run, seed_asset)
    db.commit()

    matching = [a for a in new_alerts if a.alert_type.value == "new_externally_exposed_asset"]
    assert len(matching) == 1
    assert matching[0].asset_id is not None
    resulting_asset = db.get(Asset, matching[0].asset_id)
    assert resulting_asset.value == "www.gen-new-exposed.example.com"


def test_non_exposed_asset_type_creates_no_new_asset_alert(client, register_user, db):
    email = "gen-non-exposed@example.com"
    headers = register_user(email=email)
    seed_asset, run, _ = _seed_and_run(db, client, headers, email, "gen-non-exposed.example.com")

    # `asn` is not in prioritization_service.INHERENTLY_EXPOSED_TYPES.
    candidate = DiscoveryCandidate(asset_type=AssetType.asn, value="AS64500", confidence=0.9)
    discovery_normalization_service.normalize_candidate(db, run, seed_asset, candidate)
    db.commit()
    _mark_completed(db, run)

    new_alerts = alert_service.evaluate_run_for_alerts(db, run, seed_asset)
    assert [a for a in new_alerts if a.alert_type.value == "new_externally_exposed_asset"] == []


def test_unchanged_reobservation_creates_no_alert(client, register_user, db):
    email = "gen-unchanged@example.com"
    headers = register_user(email=email)
    seed_asset, run, user = _seed_and_run(db, client, headers, email, "gen-unchanged.example.com")

    candidate = DiscoveryCandidate(asset_type=AssetType.subdomain, value="www.gen-unchanged.example.com", confidence=0.9)
    discovery_normalization_service.normalize_candidate(db, run, seed_asset, candidate)
    db.commit()
    _mark_completed(db, run)
    alert_service.evaluate_run_for_alerts(db, run, seed_asset)
    db.commit()

    run2 = _new_run(db, seed_asset, user)
    db.commit()
    result = discovery_normalization_service.normalize_candidate(db, run2, seed_asset, candidate)
    db.commit()
    assert result.outcome == DiscoveryResultOutcome.unchanged
    _mark_completed(db, run2)

    new_alerts = alert_service.evaluate_run_for_alerts(db, run2, seed_asset)
    assert new_alerts == []  # no Observation was written this run -- nothing to classify


# --- certificate_changed -----------------------------------------------------


def test_certificate_first_observation_creates_no_alert(client, register_user, db):
    email = "gen-cert-first@example.com"
    headers = register_user(email=email)
    seed_asset, run, _ = _seed_and_run(db, client, headers, email, "gen-cert-first.example.com")

    cert_obs = CertificateObservation(
        hostname="gen-cert-first.example.com", port=443, fingerprint_sha256="a" * 64, issuer="Let's Encrypt"
    )
    discovery_normalization_service.record_certificate_observation(db, run, seed_asset, cert_obs)
    db.commit()
    _mark_completed(db, run)

    new_alerts = alert_service.evaluate_run_for_alerts(db, run, seed_asset)
    assert [a for a in new_alerts if a.alert_type.value == "certificate_changed"] == []


def test_certificate_rotation_creates_alert(client, register_user, db):
    email = "gen-cert-rotate@example.com"
    headers = register_user(email=email)
    seed_asset, run, user = _seed_and_run(db, client, headers, email, "gen-cert-rotate.example.com")

    first = CertificateObservation(hostname="gen-cert-rotate.example.com", port=443, fingerprint_sha256="a" * 64)
    discovery_normalization_service.record_certificate_observation(db, run, seed_asset, first)
    db.commit()
    _mark_completed(db, run)
    alert_service.evaluate_run_for_alerts(db, run, seed_asset)
    db.commit()

    run2 = _new_run(db, seed_asset, user)
    db.commit()
    second = CertificateObservation(hostname="gen-cert-rotate.example.com", port=443, fingerprint_sha256="b" * 64)
    discovery_normalization_service.record_certificate_observation(db, run2, seed_asset, second)
    db.commit()
    _mark_completed(db, run2)

    new_alerts = alert_service.evaluate_run_for_alerts(db, run2, seed_asset)
    matching = [a for a in new_alerts if a.alert_type.value == "certificate_changed"]
    assert len(matching) == 1
    assert matching[0].asset_id == seed_asset.id


# --- http_security_posture_changed -------------------------------------------


def test_http_non_security_change_creates_no_alert(client, register_user, db):
    email = "gen-http-title@example.com"
    headers = register_user(email=email)
    seed_asset, run, user = _seed_and_run(db, client, headers, email, "gen-http-title.example.com")

    first = HttpObservation(
        scheme="https", requested_url="https://gen-http-title.example.com/", status_code=200, title="Home",
        security_headers={"strict-transport-security": True}, cookie_security_flags=[],
    )
    discovery_normalization_service.record_http_observation(db, run, seed_asset, first)
    db.commit()
    _mark_completed(db, run)
    alert_service.evaluate_run_for_alerts(db, run, seed_asset)
    db.commit()

    run2 = _new_run(db, seed_asset, user)
    db.commit()
    second = HttpObservation(
        scheme="https", requested_url="https://gen-http-title.example.com/", status_code=200, title="Welcome",
        security_headers={"strict-transport-security": True}, cookie_security_flags=[],
    )
    result = discovery_normalization_service.record_http_observation(db, run2, seed_asset, second)
    db.commit()
    assert result.outcome == DiscoveryResultOutcome.refreshed  # title differs, so it IS a meaningful change...
    _mark_completed(db, run2)

    new_alerts = alert_service.evaluate_run_for_alerts(db, run2, seed_asset)
    # ...but not a SECURITY-relevant one, so no http_security_posture_changed alert.
    assert [a for a in new_alerts if a.alert_type.value == "http_security_posture_changed"] == []


def test_http_security_header_change_creates_alert(client, register_user, db):
    email = "gen-http-sec@example.com"
    headers = register_user(email=email)
    seed_asset, run, user = _seed_and_run(db, client, headers, email, "gen-http-sec.example.com")

    first = HttpObservation(
        scheme="https", requested_url="https://gen-http-sec.example.com/", status_code=200,
        security_headers={"strict-transport-security": True, "content-security-policy": True}, cookie_security_flags=[],
    )
    discovery_normalization_service.record_http_observation(db, run, seed_asset, first)
    db.commit()
    _mark_completed(db, run)
    alert_service.evaluate_run_for_alerts(db, run, seed_asset)
    db.commit()

    run2 = _new_run(db, seed_asset, user)
    db.commit()
    second = HttpObservation(
        scheme="https", requested_url="https://gen-http-sec.example.com/", status_code=200,
        security_headers={"strict-transport-security": False, "content-security-policy": True}, cookie_security_flags=[],
    )
    discovery_normalization_service.record_http_observation(db, run2, seed_asset, second)
    db.commit()
    _mark_completed(db, run2)

    new_alerts = alert_service.evaluate_run_for_alerts(db, run2, seed_asset)
    matching = [a for a in new_alerts if a.alert_type.value == "http_security_posture_changed"]
    assert len(matching) == 1


# --- infrastructure_classification_changed -----------------------------------


def test_infrastructure_non_provider_change_creates_no_alert(client, register_user, db):
    email = "gen-infra-noise@example.com"
    headers = register_user(email=email)
    seed_asset, run, user = _seed_and_run(
        db, client, headers, email, "93.184.216.50", asset_type="ip_address"
    )

    first = InfrastructureProviderData(ip="93.184.216.50", asn="AS64500", asn_organization="Example ISP")
    discovery_normalization_service.record_infrastructure_observation(db, run, seed_asset, first)
    db.commit()
    _mark_completed(db, run)
    alert_service.evaluate_run_for_alerts(db, run, seed_asset)
    db.commit()

    run2 = _new_run(db, seed_asset, user)
    db.commit()
    # Same eventual classification (provider stays None/unknown for
    # both, since no AWS/GCP/etc. signature matches either ASN name),
    # only the PTR hostname differs -- not the `provider` field itself.
    second = InfrastructureProviderData(
        ip="93.184.216.50", asn="AS64500", asn_organization="Example ISP", ptr_hostname="host.example.net"
    )
    result = discovery_normalization_service.record_infrastructure_observation(db, run2, seed_asset, second)
    db.commit()
    assert result.outcome == DiscoveryResultOutcome.refreshed
    _mark_completed(db, run2)

    new_alerts = alert_service.evaluate_run_for_alerts(db, run2, seed_asset)
    assert [a for a in new_alerts if a.alert_type.value == "infrastructure_classification_changed"] == []


def test_infrastructure_provider_change_creates_alert(client, register_user, db):
    email = "gen-infra-provider@example.com"
    headers = register_user(email=email)
    seed_asset, run, user = _seed_and_run(
        db, client, headers, email, "93.184.216.60", asset_type="ip_address"
    )

    first = InfrastructureProviderData(ip="93.184.216.60", asn="AS64500", asn_organization="Example ISP")
    discovery_normalization_service.record_infrastructure_observation(db, run, seed_asset, first)
    db.commit()
    _mark_completed(db, run)
    alert_service.evaluate_run_for_alerts(db, run, seed_asset)
    db.commit()

    run2 = _new_run(db, seed_asset, user)
    db.commit()
    second = InfrastructureProviderData(ip="93.184.216.60", asn="AS16509", asn_organization="Amazon.com, Inc.")
    discovery_normalization_service.record_infrastructure_observation(db, run2, seed_asset, second)
    db.commit()
    _mark_completed(db, run2)

    new_alerts = alert_service.evaluate_run_for_alerts(db, run2, seed_asset)
    matching = [a for a in new_alerts if a.alert_type.value == "infrastructure_classification_changed"]
    assert len(matching) == 1


# --- dns_infrastructure_changed ------------------------------------------------


def test_dns_first_observation_creates_no_alert(client, register_user, db):
    email = "gen-dns-first@example.com"
    headers = register_user(email=email)
    seed_asset, run, _ = _seed_and_run(db, client, headers, email, "gen-dns-first.example.com")

    discovery_normalization_service.record_seed_evidence(db, run, seed_asset, {"A": ["203.0.113.1"]})
    db.commit()
    _mark_completed(db, run)

    new_alerts = alert_service.evaluate_run_for_alerts(db, run, seed_asset)
    assert [a for a in new_alerts if a.alert_type.value == "dns_infrastructure_changed"] == []


def test_dns_record_change_creates_alert(client, register_user, db):
    email = "gen-dns-change@example.com"
    headers = register_user(email=email)
    seed_asset, run, user = _seed_and_run(db, client, headers, email, "gen-dns-change.example.com")

    discovery_normalization_service.record_seed_evidence(db, run, seed_asset, {"A": ["203.0.113.1"]})
    db.commit()
    _mark_completed(db, run)
    alert_service.evaluate_run_for_alerts(db, run, seed_asset)
    db.commit()

    run2 = _new_run(db, seed_asset, user)
    db.commit()
    discovery_normalization_service.record_seed_evidence(db, run2, seed_asset, {"A": ["203.0.113.99"]})
    db.commit()
    _mark_completed(db, run2)

    new_alerts = alert_service.evaluate_run_for_alerts(db, run2, seed_asset)
    matching = [a for a in new_alerts if a.alert_type.value == "dns_infrastructure_changed"]
    assert len(matching) == 1


# --- important_asset_disappeared / reappeared / critical_asset_changed -------


def _disappear_candidate(db, client, headers, email, seed_value, candidate_value, criticality=None, environment=None):
    seed_asset, run1, user = _seed_and_run(db, client, headers, email, seed_value)
    keepalive = DiscoveryCandidate(
        asset_type=AssetType.subdomain, value=f"keepalive.{seed_value}",
        relationship_type=RelationshipType.belongs_to, confidence=0.9,
    )
    vanishing = DiscoveryCandidate(
        asset_type=AssetType.subdomain, value=candidate_value,
        relationship_type=RelationshipType.belongs_to, confidence=0.9,
    )
    discovery_normalization_service.normalize_candidate(db, run1, seed_asset, keepalive)
    result = discovery_normalization_service.normalize_candidate(db, run1, seed_asset, vanishing)
    db.commit()
    vanishing_asset = db.get(Asset, result.resulting_asset_id)
    if criticality is not None:
        vanishing_asset.criticality = criticality
    if environment is not None:
        vanishing_asset.environment = environment
    db.commit()
    _mark_completed(db, run1)

    run2 = _new_run(db, seed_asset, user)
    db.commit()
    discovery_normalization_service.normalize_candidate(db, run2, seed_asset, keepalive)  # vanishing NOT re-confirmed
    db.commit()
    _mark_completed(db, run2)
    disappeared_relationships = discovery_normalization_service.detect_and_mark_disappeared_candidates(
        db, run2, seed_asset, "stub"
    )
    db.commit()

    return seed_asset, run2, user, vanishing_asset, disappeared_relationships


def test_disappeared_asset_without_business_context_creates_no_alert(client, register_user, db):
    email = "gen-disappear-unknown@example.com"
    headers = register_user(email=email)
    seed_asset, run2, _, vanishing_asset, disappeared_relationships = _disappear_candidate(
        db, client, headers, email, "gen-disappear-unknown.example.com", "gone.gen-disappear-unknown.example.com"
    )
    assert vanishing_asset.criticality is None and vanishing_asset.environment is None
    assert len(disappeared_relationships) >= 1  # the disappearance itself genuinely happened

    new_alerts = alert_service.evaluate_run_for_alerts(
        db, run2, seed_asset, disappeared_relationships=disappeared_relationships
    )
    assert [a for a in new_alerts if a.alert_type.value == "important_asset_disappeared"] == []


def test_disappeared_critical_asset_creates_alert(client, register_user, db):
    email = "gen-disappear-critical@example.com"
    headers = register_user(email=email)
    seed_asset, run2, _, vanishing_asset, disappeared_relationships = _disappear_candidate(
        db, client, headers, email, "gen-disappear-critical.example.com", "gone.gen-disappear-critical.example.com",
        criticality=AssetCriticality.critical,
    )

    new_alerts = alert_service.evaluate_run_for_alerts(
        db, run2, seed_asset, disappeared_relationships=disappeared_relationships
    )
    matching = [a for a in new_alerts if a.alert_type.value == "important_asset_disappeared"]
    assert len(matching) == 1
    assert matching[0].priority.value == "critical"
    assert matching[0].asset_id == vanishing_asset.id


def test_reappeared_production_asset_creates_alert(client, register_user, db):
    email = "gen-reappear@example.com"
    headers = register_user(email=email)
    seed_asset, run2, user, vanishing_asset, disappeared_relationships = _disappear_candidate(
        db, client, headers, email, "gen-reappear.example.com", "gone.gen-reappear.example.com",
        environment=AssetEnvironment.production,
    )
    alert_service.evaluate_run_for_alerts(db, run2, seed_asset, disappeared_relationships=disappeared_relationships)
    db.commit()
    db.refresh(vanishing_asset)
    assert vanishing_asset.status.value == "disappeared"

    run3 = _new_run(db, seed_asset, user)
    db.commit()
    revived = DiscoveryCandidate(
        asset_type=AssetType.subdomain, value=vanishing_asset.value, confidence=0.9
    )
    discovery_normalization_service.normalize_candidate(db, run3, seed_asset, revived)
    db.commit()
    _mark_completed(db, run3)

    new_alerts = alert_service.evaluate_run_for_alerts(db, run3, seed_asset)
    matching = [a for a in new_alerts if a.alert_type.value == "important_asset_reappeared"]
    assert len(matching) == 1
    assert matching[0].priority.value == "high"  # production, not explicitly `critical` criticality


# --- high_priority_asset_detected --------------------------------------------


def test_high_priority_asset_detected(client, register_user, db):
    email = "gen-high-priority@example.com"
    headers = register_user(email=email)
    seed_asset, run, _ = _seed_and_run(db, client, headers, email, "gen-high-priority.example.com")
    seed_asset.criticality = AssetCriticality.critical
    seed_asset.environment = AssetEnvironment.production
    db.commit()

    http_obs = HttpObservation(
        scheme="https", requested_url="https://gen-high-priority.example.com/", status_code=200,
        security_headers={}, cookie_security_flags=[],
    )
    discovery_normalization_service.record_http_observation(db, run, seed_asset, http_obs)
    db.commit()
    _mark_completed(db, run)

    new_alerts = alert_service.evaluate_run_for_alerts(db, run, seed_asset)
    matching = [a for a in new_alerts if a.alert_type.value == "high_priority_asset_detected"]
    assert len(matching) == 1
    assert matching[0].asset_id == seed_asset.id
    assert matching[0].priority.value in ("high", "critical")


def test_low_priority_asset_creates_no_high_priority_alert(client, register_user, db):
    email = "gen-low-priority@example.com"
    headers = register_user(email=email)
    seed_asset, run, _ = _seed_and_run(db, client, headers, email, "gen-low-priority.example.com")

    candidate = DiscoveryCandidate(asset_type=AssetType.subdomain, value="www.gen-low-priority.example.com", confidence=0.9)
    discovery_normalization_service.normalize_candidate(db, run, seed_asset, candidate)
    db.commit()
    _mark_completed(db, run)

    new_alerts = alert_service.evaluate_run_for_alerts(db, run, seed_asset)
    assert [a for a in new_alerts if a.alert_type.value == "high_priority_asset_detected"] == []


# --- Alert Generation Safety (Step 9.12.14) -----------------------------------


def test_rejected_candidate_creates_no_alert(client, register_user, db):
    """An out-of-scope/invalid candidate never becomes an Observation --
    it becomes a `rejected` DiscoveryResult with no resulting_asset_id,
    which alert_service explicitly excludes when gathering touched
    assets. Confirmed here directly, not merely inherited by accident.
    """
    email = "gen-rejected@example.com"
    headers = register_user(email=email)
    seed_asset, run, _ = _seed_and_run(db, client, headers, email, "gen-rejected.example.com")

    # A private/reserved IP fails normalize_asset_value's scope/SSRF check.
    candidate = DiscoveryCandidate(asset_type=AssetType.ip_address, value="10.0.0.5", confidence=0.9)
    result = discovery_normalization_service.normalize_candidate(db, run, seed_asset, candidate)
    db.commit()
    assert result.outcome == DiscoveryResultOutcome.rejected
    assert result.resulting_asset_id is None
    _mark_completed(db, run)

    touched = alert_service._touched_asset_ids_this_run(db, run)
    assert touched == set()  # nothing beyond the caller's own {seed_asset.id} union

    new_alerts = alert_service.evaluate_run_for_alerts(db, run, seed_asset)
    assert new_alerts == []


def test_failed_run_creates_no_alerts(client, register_user, db, monkeypatch):
    """execute_run's failure path (_fail_run) returns before either
    disappearance detection or alert evaluation is ever reached --
    confirmed end-to-end here via the real discovery_service.execute_run,
    not just by inspecting evaluate_run_for_alerts in isolation.
    """
    from app.discovery.registry import DISCOVERY_PROVIDER_REGISTRY, get_provider

    email = "gen-failed-run@example.com"
    headers = register_user(email=email)
    asset = _create_and_authorize_asset(client, headers, "gen-failed-run.example.com")
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    user = db.query(User).filter(User.email == email).first()
    run = _new_run(db, seed_asset, user)

    def _raise(self, seed_value):
        raise RuntimeError("simulated provider crash")

    monkeypatch.setattr(type(DISCOVERY_PROVIDER_REGISTRY["stub"]), "discover", _raise)
    provider = get_provider("stub")
    discovery_service.execute_run(db, run, provider, seed_asset)
    db.refresh(run)
    assert run.status == DiscoveryRunStatus.failed

    assert db.query(Alert).filter(Alert.organization_id == seed_asset.organization_id).count() == 0


def test_zero_candidate_suspicious_run_creates_no_disappearance_alert(client, register_user, db):
    """Mirrors test_disappearance_detection.py's own zero-candidate
    guard test, but confirms the alert layer inherits the same safety:
    a completed run that reconfirms nothing when the previous run found
    something is treated as a suspicious silent partial failure, not
    genuine disappearance -- so no asset_status_changed Observation is
    ever written, so no important_asset_disappeared alert is possible.
    """
    email = "gen-zero-candidate@example.com"
    headers = register_user(email=email)
    seed_asset, run1, user = _seed_and_run(db, client, headers, email, "gen-zero-candidate.example.com")
    candidate = DiscoveryCandidate(asset_type=AssetType.subdomain, value="only.gen-zero-candidate.example.com", confidence=0.9)
    result = discovery_normalization_service.normalize_candidate(db, run1, seed_asset, candidate)
    db.commit()
    only_asset = db.get(Asset, result.resulting_asset_id)
    only_asset.criticality = AssetCriticality.critical
    db.commit()
    _mark_completed(db, run1)

    run2 = _new_run(db, seed_asset, user)
    db.commit()
    # Run2 reconfirms nothing at all (a silent partial failure look-alike).
    _mark_completed(db, run2)
    discovery_normalization_service.detect_and_mark_disappeared_candidates(db, run2, seed_asset, "stub")
    db.commit()
    db.refresh(only_asset)
    assert only_asset.status.value != "disappeared"

    new_alerts = alert_service.evaluate_run_for_alerts(db, run2, seed_asset)
    assert [a for a in new_alerts if a.alert_type.value == "important_asset_disappeared"] == []


# --- authorization_disabled (the one non-Observation-sourced type) -----------


def test_authorization_revoked_scheduled_execution_creates_authorization_disabled_alert(
    client, register_user, db, executor_uses_test_db
):
    email = "gen-auth-disabled@example.com"
    headers = register_user(email=email)
    asset = _create_and_authorize_asset(client, headers, "gen-auth-disabled.example.com")
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    user = db.query(User).filter(User.email == email).first()
    schedule = discovery_schedule_service.create_schedule(db, seed_asset, "stub", 6, user)

    runs = discovery_scheduler_executor.claim_due_schedules(db)
    assert len(runs) == 1
    seed_asset.authorization_confirmed = False
    db.commit()

    discovery_scheduler_executor.execute_scheduled_run(runs[0].id, schedule.id)
    db.commit()
    db.refresh(schedule)
    assert schedule.enabled is False  # the pre-existing Step 9.11 behavior, unmodified

    alerts = (
        db.query(Alert)
        .filter(Alert.organization_id == seed_asset.organization_id, Alert.alert_type == AlertType.authorization_disabled)
        .all()
    )
    assert len(alerts) == 1
    assert alerts[0].asset_id == seed_asset.id
    assert alerts[0].priority.value == "high"
    assert str(schedule.id) == alerts[0].evidence["schedule_id"]


def test_repeated_authorization_revocation_updates_same_alert_not_duplicates(
    client, register_user, db, executor_uses_test_db
):
    """Re-enabling and re-revoking the same schedule against the same
    asset must update the existing open alert (occurrence_count grows),
    not create a second one -- same dedup semantics as every other
    alert type, applied to the one type that isn't Observation-sourced.
    """
    email = "gen-auth-disabled-repeat@example.com"
    headers = register_user(email=email)
    asset = _create_and_authorize_asset(client, headers, "gen-auth-disabled-repeat.example.com")
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    user = db.query(User).filter(User.email == email).first()
    schedule = discovery_schedule_service.create_schedule(db, seed_asset, "stub", 6, user)

    for _ in range(2):
        seed_asset.authorization_confirmed = True
        schedule.enabled = True
        schedule.disabled_reason = None
        schedule.next_run_at = datetime.now(timezone.utc)
        db.commit()

        runs = discovery_scheduler_executor.claim_due_schedules(db)
        seed_asset.authorization_confirmed = False
        db.commit()
        discovery_scheduler_executor.execute_scheduled_run(runs[0].id, schedule.id)
        db.commit()

    alerts = (
        db.query(Alert)
        .filter(Alert.organization_id == seed_asset.organization_id, Alert.alert_type == AlertType.authorization_disabled)
        .all()
    )
    assert len(alerts) == 1
    assert alerts[0].occurrence_count == 2
