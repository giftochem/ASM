"""Step 9.12.5: alert deduplication/fingerprinting semantics --
identical event twice, two different meaningful changes on the same
asset, a resolved alert recurring, two different assets producing the
same alert type, and repeated scheduled runs not spamming duplicates.
"""

import uuid
from datetime import datetime, timezone

from app.core.enums import AlertStatus, AlertType, AssetType, DiscoveryRunStatus
from app.discovery.base import CertificateObservation, DiscoveryCandidate
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.user import User
from app.services import alert_service, discovery_normalization_service, discovery_schedule_service, discovery_scheduler_executor, discovery_service


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
    run = discovery_service.create_run(db, seed_asset, "stub", user)
    run.started_at = datetime.now(timezone.utc)
    db.commit()
    return run


def _mark_completed(db, run):
    run.status = DiscoveryRunStatus.completed
    run.completed_at = datetime.now(timezone.utc)
    db.commit()


def _seed(db, client, headers, email, value):
    asset = _create_and_authorize_asset(client, headers, value)
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    user = db.query(User).filter(User.email == email).first()
    return seed_asset, user


def _cert_alerts(alerts):
    """A certificate rotation on an inherently-exposed asset can
    legitimately ALSO trigger a co-occurring high_priority_asset_detected
    alert (Step 9.10's own, unmodified prioritization logic treats a
    recent security-relevant change plus exposure as enough to reach
    'high' even with no criticality/environment set -- unknown business
    context only downgrades confidence, never priority itself). These
    tests are about certificate_changed's own dedup identity, so they
    filter to that type specifically rather than asserting on the raw
    list, which would be coupled to prioritization's independent
    behavior.
    """
    return [a for a in alerts if a.alert_type.value == "certificate_changed"]


def test_identical_event_twice_updates_existing_alert_not_a_new_row(client, register_user, db):
    email = "dedup-identical@example.com"
    headers = register_user(email=email)
    seed_asset, user = _seed(db, client, headers, email, "dedup-identical.example.com")

    run1 = _new_run(db, seed_asset, user)
    cert = CertificateObservation(hostname="dedup-identical.example.com", port=443, fingerprint_sha256="a" * 64)
    discovery_normalization_service.record_certificate_observation(db, run1, seed_asset, cert)
    db.commit()
    _mark_completed(db, run1)
    run2 = _new_run(db, seed_asset, user)
    cert2 = CertificateObservation(hostname="dedup-identical.example.com", port=443, fingerprint_sha256="b" * 64)
    discovery_normalization_service.record_certificate_observation(db, run2, seed_asset, cert2)
    db.commit()
    _mark_completed(db, run2)
    new_cert_alerts_1 = _cert_alerts(alert_service.evaluate_run_for_alerts(db, run2, seed_asset))
    db.commit()
    assert len(new_cert_alerts_1) == 1
    alert_id = new_cert_alerts_1[0].id

    # A second, independent rotation -- same asset, same alert_type,
    # same identity (hostname:port slot) -- must update the SAME row.
    run3 = _new_run(db, seed_asset, user)
    cert3 = CertificateObservation(hostname="dedup-identical.example.com", port=443, fingerprint_sha256="c" * 64)
    discovery_normalization_service.record_certificate_observation(db, run3, seed_asset, cert3)
    db.commit()
    _mark_completed(db, run3)
    new_cert_alerts_2 = _cert_alerts(alert_service.evaluate_run_for_alerts(db, run3, seed_asset))
    db.commit()

    assert new_cert_alerts_2 == []  # not newly created -- it was a dedup update
    all_cert_alerts = (
        db.query(Alert)
        .filter(Alert.organization_id == seed_asset.organization_id, Alert.alert_type == AlertType.certificate_changed)
        .all()
    )
    assert len(all_cert_alerts) == 1
    assert all_cert_alerts[0].id == alert_id
    assert all_cert_alerts[0].occurrence_count == 2


def test_two_different_meaningful_changes_on_same_asset_create_two_alerts(client, register_user, db):
    email = "dedup-two-changes@example.com"
    headers = register_user(email=email)
    seed_asset, user = _seed(db, client, headers, email, "dedup-two-changes.example.com")

    run1 = _new_run(db, seed_asset, user)
    cert = CertificateObservation(hostname="dedup-two-changes.example.com", port=443, fingerprint_sha256="a" * 64)
    discovery_normalization_service.record_certificate_observation(db, run1, seed_asset, cert)
    db.commit()
    _mark_completed(db, run1)
    alert_service.evaluate_run_for_alerts(db, run1, seed_asset)
    db.commit()

    # A DIFFERENT slot (port 8443) on the same asset -- a first-ever
    # observation there, not a rotation, so certificate_changed
    # correctly does NOT fire for it (only rotations do).
    run2 = _new_run(db, seed_asset, user)
    cert2 = CertificateObservation(hostname="dedup-two-changes.example.com", port=8443, fingerprint_sha256="d" * 64)
    discovery_normalization_service.record_certificate_observation(db, run2, seed_asset, cert2)
    db.commit()
    _mark_completed(db, run2)
    new_cert_alerts = _cert_alerts(alert_service.evaluate_run_for_alerts(db, run2, seed_asset))
    db.commit()
    assert new_cert_alerts == []

    # Now rotate BOTH slots -- two genuinely different identities on the
    # same asset must produce two distinct certificate_changed alerts.
    run3 = _new_run(db, seed_asset, user)
    cert3 = CertificateObservation(hostname="dedup-two-changes.example.com", port=443, fingerprint_sha256="e" * 64)
    discovery_normalization_service.record_certificate_observation(db, run3, seed_asset, cert3)
    cert4 = CertificateObservation(hostname="dedup-two-changes.example.com", port=8443, fingerprint_sha256="f" * 64)
    discovery_normalization_service.record_certificate_observation(db, run3, seed_asset, cert4)
    db.commit()
    _mark_completed(db, run3)
    both_new = _cert_alerts(alert_service.evaluate_run_for_alerts(db, run3, seed_asset))
    db.commit()

    assert len(both_new) == 2
    assert {a.fingerprint for a in both_new} == {
        alert_service._fingerprint(seed_asset.organization_id, both_new[0].alert_type, seed_asset.id, "dedup-two-changes.example.com:443"),
        alert_service._fingerprint(seed_asset.organization_id, both_new[0].alert_type, seed_asset.id, "dedup-two-changes.example.com:8443"),
    }


def test_resolved_alert_recurring_creates_a_new_row_preserving_history(client, register_user, db):
    email = "dedup-resolved@example.com"
    headers = register_user(email=email)
    seed_asset, user = _seed(db, client, headers, email, "dedup-resolved.example.com")

    run1 = _new_run(db, seed_asset, user)
    cert = CertificateObservation(hostname="dedup-resolved.example.com", port=443, fingerprint_sha256="a" * 64)
    discovery_normalization_service.record_certificate_observation(db, run1, seed_asset, cert)
    db.commit()
    _mark_completed(db, run1)
    run2 = _new_run(db, seed_asset, user)
    cert2 = CertificateObservation(hostname="dedup-resolved.example.com", port=443, fingerprint_sha256="b" * 64)
    discovery_normalization_service.record_certificate_observation(db, run2, seed_asset, cert2)
    db.commit()
    _mark_completed(db, run2)
    first_cert_alerts = _cert_alerts(alert_service.evaluate_run_for_alerts(db, run2, seed_asset))
    db.commit()
    assert len(first_cert_alerts) == 1
    original_alert = first_cert_alerts[0]
    original_id = original_alert.id

    alert_service.resolve_alert(db, original_alert, user.id)
    db.refresh(original_alert)
    assert original_alert.status == AlertStatus.resolved

    # The exact same condition (another rotation) recurs.
    run3 = _new_run(db, seed_asset, user)
    cert3 = CertificateObservation(hostname="dedup-resolved.example.com", port=443, fingerprint_sha256="c" * 64)
    discovery_normalization_service.record_certificate_observation(db, run3, seed_asset, cert3)
    db.commit()
    _mark_completed(db, run3)
    second_cert_alerts = _cert_alerts(alert_service.evaluate_run_for_alerts(db, run3, seed_asset))
    db.commit()

    assert len(second_cert_alerts) == 1
    new_alert = second_cert_alerts[0]
    assert new_alert.id != original_id  # a genuinely NEW row, not a reopened one
    assert new_alert.status == AlertStatus.open
    assert new_alert.fingerprint == original_alert.fingerprint  # same semantic identity

    db.refresh(original_alert)
    assert original_alert.status == AlertStatus.resolved  # untouched, history preserved
    assert original_alert.occurrence_count == 1


def test_two_different_assets_producing_the_same_alert_type_get_separate_alerts(client, register_user, db):
    email = "dedup-two-assets@example.com"
    headers = register_user(email=email)
    seed_a, user = _seed(db, client, headers, email, "dedup-two-assets-a.example.com")
    seed_b_resp = _create_and_authorize_asset(client, headers, "dedup-two-assets-b.example.com")
    seed_b = db.get(Asset, uuid.UUID(seed_b_resp["id"]))

    run_a = _new_run(db, seed_a, user)
    cert_a = CertificateObservation(hostname="dedup-two-assets-a.example.com", port=443, fingerprint_sha256="a" * 64)
    discovery_normalization_service.record_certificate_observation(db, run_a, seed_a, cert_a)
    db.commit()
    _mark_completed(db, run_a)
    alert_service.evaluate_run_for_alerts(db, run_a, seed_a)
    db.commit()

    run_b = _new_run(db, seed_b, user)
    cert_b = CertificateObservation(hostname="dedup-two-assets-b.example.com", port=443, fingerprint_sha256="a" * 64)
    discovery_normalization_service.record_certificate_observation(db, run_b, seed_b, cert_b)
    db.commit()
    _mark_completed(db, run_b)
    alert_service.evaluate_run_for_alerts(db, run_b, seed_b)
    db.commit()

    run_a2 = _new_run(db, seed_a, user)
    cert_a2 = CertificateObservation(hostname="dedup-two-assets-a.example.com", port=443, fingerprint_sha256="z" * 64)
    discovery_normalization_service.record_certificate_observation(db, run_a2, seed_a, cert_a2)
    db.commit()
    _mark_completed(db, run_a2)
    new_cert_alerts_a = _cert_alerts(alert_service.evaluate_run_for_alerts(db, run_a2, seed_a))
    db.commit()

    run_b2 = _new_run(db, seed_b, user)
    cert_b2 = CertificateObservation(hostname="dedup-two-assets-b.example.com", port=443, fingerprint_sha256="z" * 64)
    discovery_normalization_service.record_certificate_observation(db, run_b2, seed_b, cert_b2)
    db.commit()
    _mark_completed(db, run_b2)
    new_cert_alerts_b = _cert_alerts(alert_service.evaluate_run_for_alerts(db, run_b2, seed_b))
    db.commit()

    assert len(new_cert_alerts_a) == 1 and len(new_cert_alerts_b) == 1
    assert new_cert_alerts_a[0].id != new_cert_alerts_b[0].id
    assert new_cert_alerts_a[0].fingerprint != new_cert_alerts_b[0].fingerprint  # different asset_id in the identity


def test_repeated_scheduled_execution_with_unchanged_state_does_not_spam(client, register_user, db, executor_uses_test_db):
    """The end-to-end regression: a schedule re-running the stub
    provider against the exact same seed repeatedly must not create a
    growing pile of alerts -- there is nothing NEW to alert about after
    the first run (the stub's single candidate is created once, then
    every subsequent run reconfirms it unchanged).
    """
    email = "dedup-repeated-schedule@example.com"
    headers = register_user(email=email)
    seed_asset, user = _seed(db, client, headers, email, "dedup-repeated-schedule.example.com")
    schedule = discovery_schedule_service.create_schedule(db, seed_asset, "stub", 6, user)

    for _ in range(3):
        runs = discovery_scheduler_executor.claim_due_schedules(db)
        assert len(runs) == 1
        discovery_scheduler_executor.execute_scheduled_run(runs[0].id, schedule.id)
        db.commit()
        schedule.next_run_at = datetime.now(timezone.utc)
        db.commit()

    total_alerts = db.query(Alert).filter(Alert.organization_id == seed_asset.organization_id).count()
    # At most one alert (new_externally_exposed_asset, for the stub's
    # one-time www.* candidate creation) -- never one per tick.
    assert total_alerts <= 1
