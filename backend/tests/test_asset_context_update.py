"""PATCH /assets/{asset_id} (Stage A.1): human-set business context --
criticality and environment -- and nothing else.

Covers RBAC (admin/analyst may update, viewer may not), tenant isolation
(another organization's asset is a 404 and stays untouched), strict input
(enum values only, unsupported fields rejected, empty body rejected),
partial and clearing updates, the asset_updated Observation and audit
entry (accurate before/after, none for a no-op, none when the write
fails), authorization status being out of reach, prioritization picking
up the change, and route ordering.
"""

import json
import uuid

import pytest

from app.core.enums import AssetCriticality, AssetEnvironment, AssetSource, ChangeType
from app.models.asset import Asset
from app.models.audit_log import AuditLog
from app.models.observation import Observation
from app.services import audit_service

PASSWORD = "correct-horse-battery"


def _create_asset(client, headers, value):
    resp = client.post("/assets", json={"asset_type": "domain", "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _add_user(client, admin_headers, login_as, email, role):
    resp = client.post(
        "/users", json={"email": email, "password": PASSWORD, "full_name": role.title(), "role": role}, headers=admin_headers
    )
    assert resp.status_code == 201, resp.text
    return login_as(email, PASSWORD)


def _update_records(db, asset_id):
    db.expire_all()
    observations = (
        db.query(Observation)
        .filter(Observation.asset_id == uuid.UUID(asset_id), Observation.change_type == ChangeType.asset_updated)
        .order_by(Observation.observed_at, Observation.id)
        .all()
    )
    audits = (
        db.query(AuditLog)
        .filter(AuditLog.resource_id == uuid.UUID(asset_id), AuditLog.action == "asset.update")
        .order_by(AuditLog.created_at, AuditLog.id)
        .all()
    )
    return observations, audits


def _stored(db, asset_id) -> Asset:
    db.expire_all()
    return db.get(Asset, uuid.UUID(asset_id))


# --- RBAC -----------------------------------------------------------------------


def test_admin_can_update_criticality_and_environment(client, register_user, db):
    headers = register_user(email="ctx-admin@example.com")
    asset = _create_asset(client, headers, "ctx-admin.example.com")

    resp = client.patch(
        f"/assets/{asset['id']}", json={"criticality": "high", "environment": "production"}, headers=headers
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["criticality"] == "high" and body["environment"] == "production"
    stored = _stored(db, asset["id"])
    assert stored.criticality == AssetCriticality.high
    assert stored.environment == AssetEnvironment.production


def test_analyst_can_update(client, register_user, login_as, db):
    admin_headers = register_user(email="ctx-analyst-admin@example.com")
    asset = _create_asset(client, admin_headers, "ctx-analyst.example.com")
    analyst_headers = _add_user(client, admin_headers, login_as, "ctx-analyst@example.com", "analyst")

    resp = client.patch(f"/assets/{asset['id']}", json={"criticality": "critical"}, headers=analyst_headers)

    assert resp.status_code == 200, resp.text
    assert _stored(db, asset["id"]).criticality == AssetCriticality.critical


def test_viewer_cannot_update(client, register_user, login_as, db):
    admin_headers = register_user(email="ctx-viewer-admin@example.com")
    asset = _create_asset(client, admin_headers, "ctx-viewer.example.com")
    viewer_headers = _add_user(client, admin_headers, login_as, "ctx-viewer@example.com", "viewer")

    resp = client.patch(f"/assets/{asset['id']}", json={"criticality": "critical"}, headers=viewer_headers)

    assert resp.status_code == 403
    assert _stored(db, asset["id"]).criticality is None
    assert _update_records(db, asset["id"]) == ([], [])


def test_unauthenticated_update_is_rejected(client, register_user, db):
    headers = register_user(email="ctx-anon@example.com")
    asset = _create_asset(client, headers, "ctx-anon.example.com")

    resp = client.patch(f"/assets/{asset['id']}", json={"criticality": "high"})

    assert resp.status_code in (401, 403)  # CSRF or auth, either way refused
    assert _stored(db, asset["id"]).criticality is None


def test_update_requires_the_csrf_token(client, register_user, db):
    headers = register_user(email="ctx-csrf@example.com")
    asset = _create_asset(client, headers, "ctx-csrf.example.com")
    no_csrf = {key: value for key, value in headers.items() if key != "X-CSRF-Token"}

    resp = client.patch(f"/assets/{asset['id']}", json={"criticality": "high"}, headers=no_csrf)

    assert resp.status_code == 403
    assert _stored(db, asset["id"]).criticality is None


# --- tenant isolation ------------------------------------------------------------


def test_another_organizations_asset_is_404_and_untouched(client, register_user, db):
    owner_headers = register_user(email="ctx-owner@example.com", org_name="Owner Org")
    asset = _create_asset(client, owner_headers, "ctx-owner.example.com")
    other_headers = register_user(email="ctx-other@example.com", org_name="Other Org")

    resp = client.patch(f"/assets/{asset['id']}", json={"criticality": "critical"}, headers=other_headers)

    assert resp.status_code == 404
    assert _stored(db, asset["id"]).criticality is None
    assert _update_records(db, asset["id"]) == ([], [])


def test_unknown_asset_is_404(client, register_user):
    headers = register_user(email="ctx-unknown@example.com")

    resp = client.patch(f"/assets/{uuid.uuid4()}", json={"criticality": "high"}, headers=headers)

    assert resp.status_code == 404


# --- strict input ----------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [{"criticality": "severe"}, {"environment": "prod"}, {"criticality": 3}, {"environment": ["production"]}],
)
def test_invalid_enum_values_are_rejected(client, register_user, db, body):
    headers = register_user(email="ctx-enum@example.com")
    asset = _create_asset(client, headers, "ctx-enum.example.com")

    resp = client.patch(f"/assets/{asset['id']}", json=body, headers=headers)

    assert resp.status_code == 422
    stored = _stored(db, asset["id"])
    assert stored.criticality is None and stored.environment is None


@pytest.mark.parametrize(
    "body",
    [
        {"authorization_confirmed": True},
        {"organization_id": str(uuid.uuid4())},
        {"value": "renamed.example.com"},
        {"asset_type": "subdomain"},
        {"status": "disappeared"},
        {"source": "discovery"},
        {"confidence": 0.1},
        {"owner": "someone"},
        {"tags": ["x"]},
        {"notes": "changed"},
        {"is_active": False},
        {"criticality": "high", "authorization_confirmed": True},  # one valid field doesn't let an invalid one through
    ],
)
def test_unsupported_fields_are_rejected_and_nothing_changes(client, register_user, db, body):
    headers = register_user(email="ctx-unsupported@example.com")
    asset = _create_asset(client, headers, "ctx-unsupported.example.com")

    resp = client.patch(f"/assets/{asset['id']}", json=body, headers=headers)

    assert resp.status_code == 422
    stored = _stored(db, asset["id"])
    assert stored.value == "ctx-unsupported.example.com"
    assert stored.criticality is None
    assert stored.authorization_confirmed is False
    assert stored.is_active is True
    assert _update_records(db, asset["id"]) == ([], [])


def test_empty_update_is_rejected(client, register_user, db):
    headers = register_user(email="ctx-empty@example.com")
    asset = _create_asset(client, headers, "ctx-empty.example.com")

    resp = client.patch(f"/assets/{asset['id']}", json={}, headers=headers)

    assert resp.status_code == 422
    assert "at least one of" in resp.text


# --- partial, clearing and idempotent updates -------------------------------------


def test_partial_update_preserves_the_other_field(client, register_user, db):
    headers = register_user(email="ctx-partial@example.com")
    asset = _create_asset(client, headers, "ctx-partial.example.com")
    client.patch(f"/assets/{asset['id']}", json={"environment": "staging"}, headers=headers)

    resp = client.patch(f"/assets/{asset['id']}", json={"criticality": "medium"}, headers=headers)

    assert resp.status_code == 200
    stored = _stored(db, asset["id"])
    assert stored.environment == AssetEnvironment.staging
    assert stored.criticality == AssetCriticality.medium


def test_null_clears_a_value_and_is_recorded(client, register_user, db):
    headers = register_user(email="ctx-clear@example.com")
    asset = _create_asset(client, headers, "ctx-clear.example.com")
    client.patch(f"/assets/{asset['id']}", json={"criticality": "high", "environment": "test"}, headers=headers)

    resp = client.patch(f"/assets/{asset['id']}", json={"criticality": None}, headers=headers)

    assert resp.status_code == 200
    assert resp.json()["criticality"] is None and resp.json()["environment"] == "test"
    observations, audits = _update_records(db, asset["id"])
    assert json.loads(observations[-1].previous_value) == {"criticality": "high"}
    assert json.loads(observations[-1].current_value) == {"criticality": None}
    assert audits[-1].details == {"changes": {"criticality": {"from": "high", "to": None}}}


def test_idempotent_update_writes_no_records(client, register_user, db):
    headers = register_user(email="ctx-idem@example.com")
    asset = _create_asset(client, headers, "ctx-idem.example.com")
    client.patch(f"/assets/{asset['id']}", json={"criticality": "high", "environment": "production"}, headers=headers)
    before = _update_records(db, asset["id"])
    assert len(before[0]) == 1 and len(before[1]) == 1

    resp = client.patch(
        f"/assets/{asset['id']}", json={"criticality": "high", "environment": "production"}, headers=headers
    )

    assert resp.status_code == 200
    after = _update_records(db, asset["id"])
    assert len(after[0]) == 1 and len(after[1]) == 1


def test_partly_idempotent_update_records_only_the_changed_field(client, register_user, db):
    headers = register_user(email="ctx-partly@example.com")
    asset = _create_asset(client, headers, "ctx-partly.example.com")
    client.patch(f"/assets/{asset['id']}", json={"criticality": "low", "environment": "production"}, headers=headers)

    client.patch(f"/assets/{asset['id']}", json={"criticality": "low", "environment": "staging"}, headers=headers)

    observations, audits = _update_records(db, asset["id"])
    assert json.loads(observations[-1].previous_value) == {"environment": "production"}
    assert json.loads(observations[-1].current_value) == {"environment": "staging"}
    assert audits[-1].details == {"changes": {"environment": {"from": "production", "to": "staging"}}}


# --- audit and observation ---------------------------------------------------------


def test_update_records_accurate_before_and_after(client, register_user, db):
    email = "ctx-records@example.com"
    headers = register_user(email=email)
    asset = _create_asset(client, headers, "ctx-records.example.com")

    client.patch(f"/assets/{asset['id']}", json={"criticality": "critical", "environment": "production"}, headers=headers)

    observations, audits = _update_records(db, asset["id"])
    assert len(observations) == 1 and len(audits) == 1
    observation, audit = observations[0], audits[0]
    assert observation.field_name == "asset_state"
    assert observation.source == AssetSource.manual
    assert json.loads(observation.previous_value) == {"criticality": None, "environment": None}
    assert json.loads(observation.current_value) == {"criticality": "critical", "environment": "production"}
    assert audit.resource_type == "asset"
    assert audit.organization_id == _stored(db, asset["id"]).organization_id
    assert audit.user_id is not None
    assert audit.details == {
        "changes": {
            "criticality": {"from": None, "to": "critical"},
            "environment": {"from": None, "to": "production"},
        }
    }


def test_update_appears_in_the_change_timeline(client, register_user):
    headers = register_user(email="ctx-timeline@example.com")
    asset = _create_asset(client, headers, "ctx-timeline.example.com")
    client.patch(f"/assets/{asset['id']}", json={"criticality": "high"}, headers=headers)

    resp = client.get("/assets/activity", params={"change_type": "asset_updated"}, headers=headers)

    assert resp.status_code == 200
    entries = resp.json()
    assert len(entries) == 1
    assert entries[0]["asset_id"] == asset["id"] and entries[0]["field_name"] == "asset_state"


def test_failed_update_leaves_no_partial_changes(client, register_user, db, monkeypatch):
    headers = register_user(email="ctx-failure@example.com")
    asset = _create_asset(client, headers, "ctx-failure.example.com")

    def failing_audit(*args, **kwargs):
        raise RuntimeError("simulated audit-log failure")

    monkeypatch.setattr(audit_service, "log_action", failing_audit)

    try:
        resp = client.patch(f"/assets/{asset['id']}", json={"criticality": "critical"}, headers=headers)
    except RuntimeError as exc:  # TestClient re-raises unhandled server errors
        assert "simulated audit-log failure" in str(exc)
    else:
        assert resp.status_code == 500

    stored = _stored(db, asset["id"])
    assert stored.criticality is None  # the field change was rolled back with everything else
    assert _update_records(db, asset["id"]) == ([], [])


def test_authorization_status_is_untouched_by_updates(client, register_user, db):
    headers = register_user(email="ctx-authz@example.com")
    asset = _create_asset(client, headers, "ctx-authz.example.com")
    client.post(
        f"/assets/{asset['id']}/confirm-authorization", json={"authorization_confirmed": True}, headers=headers
    )
    confirmed = _stored(db, asset["id"])
    confirmed_by, confirmed_at = confirmed.authorization_confirmed_by, confirmed.authorization_confirmed_at

    assert client.patch(f"/assets/{asset['id']}", json={"criticality": "high"}, headers=headers).status_code == 200
    revoke_attempt = client.patch(
        f"/assets/{asset['id']}", json={"authorization_confirmed": False}, headers=headers
    )

    assert revoke_attempt.status_code == 422
    stored = _stored(db, asset["id"])
    assert stored.authorization_confirmed is True
    assert stored.authorization_confirmed_by == confirmed_by
    assert stored.authorization_confirmed_at == confirmed_at


# --- prioritization picks up the change ---------------------------------------------


def test_prioritization_reflects_updated_business_context(client, register_user):
    headers = register_user(email="ctx-priority@example.com")
    asset = _create_asset(client, headers, "ctx-priority.example.com")
    before = client.get(f"/assets/{asset['id']}/risk", headers=headers).json()
    assert before["dimensions"]["business_criticality"] == "unknown"

    client.patch(f"/assets/{asset['id']}", json={"criticality": "high", "environment": "production"}, headers=headers)

    after = client.get(f"/assets/{asset['id']}/risk", headers=headers).json()
    assert after["dimensions"]["business_criticality"] == "high"
    signals = {reason["signal"] for reason in after["reasons"]}
    assert {"asset_criticality", "production_environment"} <= signals
    assert "unknown_business_context" not in signals
    prioritized = client.get("/assets/prioritized", params={"criticality": "high"}, headers=headers).json()
    assert [entry["asset_id"] for entry in prioritized] == [asset["id"]]


# --- route ordering ------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/assets/activity", "/assets/summary", "/assets/shared-infrastructure", "/assets/prioritized"])
def test_static_asset_routes_are_unaffected_by_the_patch_route(client, register_user, path):
    headers = register_user(email="ctx-routes@example.com")

    assert client.get(path, headers=headers).status_code == 200
    # PATCH on a static name hits the path-param route and fails UUID
    # validation -- it is never routed to another handler.
    assert client.patch(path, json={"criticality": "high"}, headers=headers).status_code == 422
