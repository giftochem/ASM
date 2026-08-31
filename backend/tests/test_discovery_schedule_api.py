"""API-level tests for /discovery/schedules: CRUD, validation, RBAC,
organization isolation, IDOR, and manual-trigger behavior.
"""

import uuid

from app.core.enums import DiscoveryRunStatus
from app.models.discovery_schedule import DiscoverySchedule


def _create_and_authorize_asset(client, headers, value, asset_type="domain"):
    resp = client.post("/assets", json={"asset_type": asset_type, "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    asset = resp.json()
    confirm = client.post(
        f"/assets/{asset['id']}/confirm-authorization", json={"authorization_confirmed": True}, headers=headers
    )
    assert confirm.status_code == 200, confirm.text
    return asset


def _create_schedule(client, headers, seed_id, provider_name="stub", interval_hours=6):
    resp = client.post(
        "/discovery/schedules",
        json={"seed_asset_id": seed_id, "provider_name": provider_name, "interval_hours": interval_hours},
        headers=headers,
    )
    return resp


def test_create_schedule_success(client, register_user):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sched-create.example.com")

    resp = _create_schedule(client, headers, seed["id"])
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["seed_asset_id"] == seed["id"]
    assert body["provider_name"] == "stub"
    assert body["interval_hours"] == 6
    assert body["enabled"] is True
    assert body["last_run_at"] is None
    assert body["last_run_id"] is None
    assert body["disabled_reason"] is None
    assert body["next_run_at"] is not None
    # Step 9.13: denormalized seed asset identity, no run yet.
    assert body["seed_asset_value"] == "sched-create.example.com"
    assert body["seed_asset_type"] == "domain"
    assert body["last_run_status"] is None


def test_list_schedules_includes_last_run_status_after_execution(client, register_user, db, executor_uses_test_db):
    """Step 9.13: last_run_status is denormalized from the schedule's own
    last_run relationship -- confirmed here via GET /discovery/schedules
    (the LIST endpoint, which eager-loads it to avoid N+1) after a real
    execution, not just via the single-schedule read.
    """
    from app.services import discovery_scheduler_executor

    headers = register_user(email="sched-liststatus@example.com")
    seed = _create_and_authorize_asset(client, headers, "sched-liststatus.example.com")
    create_resp = _create_schedule(client, headers, seed["id"])
    schedule_id = create_resp.json()["id"]

    runs = discovery_scheduler_executor.claim_due_schedules(db)
    assert len(runs) == 1
    discovery_scheduler_executor.execute_scheduled_run(runs[0].id, uuid.UUID(schedule_id))

    # execute_scheduled_run committed via its own, separate session
    # (executor_uses_test_db points database.SessionLocal at
    # TestSessionLocal, not this fixture's `db`) -- this test's `db`
    # session (the same one the `client` fixture's route handlers use,
    # via the get_db override) still has the pre-execution DiscoveryRun
    # cached by identity. expire_all() forces a fresh read reflecting
    # what the other session actually committed.
    db.expire_all()

    listed = client.get("/discovery/schedules", headers=headers).json()
    matching = next(s for s in listed if s["id"] == schedule_id)
    assert matching["last_run_status"] == "completed"
    assert matching["seed_asset_value"] == "sched-liststatus.example.com"


def test_create_schedule_requires_authorization_confirmed(client, register_user):
    headers = register_user()
    unauthorized = client.post(
        "/assets", json={"asset_type": "domain", "value": "sched-unauth.example.com"}, headers=headers
    ).json()

    resp = _create_schedule(client, headers, unauthorized["id"])
    assert resp.status_code == 403


def test_create_schedule_unsupported_provider(client, register_user):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sched-badprovider.example.com")

    resp = _create_schedule(client, headers, seed["id"], provider_name="not-a-real-provider")
    assert resp.status_code == 400
    assert "unknown discovery provider" in resp.json()["detail"]


def test_create_schedule_provider_incompatible_with_seed_type(client, register_user):
    headers = register_user()
    # "network" only supports ip_address seeds.
    seed = _create_and_authorize_asset(client, headers, "sched-wrongtype.example.com", asset_type="domain")

    resp = _create_schedule(client, headers, seed["id"], provider_name="network")
    assert resp.status_code == 400
    assert "does not support asset_type" in resp.json()["detail"]


def test_create_schedule_nonexistent_seed(client, register_user):
    headers = register_user()
    resp = _create_schedule(client, headers, str(uuid.uuid4()))
    assert resp.status_code == 404


def test_create_schedule_cross_organization_seed(client, register_user):
    org_a_headers = register_user(org_name="Sched Org A", email="sched-org-a@example.com")
    org_b_headers = register_user(org_name="Sched Org B", email="sched-org-b@example.com")
    seed_b = _create_and_authorize_asset(client, org_b_headers, "sched-crossorg.example.com")

    resp = _create_schedule(client, org_a_headers, seed_b["id"])
    assert resp.status_code == 404


def test_create_schedule_invalid_interval_too_small(client, register_user):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sched-interval-small.example.com")

    resp = client.post(
        "/discovery/schedules",
        json={"seed_asset_id": seed["id"], "provider_name": "stub", "interval_hours": 0},
        headers=headers,
    )
    assert resp.status_code == 422  # Pydantic Field(ge=1) rejects this before it ever reaches the service


def test_create_schedule_invalid_interval_too_large(client, register_user):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sched-interval-large.example.com")

    resp = client.post(
        "/discovery/schedules",
        json={"seed_asset_id": seed["id"], "provider_name": "stub", "interval_hours": 100000},
        headers=headers,
    )
    assert resp.status_code == 422


def test_viewer_cannot_create_schedule(client, register_user, login_as):
    admin_headers = register_user(email="sched-viewer-admin@example.com")
    seed = _create_and_authorize_asset(client, admin_headers, "sched-viewer.example.com")
    resp = client.post(
        "/users",
        json={"email": "sched-viewer@example.com", "password": "correct-horse-battery", "full_name": "V", "role": "viewer"},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    viewer_headers = login_as("sched-viewer@example.com", "correct-horse-battery")

    resp = _create_schedule(client, viewer_headers, seed["id"])
    assert resp.status_code == 403


def test_analyst_can_create_schedule(client, register_user, login_as):
    admin_headers = register_user(email="sched-analyst-admin@example.com")
    seed = _create_and_authorize_asset(client, admin_headers, "sched-analyst.example.com")
    resp = client.post(
        "/users",
        json={"email": "sched-analyst@example.com", "password": "correct-horse-battery", "full_name": "A", "role": "analyst"},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    analyst_headers = login_as("sched-analyst@example.com", "correct-horse-battery")

    resp = _create_schedule(client, analyst_headers, seed["id"])
    assert resp.status_code == 201


def test_list_schedules_organization_isolation(client, register_user):
    org_a_headers = register_user(org_name="List Sched Org A", email="list-sched-a@example.com")
    org_b_headers = register_user(org_name="List Sched Org B", email="list-sched-b@example.com")
    seed_a = _create_and_authorize_asset(client, org_a_headers, "list-sched-a.example.com")
    seed_b = _create_and_authorize_asset(client, org_b_headers, "list-sched-b.example.com")
    _create_schedule(client, org_a_headers, seed_a["id"])
    _create_schedule(client, org_b_headers, seed_b["id"])

    resp_a = client.get("/discovery/schedules", headers=org_a_headers)
    values_a = {item["seed_asset_id"] for item in resp_a.json()}
    assert seed_a["id"] in values_a
    assert seed_b["id"] not in values_a


def test_get_schedule_idor_cross_org_404(client, register_user):
    org_a_headers = register_user(org_name="IDOR Sched Org A", email="idor-sched-a@example.com")
    org_b_headers = register_user(org_name="IDOR Sched Org B", email="idor-sched-b@example.com")
    seed_b = _create_and_authorize_asset(client, org_b_headers, "idor-sched-b.example.com")
    schedule_b = _create_schedule(client, org_b_headers, seed_b["id"]).json()

    resp = client.get(f"/discovery/schedules/{schedule_b['id']}", headers=org_a_headers)
    assert resp.status_code == 404


def test_update_schedule_idor_cross_org_404(client, register_user):
    org_a_headers = register_user(org_name="Update IDOR Org A", email="update-idor-a@example.com")
    org_b_headers = register_user(org_name="Update IDOR Org B", email="update-idor-b@example.com")
    seed_b = _create_and_authorize_asset(client, org_b_headers, "update-idor-b.example.com")
    schedule_b = _create_schedule(client, org_b_headers, seed_b["id"]).json()

    resp = client.patch(f"/discovery/schedules/{schedule_b['id']}", json={"enabled": False}, headers=org_a_headers)
    assert resp.status_code == 404


def test_delete_schedule_idor_cross_org_404(client, register_user):
    org_a_headers = register_user(org_name="Delete IDOR Org A", email="delete-idor-a@example.com")
    org_b_headers = register_user(org_name="Delete IDOR Org B", email="delete-idor-b@example.com")
    seed_b = _create_and_authorize_asset(client, org_b_headers, "delete-idor-b.example.com")
    schedule_b = _create_schedule(client, org_b_headers, seed_b["id"]).json()

    resp = client.delete(f"/discovery/schedules/{schedule_b['id']}", headers=org_a_headers)
    assert resp.status_code == 404


def test_trigger_schedule_idor_cross_org_404(client, register_user):
    org_a_headers = register_user(org_name="Trigger IDOR Org A", email="trigger-idor-a@example.com")
    org_b_headers = register_user(org_name="Trigger IDOR Org B", email="trigger-idor-b@example.com")
    seed_b = _create_and_authorize_asset(client, org_b_headers, "trigger-idor-b.example.com")
    schedule_b = _create_schedule(client, org_b_headers, seed_b["id"]).json()

    resp = client.post(f"/discovery/schedules/{schedule_b['id']}/run", headers=org_a_headers)
    assert resp.status_code == 404


def test_disable_then_enable_schedule(client, register_user, db):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sched-disable.example.com")
    schedule = _create_schedule(client, headers, seed["id"]).json()

    disable_resp = client.patch(f"/discovery/schedules/{schedule['id']}", json={"enabled": False}, headers=headers)
    assert disable_resp.status_code == 200
    assert disable_resp.json()["enabled"] is False

    db_schedule = db.get(DiscoverySchedule, uuid.UUID(schedule["id"]))
    assert db_schedule.enabled is False

    enable_resp = client.patch(f"/discovery/schedules/{schedule['id']}", json={"enabled": True}, headers=headers)
    assert enable_resp.status_code == 200
    assert enable_resp.json()["enabled"] is True
    assert enable_resp.json()["disabled_reason"] is None


def test_update_interval(client, register_user):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sched-update-interval.example.com")
    schedule = _create_schedule(client, headers, seed["id"], interval_hours=6).json()

    resp = client.patch(f"/discovery/schedules/{schedule['id']}", json={"interval_hours": 12}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["interval_hours"] == 12


def test_update_interval_invalid_rejected(client, register_user):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sched-update-bad-interval.example.com")
    schedule = _create_schedule(client, headers, seed["id"]).json()

    resp = client.patch(f"/discovery/schedules/{schedule['id']}", json={"interval_hours": -5}, headers=headers)
    assert resp.status_code == 422


def test_delete_schedule(client, register_user, db):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sched-delete.example.com")
    schedule = _create_schedule(client, headers, seed["id"]).json()

    resp = client.delete(f"/discovery/schedules/{schedule['id']}", headers=headers)
    assert resp.status_code == 204
    assert db.get(DiscoverySchedule, uuid.UUID(schedule["id"])) is None


def test_manual_trigger_enqueues_and_returns_run(client, register_user, eager_celery):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sched-trigger.example.com")
    schedule = _create_schedule(client, headers, seed["id"]).json()

    resp = client.post(f"/discovery/schedules/{schedule['id']}/run", headers=headers)
    assert resp.status_code == 202, resp.text
    run = resp.json()
    assert run["provider_name"] == "stub"
    # Under eager_celery, execution has already completed synchronously
    # by the time this returns.
    assert run["status"] == DiscoveryRunStatus.completed.value

    schedule_after = client.get(f"/discovery/schedules/{schedule['id']}", headers=headers).json()
    assert schedule_after["last_run_id"] == run["id"]
    assert schedule_after["last_run_at"] is not None


def test_manual_trigger_disabled_schedule_rejected(client, register_user):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sched-trigger-disabled.example.com")
    schedule = _create_schedule(client, headers, seed["id"]).json()
    client.patch(f"/discovery/schedules/{schedule['id']}", json={"enabled": False}, headers=headers)

    resp = client.post(f"/discovery/schedules/{schedule['id']}/run", headers=headers)
    assert resp.status_code == 400


def test_manual_trigger_while_already_running_returns_409(client, register_user, db):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sched-trigger-conflict.example.com")
    schedule_resp = _create_schedule(client, headers, seed["id"]).json()

    db_schedule = db.get(DiscoverySchedule, uuid.UUID(schedule_resp["id"]))
    from datetime import datetime, timezone

    db_schedule.claimed_at = datetime.now(timezone.utc)  # simulate an in-flight claim
    db.commit()

    resp = client.post(f"/discovery/schedules/{schedule_resp['id']}/run", headers=headers)
    assert resp.status_code == 409


def test_viewer_cannot_trigger_schedule(client, register_user, login_as):
    admin_headers = register_user(email="sched-trigger-viewer-admin@example.com")
    seed = _create_and_authorize_asset(client, admin_headers, "sched-trigger-viewer.example.com")
    schedule = _create_schedule(client, admin_headers, seed["id"]).json()
    resp = client.post(
        "/users",
        json={"email": "sched-trigger-viewer@example.com", "password": "correct-horse-battery", "full_name": "V", "role": "viewer"},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    viewer_headers = login_as("sched-trigger-viewer@example.com", "correct-horse-battery")

    resp = client.post(f"/discovery/schedules/{schedule['id']}/run", headers=viewer_headers)
    assert resp.status_code == 403


def test_all_endpoints_require_authentication(client):
    """GET endpoints have no CSRF check (read-only), so a missing auth
    cookie is always a clean 401. POST/PATCH/DELETE sit behind the
    global CSRF middleware, which runs before route-level auth and
    rejects a request with no CSRF cookie/header pair at all -- 403,
    not 401, for a bare unauthenticated request specifically (a real,
    pre-existing, correct security property of this codebase, not
    something Step 9.11 changes) -- either code is a correct rejection,
    so both are accepted here rather than asserting one exact value.
    """
    schedule_id = str(uuid.uuid4())
    assert client.get("/discovery/schedules").status_code == 401
    assert client.get(f"/discovery/schedules/{schedule_id}").status_code == 401
    assert client.post("/discovery/schedules", json={}).status_code in (401, 403)
    assert client.patch(f"/discovery/schedules/{schedule_id}", json={}).status_code in (401, 403)
    assert client.delete(f"/discovery/schedules/{schedule_id}").status_code in (401, 403)
    assert client.post(f"/discovery/schedules/{schedule_id}/run").status_code in (401, 403)
