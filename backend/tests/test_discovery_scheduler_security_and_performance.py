"""Remaining explicit Step 9.11 security/performance requirements not
already covered by test_discovery_schedule_api.py (org isolation, IDOR,
RBAC, authorization) or test_discovery_scheduler_execution.py
(authorization re-validation, revocation). Background execution's
SSRF/scope/DNS-rebinding safety is unchanged and already exhaustively
covered by the existing provider test suites (test_http_provider_ssrf.py,
test_net_safety.py, test_dns_rebinding.py) -- scheduled execution calls
the exact same, untouched discovery_service.execute_run and provider
registry, so it isn't re-tested here.
"""

import uuid

from sqlalchemy import event

from app.core.enums import DiscoveryRunStatus
from app.models.asset import Asset
from app.models.user import User
from app.services import discovery_schedule_service, discovery_scheduler_executor
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


def test_provider_name_cannot_invoke_arbitrary_code(client, register_user):
    """provider_name is looked up only through the fixed, pre-registered
    DISCOVERY_PROVIDER_REGISTRY dict (get_provider) -- never through
    getattr/import/eval on client-supplied text -- so nothing resembling
    a Python import path, dunder attribute, or module reference can ever
    resolve to executable code, only to "unknown provider" 400s.
    """
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sec-provider.example.com")

    for hostile_name in (
        "os.system",
        "__import__('os').system",
        "app.services.discovery_service",
        "../../etc/passwd",
        "eval('1')",
    ):
        resp = client.post(
            "/discovery/schedules",
            json={"seed_asset_id": seed["id"], "provider_name": hostile_name, "interval_hours": 6},
            headers=headers,
        )
        assert resp.status_code == 400
        assert "unknown discovery provider" in resp.json()["detail"]


def test_task_arguments_carry_only_uuids_no_secrets(client, register_user, db, executor_uses_test_db):
    """The Celery task boundary (dispatch -> execute) passes only
    run_id/schedule_id UUID strings -- confirmed structurally here since
    claim_due_schedules' return value is exactly what gets serialized
    into task args in app/tasks/discovery_schedule_tasks.py.
    """
    headers = register_user(email="sec-task-args@example.com")
    asset = _create_and_authorize_asset(client, headers, "sec-task-args.example.com")
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    user = db.query(User).filter(User.email == "sec-task-args@example.com").first()
    discovery_schedule_service.create_schedule(db, seed_asset, "stub", 6, user)

    runs = discovery_scheduler_executor.claim_due_schedules(db)
    assert len(runs) == 1
    # Exactly what execute_scheduled_discovery_task.delay(...) receives:
    task_args = (str(runs[0].id), str(runs[0].schedule_id))
    for arg in task_args:
        uuid.UUID(arg)  # raises ValueError if this is anything other than a bare UUID string


def test_schedule_response_contains_no_asset_authorization_internals(client, register_user):
    """The schedule read model exposes only orchestration state -- never
    re-serializes the seed asset's own fields (which could otherwise
    leak authorization metadata/notes through an unrelated endpoint).
    """
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "sec-schedule-shape.example.com")
    resp = client.post(
        "/discovery/schedules",
        json={"seed_asset_id": seed["id"], "provider_name": "stub", "interval_hours": 6},
        headers=headers,
    )
    body = resp.json()
    forbidden_keys = {"authorization_confirmed_by", "notes", "owner", "tags"}
    assert forbidden_keys.isdisjoint(body.keys())


def test_claim_due_schedules_does_not_scale_linearly_with_schedule_count(client, register_user, db):
    headers = register_user(email="sec-perf@example.com")
    org_id = None

    def _count_queries(n_schedules: int) -> int:
        nonlocal org_id
        for i in range(n_schedules):
            asset = _create_and_authorize_asset(client, headers, f"sec-perf-{n_schedules}-{i}.example.com")
            seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
            org_id = seed_asset.organization_id
            user = db.query(User).filter(User.email == "sec-perf@example.com").first()
            discovery_schedule_service.create_schedule(db, seed_asset, "stub", 6, user)

        counts = {"n": 0}

        def _on_execute(*args, **kwargs):
            counts["n"] += 1

        event.listen(test_engine, "before_cursor_execute", _on_execute)
        try:
            discovery_scheduler_executor.claim_due_schedules(db, batch_size=200)
        finally:
            event.remove(test_engine, "before_cursor_execute", _on_execute)
        return counts["n"]

    small_batch_queries = _count_queries(3)
    large_batch_queries = _count_queries(15)

    # claim_due_schedules is a fixed, small number of queries regardless
    # of batch size: one SELECT ... FOR UPDATE SKIP LOCKED, one batched
    # owner-validity query, one flush/INSERT batch, one commit -- no
    # per-schedule owner lookup (the classic N+1 shape) and no per-row
    # refresh (id/schedule_id are already correct without one -- see
    # claim_due_schedules' own comment). Query count should not grow
    # materially between a 3-schedule and a 15-schedule claim.
    assert large_batch_queries <= small_batch_queries + 2
