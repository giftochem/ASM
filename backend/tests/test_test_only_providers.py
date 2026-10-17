"""The `stub` discovery provider is test-only. With
settings.enable_test_discovery_providers off -- the default everywhere
except this test suite -- it must be absent from the catalog and
impossible to run, schedule, re-enable, trigger, or execute. A schedule
created for it before it was turned off is retired with an explicit
reason the first time the scheduler reaches it: never deleted, its
history untouched, the provider never invoked.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.config import Settings, settings
from app.core.enums import DiscoveryRunStatus
from app.discovery import registry
from app.discovery.stub_provider import StubDiscoveryProvider
from app.models.asset import Asset
from app.models.discovery_result import DiscoveryResult
from app.models.discovery_run import DiscoveryRun
from app.models.discovery_schedule import DiscoverySchedule
from app.models.user import User
from app.services import discovery_schedule_service, discovery_scheduler_executor

REAL_PROVIDERS = {"dns", "certificate", "subdomain", "http", "network", "cloud"}


def _disable_test_only_providers(monkeypatch) -> None:
    monkeypatch.setattr(settings, "enable_test_discovery_providers", False)


@pytest.fixture
def stub_discover_calls(monkeypatch):
    calls: list[str] = []
    real_discover = StubDiscoveryProvider.discover

    def recording_discover(self, seed_value):
        calls.append(seed_value)
        return real_discover(self, seed_value)

    monkeypatch.setattr(StubDiscoveryProvider, "discover", recording_discover)
    return calls


def _create_and_authorize_asset(client, headers, value):
    resp = client.post("/assets", json={"asset_type": "domain", "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    asset = resp.json()
    confirm = client.post(
        f"/assets/{asset['id']}/confirm-authorization", json={"authorization_confirmed": True}, headers=headers
    )
    assert confirm.status_code == 200, confirm.text
    return asset


# --- registry ---------------------------------------------------------------


def test_flag_defaults_to_off():
    assert Settings.model_fields["enable_test_discovery_providers"].default is False


def test_stub_is_unavailable_when_flag_is_off(monkeypatch):
    _disable_test_only_providers(monkeypatch)

    assert registry.get_provider("stub") is None
    assert set(registry.all_provider_names()) == REAL_PROVIDERS
    assert "stub" not in {provider.name for provider in registry.available_providers()}
    for name in REAL_PROVIDERS:
        assert registry.get_provider(name) is not None
    # The class itself stays reachable for tests, just never via lookups.
    assert isinstance(registry.DISCOVERY_PROVIDER_REGISTRY["stub"], StubDiscoveryProvider)


@pytest.mark.parametrize("environment", ["production", "Production", "prod", "staging", "qa", ""])
def test_stub_is_unavailable_outside_allowlisted_environments_even_with_flag_on(monkeypatch, environment):
    monkeypatch.setattr(settings, "enable_test_discovery_providers", True)
    monkeypatch.setattr(settings, "environment", environment)

    assert registry.get_provider("stub") is None
    assert "stub" not in registry.all_provider_names()


def test_stub_is_blocked_through_the_api_in_a_production_configuration(client, register_user, db, monkeypatch, stub_discover_calls):
    # Registered while still in development, so the session cookies work
    # over the TestClient's plain HTTP; the production switch comes after.
    headers = register_user(email="testonly-production@example.com")
    asset = _create_and_authorize_asset(client, headers, "testonly-production.example.com")
    monkeypatch.setattr(settings, "enable_test_discovery_providers", True)
    monkeypatch.setattr(settings, "environment", "production")

    catalog = client.get("/discovery/providers", headers=headers)
    run = client.post("/discovery/runs", json={"seed_asset_id": asset["id"], "provider_name": "stub"}, headers=headers)
    schedule = client.post(
        "/discovery/schedules",
        json={"seed_asset_id": asset["id"], "provider_name": "stub", "interval_hours": 24},
        headers=headers,
    )

    assert catalog.status_code == 200
    assert {provider["name"] for provider in catalog.json()} == REAL_PROVIDERS
    assert run.status_code == 400 and "unknown discovery provider: 'stub'" in run.json()["detail"]
    assert schedule.status_code == 400 and "unknown discovery provider: 'stub'" in schedule.json()["detail"]
    assert db.query(DiscoveryRun).count() == 0
    assert db.query(DiscoverySchedule).count() == 0
    assert stub_discover_calls == []


def test_stub_is_available_only_when_explicitly_enabled(monkeypatch):
    monkeypatch.setattr(settings, "enable_test_discovery_providers", True)

    assert isinstance(registry.get_provider("stub"), StubDiscoveryProvider)
    assert "stub" in registry.all_provider_names()


# --- API: nothing new can be run or scheduled --------------------------------


def test_provider_catalog_excludes_stub(client, register_user, monkeypatch):
    _disable_test_only_providers(monkeypatch)
    headers = register_user(email="testonly-catalog@example.com")

    resp = client.get("/discovery/providers", headers=headers)

    assert resp.status_code == 200
    assert {provider["name"] for provider in resp.json()} == REAL_PROVIDERS


def test_manual_stub_run_is_rejected_and_never_executed(client, register_user, db, monkeypatch, stub_discover_calls):
    _disable_test_only_providers(monkeypatch)
    headers = register_user(email="testonly-run@example.com")
    asset = _create_and_authorize_asset(client, headers, "testonly-run.example.com")

    resp = client.post("/discovery/runs", json={"seed_asset_id": asset["id"], "provider_name": "stub"}, headers=headers)

    assert resp.status_code == 400
    assert "unknown discovery provider: 'stub'" in resp.json()["detail"]
    assert db.query(DiscoveryRun).count() == 0
    assert stub_discover_calls == []


def test_stub_schedule_creation_is_rejected(client, register_user, db, monkeypatch):
    _disable_test_only_providers(monkeypatch)
    headers = register_user(email="testonly-schedule@example.com")
    asset = _create_and_authorize_asset(client, headers, "testonly-schedule.example.com")

    resp = client.post(
        "/discovery/schedules",
        json={"seed_asset_id": asset["id"], "provider_name": "stub", "interval_hours": 24},
        headers=headers,
    )

    assert resp.status_code == 400
    assert "unknown discovery provider: 'stub'" in resp.json()["detail"]
    assert db.query(DiscoverySchedule).count() == 0


# --- an existing stub schedule (created while it was still enabled) ---------


def _existing_stub_schedule(client, headers, value):
    """Created through the API while the provider is still enabled, like
    the schedules that already exist in pre-hardening databases."""
    asset = _create_and_authorize_asset(client, headers, value)
    resp = client.post(
        "/discovery/schedules",
        json={"seed_asset_id": asset["id"], "provider_name": "stub", "interval_hours": 24},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_existing_stub_schedule_cannot_be_triggered(client, register_user, db, monkeypatch, stub_discover_calls):
    headers = register_user(email="testonly-trigger@example.com")
    schedule = _existing_stub_schedule(client, headers, "testonly-trigger.example.com")
    _disable_test_only_providers(monkeypatch)

    resp = client.post(f"/discovery/schedules/{schedule['id']}/run", headers=headers)

    assert resp.status_code == 400
    assert "unknown discovery provider: 'stub'" in resp.json()["detail"]
    assert db.query(DiscoveryRun).count() == 0  # nothing claimed, nothing queued
    assert stub_discover_calls == []


def test_existing_stub_schedule_can_be_disabled_but_not_re_enabled(client, register_user, db, monkeypatch):
    headers = register_user(email="testonly-reenable@example.com")
    schedule = _existing_stub_schedule(client, headers, "testonly-reenable.example.com")
    _disable_test_only_providers(monkeypatch)

    disable = client.patch(f"/discovery/schedules/{schedule['id']}", json={"enabled": False}, headers=headers)
    assert disable.status_code == 200, disable.text

    reenable = client.patch(f"/discovery/schedules/{schedule['id']}", json={"enabled": True}, headers=headers)
    assert reenable.status_code == 400
    assert "unknown discovery provider: 'stub'" in reenable.json()["detail"]

    stored = db.get(DiscoverySchedule, uuid.UUID(schedule["id"]))
    db.refresh(stored)
    assert stored.enabled is False


def test_rejected_re_enable_leaves_no_partial_change(client, register_user, db, monkeypatch):
    headers = register_user(email="testonly-partial@example.com")
    schedule = _existing_stub_schedule(client, headers, "testonly-partial.example.com")
    client.patch(f"/discovery/schedules/{schedule['id']}", json={"enabled": False}, headers=headers)
    _disable_test_only_providers(monkeypatch)

    resp = client.patch(
        f"/discovery/schedules/{schedule['id']}", json={"enabled": True, "interval_hours": 48}, headers=headers
    )

    assert resp.status_code == 400
    stored = db.get(DiscoverySchedule, uuid.UUID(schedule["id"]))
    db.refresh(stored)
    assert stored.enabled is False
    assert stored.interval_hours == 24


def test_due_stub_schedule_is_retired_by_the_scheduler_without_executing(
    client, register_user, db, executor_uses_test_db, monkeypatch, stub_discover_calls
):
    email = "testonly-scheduler@example.com"
    headers = register_user(email=email)
    asset = _create_and_authorize_asset(client, headers, "testonly-scheduler.example.com")
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    owner = db.query(User).filter(User.email == email).first()
    schedule = discovery_schedule_service.create_schedule(db, seed_asset, "stub", 24, owner)

    # History from before the hardening: one real scheduled stub run.
    first_run = discovery_scheduler_executor.claim_due_schedules(db)[0]
    discovery_scheduler_executor.execute_scheduled_run(first_run.id, schedule.id)
    db.refresh(first_run)
    assert first_run.status == DiscoveryRunStatus.completed
    results_before = db.query(DiscoveryResult).count()
    assets_before = db.query(Asset).count()
    assert results_before > 0 and assets_before == 2  # seed + the stub's fabricated www. asset

    # The provider is now off; the schedule comes due again.
    _disable_test_only_providers(monkeypatch)
    stub_discover_calls.clear()
    schedule.next_run_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db.commit()

    claimed = discovery_scheduler_executor.claim_due_schedules(db)
    assert len(claimed) == 1
    discovery_scheduler_executor.execute_scheduled_run(claimed[0].id, schedule.id)

    db.refresh(schedule)
    retired_run = db.get(DiscoveryRun, claimed[0].id)
    db.refresh(retired_run)
    assert stub_discover_calls == [], "the stub provider must never be invoked once disabled"
    assert retired_run.status == DiscoveryRunStatus.failed
    assert "unknown discovery provider: 'stub'" in retired_run.error_message
    assert schedule.enabled is False
    assert schedule.disabled_reason == "Schedule configuration is no longer valid: unknown discovery provider: 'stub'"
    assert schedule.claimed_at is None

    # History is preserved, untouched.
    db.refresh(first_run)
    assert first_run.status == DiscoveryRunStatus.completed
    assert db.query(DiscoveryResult).count() == results_before
    assert db.query(Asset).count() == assets_before
    assert db.query(DiscoverySchedule).count() == 1

    # Disabled for good: later ticks never claim it again.
    assert discovery_scheduler_executor.claim_due_schedules(db) == []

    # And the API shows the explicit reason.
    listed = client.get("/discovery/schedules", headers=headers).json()
    assert listed[0]["enabled"] is False
    assert listed[0]["disabled_reason"] == schedule.disabled_reason
