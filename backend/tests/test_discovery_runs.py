import threading
import uuid

import pytest

from app.core.enums import AssetType, DiscoveryResultOutcome, RelationshipType
from app.discovery.base import DiscoveryCandidate, DiscoveryProvider, DiscoveryProviderResult
from app.models.asset import Asset
from app.models.discovery_run import DiscoveryRun
from app.models.user import User
from app.services import discovery_normalization_service, discovery_service
from tests.conftest import TestSessionLocal


def _create_and_authorize_asset(client, headers, value, asset_type="domain"):
    resp = client.post("/assets", json={"asset_type": asset_type, "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    asset = resp.json()
    confirm = client.post(
        f"/assets/{asset['id']}/confirm-authorization",
        json={"authorization_confirmed": True},
        headers=headers,
    )
    assert confirm.status_code == 200, confirm.text
    return asset


class _FailingProvider(DiscoveryProvider):
    """Simulates an unexpected exception escaping a provider — proves
    discovery_service's try/except safety net, mirroring how
    scan_executor is proven never to let a module's exception escape.
    """

    name = "failing"
    applicable_seed_types = {AssetType.domain, AssetType.subdomain}

    def discover(self, seed_value: str) -> DiscoveryProviderResult:
        raise RuntimeError("simulated provider crash")


class _ErrorReportingProvider(DiscoveryProvider):
    """Simulates a provider correctly following its 'never raise, report
    via result.error' contract for an expected failure.
    """

    name = "error-reporting"
    applicable_seed_types = {AssetType.domain, AssetType.subdomain}

    def discover(self, seed_value: str) -> DiscoveryProviderResult:
        return DiscoveryProviderResult(provider=self.name, error="simulated expected failure")


def _patch_fake_provider(monkeypatch, provider):
    import app.services.discovery_service as discovery_service_module

    def fake_lookup(name):
        return provider if name == provider.name else None

    monkeypatch.setattr(discovery_service_module, "get_provider", fake_lookup)


# --- Authorization / RBAC / org isolation ---------------------------------


def test_discovery_requires_authorization(client, register_user):
    headers = register_user()
    asset = client.post("/assets", json={"asset_type": "domain", "value": "unauth.example.com"}, headers=headers).json()

    resp = client.post(
        "/discovery/runs", json={"seed_asset_id": asset["id"], "provider_name": "stub"}, headers=headers
    )
    assert resp.status_code == 403


def test_unknown_provider_rejected(client, register_user):
    headers = register_user()
    asset = _create_and_authorize_asset(client, headers, "unknown-provider.example.com")

    resp = client.post(
        "/discovery/runs", json={"seed_asset_id": asset["id"], "provider_name": "does-not-exist"}, headers=headers
    )
    assert resp.status_code == 400


def test_provider_not_supporting_seed_asset_type_rejected(client, register_user):
    headers = register_user()
    asset = _create_and_authorize_asset(client, headers, "93.184.216.34", asset_type="ip_address")

    resp = client.post(
        "/discovery/runs", json={"seed_asset_id": asset["id"], "provider_name": "stub"}, headers=headers
    )
    assert resp.status_code == 400


def test_viewer_cannot_create_discovery_run(client, register_user, login_as):
    admin_headers = register_user(email="disc-org-admin@example.com")
    asset = _create_and_authorize_asset(client, admin_headers, "viewer-blocked.example.com")

    viewer_resp = client.post(
        "/users",
        json={
            "email": "disc-viewer@example.com",
            "password": "correct-horse-battery",
            "full_name": "Viewer Person",
            "role": "viewer",
        },
        headers=admin_headers,
    )
    assert viewer_resp.status_code == 201
    viewer_headers = login_as("disc-viewer@example.com", "correct-horse-battery")

    resp = client.post(
        "/discovery/runs",
        json={"seed_asset_id": asset["id"], "provider_name": "stub"},
        headers=viewer_headers,
    )
    assert resp.status_code == 403


def test_discovery_against_another_orgs_asset_is_rejected(client, register_user):
    org_a_headers = register_user(org_name="Org A", email="disc-a-admin@example.com")
    org_b_headers = register_user(org_name="Org B", email="disc-b-admin@example.com")

    org_b_asset = _create_and_authorize_asset(client, org_b_headers, "org-b-asset.example.com")

    resp = client.post(
        "/discovery/runs",
        json={"seed_asset_id": org_b_asset["id"], "provider_name": "stub"},
        headers=org_a_headers,
    )
    assert resp.status_code == 404


def test_runs_and_results_are_isolated_between_organizations(client, register_user):
    org_a_headers = register_user(org_name="Org A", email="disc-iso-a@example.com")
    org_b_headers = register_user(org_name="Org B", email="disc-iso-b@example.com")

    asset = _create_and_authorize_asset(client, org_a_headers, "iso.example.com")
    run = client.post(
        "/discovery/runs", json={"seed_asset_id": asset["id"], "provider_name": "stub"}, headers=org_a_headers
    ).json()

    assert client.get(f"/discovery/runs/{run['id']}", headers=org_b_headers).status_code == 404
    assert client.get(f"/discovery/runs/{run['id']}/results", headers=org_b_headers).status_code == 404
    assert client.get("/discovery/runs", headers=org_b_headers).json() == []


# --- Lifecycle / normalization ---------------------------------------------


def test_discovery_run_completes_and_creates_asset_relationship_observation(client, register_user):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "lifecycle.example.com")

    resp = client.post(
        "/discovery/runs", json={"seed_asset_id": seed["id"], "provider_name": "stub"}, headers=headers
    )
    assert resp.status_code == 201, resp.text
    run = resp.json()
    assert run["status"] == "completed"
    assert run["provider_name"] == "stub"
    assert run["started_at"] is not None
    assert run["completed_at"] is not None
    assert run["error_message"] is None

    results = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()
    assert len(results) == 1
    assert results[0]["outcome"] == "created"
    assert results[0]["candidate_value"] == "www.lifecycle.example.com"
    assert results[0]["confidence"] == pytest.approx(0.9)
    resulting_asset_id = results[0]["resulting_asset_id"]
    assert resulting_asset_id is not None

    # The discovered asset itself: source=discovery, status=first_seen.
    discovered = client.get(f"/assets/{resulting_asset_id}", headers=headers).json()
    assert discovered["asset_type"] == "subdomain"
    assert discovered["value"] == "www.lifecycle.example.com"
    assert discovered["source"] == "discovery"
    assert discovered["status"] == "first_seen"

    # The relationship to the seed -- belongs_to is direction-reversed
    # (Step 9.4 fix): "a subdomain belongs_to its domain," so the
    # DISCOVERED asset is the relationship's source and the seed is the
    # target, not the other way around. (Prior to this fix, this
    # assertion was backwards -- a real bug found while designing Step
    # 9.2, fixed once a real provider (9.4) needed the correct
    # direction; see discovery_normalization_service's
    # _REVERSED_DIRECTION_RELATIONSHIP_TYPES.)
    relationships = client.get(f"/assets/{seed['id']}/relationships", headers=headers).json()
    assert len(relationships) == 1
    assert relationships[0]["source_asset_id"] == resulting_asset_id
    assert relationships[0]["target_asset_id"] == seed["id"]
    assert relationships[0]["relationship_type"] == "belongs_to"
    assert relationships[0]["source"] == "discovery"

    # Observations: relationship_created is written on the relationship's
    # source_asset (asset_relationship_service's existing behavior,
    # unchanged) -- which is now the discovered asset for belongs_to,
    # alongside its own asset_created.
    new_asset_observations = client.get(f"/assets/{resulting_asset_id}/observations", headers=headers).json()
    new_asset_change_types = [o["change_type"] for o in new_asset_observations]
    assert "asset_created" in new_asset_change_types
    assert "relationship_created" in new_asset_change_types


def test_relationship_direction_depends_on_relationship_type(client, register_user, db):
    """The general rule, isolated from any one provider: relationship
    types with a naturally seed->target semantic (resolves_to/uses/
    served_by/related_to/...) keep the seed as source; belongs_to is the
    one exception (a child->parent semantic), reversed automatically by
    discovery_normalization_service regardless of which provider used it.
    """
    headers = register_user(email="direction-admin@example.com")
    seed_resp = _create_and_authorize_asset(client, headers, "direction.example.com")
    seed_asset = db.get(Asset, uuid.UUID(seed_resp["id"]))
    admin_user = db.query(User).filter(User.email == "direction-admin@example.com").first()
    run = discovery_service.create_run(db, seed_asset, "stub", admin_user)

    related_to_candidate = DiscoveryCandidate(
        asset_type=AssetType.subdomain,
        value="related.direction.example.com",
        relationship_type=RelationshipType.related_to,
        confidence=0.9,
    )
    belongs_to_candidate = DiscoveryCandidate(
        asset_type=AssetType.subdomain,
        value="child.direction.example.com",
        relationship_type=RelationshipType.belongs_to,
        confidence=0.9,
    )

    related_result = discovery_normalization_service.normalize_candidate(db, run, seed_asset, related_to_candidate)
    belongs_result = discovery_normalization_service.normalize_candidate(db, run, seed_asset, belongs_to_candidate)

    relationships = client.get(f"/assets/{seed_resp['id']}/relationships", headers=headers).json()
    by_type = {r["relationship_type"]: r for r in relationships}

    assert by_type["related_to"]["source_asset_id"] == seed_resp["id"]
    assert by_type["related_to"]["target_asset_id"] == str(related_result.resulting_asset_id)

    assert by_type["belongs_to"]["source_asset_id"] == str(belongs_result.resulting_asset_id)
    assert by_type["belongs_to"]["target_asset_id"] == seed_resp["id"]


def test_repeated_discovery_refreshes_instead_of_duplicating(client, register_user):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "repeat.example.com")

    first = client.post(
        "/discovery/runs", json={"seed_asset_id": seed["id"], "provider_name": "stub"}, headers=headers
    ).json()
    second = client.post(
        "/discovery/runs", json={"seed_asset_id": seed["id"], "provider_name": "stub"}, headers=headers
    ).json()

    first_results = client.get(f"/discovery/runs/{first['id']}/results", headers=headers).json()
    second_results = client.get(f"/discovery/runs/{second['id']}/results", headers=headers).json()
    assert first_results[0]["outcome"] == "created"
    # Step 9.9.2: a re-discovery that changes nothing meaningful about
    # the asset (same value/type/status/source/...) is now `unchanged`,
    # not `refreshed` -- closing the "every refresh writes a duplicate
    # asset_updated Observation forever" gap disclosed since Step 9.1.
    # `refreshed` is reserved for when a meaningful field genuinely
    # differs (most commonly a stale/disappeared -> active revival).
    assert second_results[0]["outcome"] == "unchanged"
    assert first_results[0]["resulting_asset_id"] == second_results[0]["resulting_asset_id"]

    all_assets = client.get("/assets", headers=headers).json()
    matching = [a for a in all_assets if a["value"] == "www.repeat.example.com"]
    assert len(matching) == 1

    # Relationship also refreshed, not duplicated.
    relationships = client.get(f"/assets/{seed['id']}/relationships", headers=headers).json()
    assert len(relationships) == 1


def test_failed_provider_exception_marks_run_failed(client, register_user, monkeypatch):
    _patch_fake_provider(monkeypatch, _FailingProvider())
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "crash.example.com")

    resp = client.post(
        "/discovery/runs", json={"seed_asset_id": seed["id"], "provider_name": "failing"}, headers=headers
    )
    assert resp.status_code == 201
    run = resp.json()
    assert run["status"] == "failed"
    assert "simulated provider crash" in run["error_message"]

    results = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()
    assert results == []


def test_provider_reported_error_marks_run_failed(client, register_user, monkeypatch):
    _patch_fake_provider(monkeypatch, _ErrorReportingProvider())
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "reported-error.example.com")

    resp = client.post(
        "/discovery/runs",
        json={"seed_asset_id": seed["id"], "provider_name": "error-reporting"},
        headers=headers,
    )
    assert resp.status_code == 201
    run = resp.json()
    assert run["status"] == "failed"
    assert "simulated expected failure" in run["error_message"]


# --- Safety: SSRF-sensitive candidate rejection, concurrency ---------------


def test_normalize_candidate_rejects_private_ip_candidate(client, register_user, db):
    headers = register_user()
    seed_resp = _create_and_authorize_asset(client, headers, "ssrf-check.example.com")
    seed_asset = db.get(Asset, uuid.UUID(seed_resp["id"]))
    admin_user = db.query(User).filter(User.email == "admin@example.com").first()
    run = discovery_service.create_run(db, seed_asset, "stub", admin_user)

    unsafe_candidate = DiscoveryCandidate(asset_type=AssetType.ip_address, value="127.0.0.1", confidence=0.5)
    result = discovery_normalization_service.normalize_candidate(db, run, seed_asset, unsafe_candidate)

    assert result.outcome == DiscoveryResultOutcome.rejected
    assert result.resulting_asset_id is None
    assert db.query(Asset).filter(Asset.value == "127.0.0.1").count() == 0


def test_concurrent_normalization_does_not_create_duplicate_assets(client, register_user, db):
    headers = register_user(email="race-admin@example.com")
    seed_resp = _create_and_authorize_asset(client, headers, "race.example.com")
    seed_id = uuid.UUID(seed_resp["id"])

    admin_user = db.query(User).filter(User.email == "race-admin@example.com").first()
    run = discovery_service.create_run(db, db.get(Asset, seed_id), "stub", admin_user)
    db.commit()
    run_id = run.id

    candidate = DiscoveryCandidate(
        asset_type=AssetType.subdomain,
        value="race-target.race.example.com",
        relationship_type=RelationshipType.belongs_to,
        confidence=0.9,
    )

    barrier = threading.Barrier(2)
    results = {}
    lock = threading.Lock()

    def _do_normalize(name: str) -> None:
        session = TestSessionLocal()
        try:
            seed_asset = session.get(Asset, seed_id)
            run_obj = session.get(DiscoveryRun, run_id)
            barrier.wait(timeout=5)
            try:
                discovery_normalization_service.normalize_candidate(session, run_obj, seed_asset, candidate)
                session.commit()
                outcome = "ok"
            except Exception as exc:  # pragma: no cover - only hit on an actual regression
                session.rollback()
                outcome = f"error:{exc}"
            with lock:
                results[name] = outcome
        finally:
            session.close()

    t1 = threading.Thread(target=_do_normalize, args=("t1",))
    t2 = threading.Thread(target=_do_normalize, args=("t2",))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    assert results == {"t1": "ok", "t2": "ok"}

    matching_assets = db.query(Asset).filter(Asset.value == "race-target.race.example.com").all()
    assert len(matching_assets) == 1
