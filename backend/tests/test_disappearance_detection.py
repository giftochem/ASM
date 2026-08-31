"""Tests for Step 9.9.5 disappearance detection: a candidate no longer
reconfirmed by a successful run has its relationship (and, if nothing
else vouches for it, the asset itself) marked disappeared -- soft-
remove, history preserved -- while a failed or suspiciously-empty run
must never trigger this.
"""

import threading
import uuid

import app.discovery.subdomain_provider as subdomain_provider_module
from app.core.enums import AssetType, DiscoveryRunStatus, LifecycleStatus, RelationshipType
from app.discovery.base import DiscoveryCandidate
from app.models.asset import Asset
from app.models.discovery_run import DiscoveryRun
from app.models.user import User
from app.services import discovery_normalization_service, discovery_service
from tests.conftest import TestSessionLocal


def _entry(name_value: str) -> dict:
    return {"name_value": name_value}


class _FakeResponse:
    def __init__(self, json_data):
        self._json_data = json_data
        self.status_code = 200

    def raise_for_status(self):
        pass

    def json(self):
        return self._json_data


def _patch_ct_response(monkeypatch, entries: list[dict]):
    def _fake_get(url, params=None, timeout=None):
        return _FakeResponse(entries)

    monkeypatch.setattr(subdomain_provider_module.httpx, "get", _fake_get)


def _create_and_authorize_asset(client, headers, value, asset_type="domain"):
    resp = client.post("/assets", json={"asset_type": asset_type, "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    asset = resp.json()
    confirm = client.post(
        f"/assets/{asset['id']}/confirm-authorization", json={"authorization_confirmed": True}, headers=headers
    )
    assert confirm.status_code == 200, confirm.text
    return asset


def _run_subdomain_discovery(client, headers, seed_id):
    resp = client.post("/discovery/runs", json={"seed_asset_id": seed_id, "provider_name": "subdomain"}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_first_successful_run_never_marks_anything_disappeared(client, register_user, monkeypatch):
    """No prior completed run to compare against -- nothing can have
    disappeared yet, by definition.
    """
    _patch_ct_response(monkeypatch, [_entry("api.first-run.example.com")])
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "first-run.example.com")

    run = _run_subdomain_discovery(client, headers, seed["id"])
    assert run["status"] == "completed"

    all_assets = client.get("/assets", headers=headers).json()
    assert all(a["status"] != "disappeared" for a in all_assets)


def test_candidate_missing_from_second_run_is_marked_disappeared(client, register_user, monkeypatch):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "disappear.example.com")

    _patch_ct_response(monkeypatch, [_entry("api.disappear.example.com\ndev.disappear.example.com")])
    first = _run_subdomain_discovery(client, headers, seed["id"])
    assert first["status"] == "completed"

    _patch_ct_response(monkeypatch, [_entry("api.disappear.example.com")])  # dev.* no longer reported
    second = _run_subdomain_discovery(client, headers, seed["id"])
    assert second["status"] == "completed"

    all_assets = client.get("/assets", headers=headers).json()
    dev_asset = next(a for a in all_assets if a["value"] == "dev.disappear.example.com")
    api_asset = next(a for a in all_assets if a["value"] == "api.disappear.example.com")
    assert dev_asset["status"] == "disappeared"
    assert api_asset["status"] != "disappeared"

    relationships = client.get(f"/assets/{seed['id']}/relationships", headers=headers).json()
    # belongs_to's direction is reversed: source=discovered, target=seed.
    dev_rel = next(r for r in relationships if r["source_asset_id"] == dev_asset["id"])
    assert dev_rel["status"] == "disappeared"
    api_rel = next(r for r in relationships if r["source_asset_id"] == api_asset["id"])
    assert api_rel["status"] == "active"

    dev_observations = client.get(f"/assets/{dev_asset['id']}/observations", headers=headers).json()
    assert any(o["change_type"] == "asset_status_changed" for o in dev_observations)


def test_disappeared_candidate_returns_and_is_revived(client, register_user, monkeypatch):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "returns.example.com")

    _patch_ct_response(monkeypatch, [_entry("dev.returns.example.com")])
    _run_subdomain_discovery(client, headers, seed["id"])

    _patch_ct_response(monkeypatch, [_entry("keepalive.returns.example.com")])  # dev.* absent, but run isn't empty
    _run_subdomain_discovery(client, headers, seed["id"])

    all_assets = client.get("/assets", headers=headers).json()
    dev_asset = next(a for a in all_assets if a["value"] == "dev.returns.example.com")
    assert dev_asset["status"] == "disappeared"

    _patch_ct_response(monkeypatch, [_entry("dev.returns.example.com\nkeepalive.returns.example.com")])  # dev.* returns
    _run_subdomain_discovery(client, headers, seed["id"])

    all_assets_after = client.get("/assets", headers=headers).json()
    dev_asset_after = next(a for a in all_assets_after if a["value"] == "dev.returns.example.com")
    assert dev_asset_after["status"] != "disappeared"

    relationships = client.get(f"/assets/{seed['id']}/relationships", headers=headers).json()
    dev_rel = next(r for r in relationships if r["source_asset_id"] == dev_asset_after["id"])
    assert dev_rel["status"] == "active"


def test_failed_run_never_marks_anything_disappeared(client, register_user, monkeypatch):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "failsafe.example.com")

    _patch_ct_response(monkeypatch, [_entry("api.failsafe.example.com")])
    first = _run_subdomain_discovery(client, headers, seed["id"])
    assert first["status"] == "completed"

    def _raise(url, params=None, timeout=None):
        raise ConnectionError("simulated total provider outage")

    monkeypatch.setattr(subdomain_provider_module.httpx, "get", _raise)

    second = _run_subdomain_discovery(client, headers, seed["id"])
    assert second["status"] == "failed"

    all_assets = client.get("/assets", headers=headers).json()
    api_asset = next(a for a in all_assets if a["value"] == "api.failsafe.example.com")
    assert api_asset["status"] != "disappeared"  # a failed run must never erase previously-known assets

    relationships = client.get(f"/assets/{seed['id']}/relationships", headers=headers).json()
    assert all(r["status"] != "disappeared" for r in relationships)


def test_zero_candidate_run_does_not_trigger_disappearance(client, register_user, monkeypatch):
    """A run that legitimately completes but finds nothing at all (not
    an error -- e.g. crt.sh genuinely returning an empty result set)
    when the previous run found something is treated as suspicious/
    inconclusive, not evidence of mass disappearance.
    """
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "zeroguard.example.com")

    _patch_ct_response(monkeypatch, [_entry("api.zeroguard.example.com")])
    first = _run_subdomain_discovery(client, headers, seed["id"])
    assert first["status"] == "completed"

    _patch_ct_response(monkeypatch, [])  # legitimate empty response, not a failure
    second = _run_subdomain_discovery(client, headers, seed["id"])
    assert second["status"] == "completed"

    all_assets = client.get("/assets", headers=headers).json()
    api_asset = next(a for a in all_assets if a["value"] == "api.zeroguard.example.com")
    assert api_asset["status"] != "disappeared"


def test_asset_with_other_active_relationship_is_not_marked_disappeared(client, register_user, monkeypatch):
    """An asset independently reconfirmed via a different seed/path must
    not be marked disappeared just because ONE path stopped confirming
    it.
    """
    headers = register_user()
    seed1 = _create_and_authorize_asset(client, headers, "multi-seed1.example.com")
    seed2 = _create_and_authorize_asset(client, headers, "multi-seed2.example.com")

    _patch_ct_response(monkeypatch, [_entry("shared.multi-seed1.example.com")])
    _run_subdomain_discovery(client, headers, seed1["id"])

    all_assets = client.get("/assets", headers=headers).json()
    shared_asset = next(a for a in all_assets if a["value"] == "shared.multi-seed1.example.com")

    link_resp = client.post(
        f"/assets/{seed2['id']}/relationships",
        json={"target_asset_id": shared_asset["id"], "relationship_type": "related_to"},
        headers=headers,
    )
    assert link_resp.status_code == 201, link_resp.text

    # shared.* no longer reported from seed1, but the run isn't empty.
    _patch_ct_response(monkeypatch, [_entry("other.multi-seed1.example.com")])
    _run_subdomain_discovery(client, headers, seed1["id"])

    shared_asset_after = client.get(f"/assets/{shared_asset['id']}", headers=headers).json()
    assert shared_asset_after["status"] != "disappeared"

    relationships = client.get(f"/assets/{seed1['id']}/relationships", headers=headers).json()
    seed1_to_shared = next(r for r in relationships if r["source_asset_id"] == shared_asset["id"])
    assert seed1_to_shared["status"] == "disappeared"  # this SPECIFIC path is still correctly marked disappeared


def test_organization_isolation_in_disappearance_comparison(client, register_user, monkeypatch):
    """Disappearance comparison is scoped per (seed, provider) via the
    DiscoveryRun's own organization-scoped seed -- confirms no
    cross-organization leakage into the comparison logic.
    """
    org_a_headers = register_user(org_name="Disappear Org A", email="disappear-org-a@example.com")
    org_b_headers = register_user(org_name="Disappear Org B", email="disappear-org-b@example.com")
    seed_a = _create_and_authorize_asset(client, org_a_headers, "disappear-iso-a.example.com")
    seed_b = _create_and_authorize_asset(client, org_b_headers, "disappear-iso-b.example.com")

    _patch_ct_response(monkeypatch, [_entry("api.disappear-iso-a.example.com")])
    _run_subdomain_discovery(client, org_a_headers, seed_a["id"])
    _run_subdomain_discovery(client, org_b_headers, seed_b["id"])

    resp_a = client.get("/assets", headers=org_a_headers).json()
    resp_b = client.get("/assets", headers=org_b_headers).json()
    assert all(a["status"] != "disappeared" for a in resp_a)
    assert all(a["status"] != "disappeared" for a in resp_b)


def test_concurrent_reconfirmation_of_same_candidate_does_not_crash(client, register_user, db):
    """Concurrent execution/race test (state mutation: the asset-state
    comparison + conditional Observation write in _refresh_asset).
    Mirrors the Barrier + separate-session pattern established since
    Step 9.1. This is a benign race (Observation has no uniqueness
    constraint, so a rare double-write is possible, not corruption) --
    the guarantee under test is that neither call crashes or leaves the
    run/asset in a broken state.
    """
    headers = register_user(email="cd-race-admin@example.com")
    seed_resp = _create_and_authorize_asset(client, headers, "cd-race-seed.example.com")
    seed_id = uuid.UUID(seed_resp["id"])

    admin_user = db.query(User).filter(User.email == "cd-race-admin@example.com").first()
    run = discovery_service.create_run(db, db.get(Asset, seed_id), "stub", admin_user)
    db.commit()
    run_id = run.id

    # Pre-create the target asset once, so both threads race on the
    # REFRESH path specifically (not asset creation, already proven
    # race-safe since Step 9.1).
    candidate = DiscoveryCandidate(asset_type=AssetType.subdomain, value="cd-race-target.example.com", confidence=0.9)
    discovery_normalization_service.normalize_candidate(db, run, db.get(Asset, seed_id), candidate)
    db.commit()

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
    matching = db.query(Asset).filter(Asset.value == "cd-race-target.example.com").all()
    assert len(matching) == 1  # still exactly one asset, no duplicate from the race
