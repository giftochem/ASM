"""API-level integration tests for the "certificate" discovery provider.
Reuses test_certificate_provider.py's local TLS server fixture directly
(imported, not duplicated) — no public Internet involved. Certificate/
Service have no API routes yet (Step 8.1), so their state is verified
via direct DB query using the `db` fixture, same as
test_asset_intelligence_model.py already does for the same reason.
"""

import uuid

from app.core.enums import LifecycleStatus
from app.models.certificate import Certificate
from tests.test_certificate_provider import _point_provider_at, tls_server  # noqa: F401 (fixture import)


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


def _run_certificate_discovery(client, headers, seed_id):
    resp = client.post(
        "/discovery/runs", json={"seed_asset_id": seed_id, "provider_name": "certificate"}, headers=headers
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_certificate_discovery_creates_certificate_row_and_observation(client, register_user, db, tls_server, monkeypatch):
    server = tls_server("cert-a.example.com")
    _point_provider_at(monkeypatch, server)

    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "cert-a.example.com")

    run = _run_certificate_discovery(client, headers, seed["id"])
    assert run["status"] == "completed"
    assert run["error_message"] is None

    results = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()
    assert len(results) == 1
    assert results[0]["outcome"] == "created"

    certificate = (
        db.query(Certificate)
        .filter(Certificate.asset_id == uuid.UUID(seed["id"]), Certificate.hostname == "cert-a.example.com")
        .one()
    )
    assert certificate.port == server.port
    assert certificate.is_self_signed is True
    assert certificate.status == LifecycleStatus.first_seen
    assert len(certificate.fingerprint_sha256) == 64

    observations = client.get(f"/assets/{seed['id']}/observations", headers=headers).json()
    assert "certificate_observed" in [o["change_type"] for o in observations]


def test_in_scope_san_creates_unauthorized_first_seen_asset(client, register_user, tls_server, monkeypatch):
    """The core safety proof at the API level: a SAN-derived asset is
    real (queryable), but authorization_confirmed is False -- it cannot
    be scanned without a human separately, explicitly authorizing it.
    """
    server = tls_server("cert-b.example.com", extra_sans=["api.cert-b.example.com"])
    _point_provider_at(monkeypatch, server)

    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "cert-b.example.com")
    run = _run_certificate_discovery(client, headers, seed["id"])

    results = client.get(f"/discovery/runs/{run['id']}/results", headers=headers).json()
    san_result = results[0]
    resulting_asset_id = san_result["resulting_asset_id"]

    all_assets = client.get("/assets", headers=headers).json()
    san_asset = next(a for a in all_assets if a["value"] == "api.cert-b.example.com")
    assert san_asset["status"] == "first_seen"
    assert san_asset["authorization_confirmed"] is False
    assert san_asset["source"] == "discovery"

    # Attempting to scan it must still be rejected -- authorization was
    # never implicitly granted by appearing in a certificate.
    scan_resp = client.post(
        "/scans", json={"asset_id": san_asset["id"], "modules": ["dns"]}, headers=headers
    )
    assert scan_resp.status_code == 403


def test_external_san_recorded_as_evidence_not_asset(client, register_user, tls_server, monkeypatch):
    server = tls_server("cert-c.example.com", extra_sans=["vendor.example.net"])
    _point_provider_at(monkeypatch, server)

    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "cert-c.example.com")
    _run_certificate_discovery(client, headers, seed["id"])

    all_assets = client.get("/assets", headers=headers).json()
    assert all(a["value"] != "vendor.example.net" for a in all_assets)


def test_repeated_identical_certificate_discovery_is_unchanged(client, register_user, db, tls_server, monkeypatch):
    server = tls_server("cert-d.example.com")
    _point_provider_at(monkeypatch, server)

    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "cert-d.example.com")

    first_run = _run_certificate_discovery(client, headers, seed["id"])
    second_run = _run_certificate_discovery(client, headers, seed["id"])

    first_outcome = client.get(f"/discovery/runs/{first_run['id']}/results", headers=headers).json()[0]["outcome"]
    second_outcome = client.get(f"/discovery/runs/{second_run['id']}/results", headers=headers).json()[0]["outcome"]
    assert first_outcome == "created"
    assert second_outcome == "unchanged"

    certificates = db.query(Certificate).filter(Certificate.asset_id == uuid.UUID(seed["id"])).all()
    assert len(certificates) == 1  # no duplicate row

    observations = client.get(f"/assets/{seed['id']}/observations", headers=headers).json()
    cert_observations = [o for o in observations if o["change_type"] in ("certificate_observed", "certificate_changed")]
    assert len(cert_observations) == 1  # only the first run wrote one; the unchanged run wrote none


def test_certificate_rotation_produces_changed_observation_and_preserves_history(
    client, register_user, db, tls_server, monkeypatch
):
    """Proves Step 9.3's change-detection-preparation requirement
    directly: a fingerprint rotation must not destroy the original
    certificate_observed observation, and must record old -> new
    fingerprint on a new certificate_changed observation.
    """
    server_a = tls_server("cert-e.example.com")
    _point_provider_at(monkeypatch, server_a)

    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "cert-e.example.com")
    _run_certificate_discovery(client, headers, seed["id"])

    first_cert = (
        db.query(Certificate)
        .filter(Certificate.asset_id == uuid.UUID(seed["id"]), Certificate.hostname == "cert-e.example.com")
        .one()
    )
    first_fingerprint = first_cert.fingerprint_sha256
    reused_port = server_a.port
    server_a.close()

    server_b = tls_server("cert-e.example.com", port=reused_port)
    _point_provider_at(monkeypatch, server_b)

    second_run = _run_certificate_discovery(client, headers, seed["id"])
    second_outcome = client.get(f"/discovery/runs/{second_run['id']}/results", headers=headers).json()[0]["outcome"]
    assert second_outcome == "refreshed"

    second_cert = (
        db.query(Certificate)
        .filter(Certificate.asset_id == uuid.UUID(seed["id"]), Certificate.hostname == "cert-e.example.com")
        .one()
    )
    assert second_cert.fingerprint_sha256 != first_fingerprint  # rotated, same row (not a duplicate)

    observations = client.get(f"/assets/{seed['id']}/observations", headers=headers).json()
    changed = next(o for o in observations if o["change_type"] == "certificate_changed")
    assert changed["previous_value"] == first_fingerprint
    # The original observation is still there -- history preserved, not overwritten.
    assert "certificate_observed" in [o["change_type"] for o in observations]


# --- Authorization / RBAC / org isolation, confirmed for "certificate" ----


def test_certificate_discovery_requires_authorization(client, register_user):
    headers = register_user()
    unauthorized = client.post(
        "/assets", json={"asset_type": "domain", "value": "cert-unauth.example.com"}, headers=headers
    ).json()

    resp = client.post(
        "/discovery/runs",
        json={"seed_asset_id": unauthorized["id"], "provider_name": "certificate"},
        headers=headers,
    )
    assert resp.status_code == 403


def test_viewer_cannot_run_certificate_discovery(client, register_user, login_as, tls_server, monkeypatch):
    server = tls_server("cert-viewer.example.com")
    _point_provider_at(monkeypatch, server)

    admin_headers = register_user(email="cert-org-admin@example.com")
    seed = _create_and_authorize_asset(client, admin_headers, "cert-viewer.example.com")

    viewer_resp = client.post(
        "/users",
        json={
            "email": "cert-viewer@example.com",
            "password": "correct-horse-battery",
            "full_name": "Viewer Person",
            "role": "viewer",
        },
        headers=admin_headers,
    )
    assert viewer_resp.status_code == 201
    viewer_headers = login_as("cert-viewer@example.com", "correct-horse-battery")

    resp = client.post(
        "/discovery/runs",
        json={"seed_asset_id": seed["id"], "provider_name": "certificate"},
        headers=viewer_headers,
    )
    assert resp.status_code == 403


def test_certificate_discovery_results_are_isolated_between_organizations(
    client, register_user, tls_server, monkeypatch
):
    server = tls_server("cert-iso.example.com")
    _point_provider_at(monkeypatch, server)

    org_a_headers = register_user(org_name="Org A", email="cert-iso-a@example.com")
    org_b_headers = register_user(org_name="Org B", email="cert-iso-b@example.com")

    seed = _create_and_authorize_asset(client, org_a_headers, "cert-iso.example.com")
    run = _run_certificate_discovery(client, org_a_headers, seed["id"])

    assert client.get(f"/discovery/runs/{run['id']}", headers=org_b_headers).status_code == 404
    assert client.get(f"/discovery/runs/{run['id']}/results", headers=org_b_headers).status_code == 404
