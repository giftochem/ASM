"""IDOR/BOLA and privilege-escalation regression tests: a user changing an
ID in an otherwise-valid, correctly-authenticated request must never
reach another organization's resources, and a lower-privileged role must
never reach a higher-privileged endpoint no matter what it's pointed at.
Distinct from the happy-path RBAC tests scattered through the other test
files — this file is specifically about attempts to break the boundary.
"""

from app.core.enums import AssetType, FindingSeverity
from app.scanners.base import ScanFinding, ScanModuleResult


def _confirmed_asset(client, headers, value="example.com"):
    asset = client.post("/assets", json={"asset_type": "domain", "value": value}, headers=headers).json()
    client.post(
        f"/assets/{asset['id']}/confirm-authorization",
        json={"authorization_confirmed": True},
        headers=headers,
    )
    return asset


class _FakeModule:
    name = "whois"
    applicable_asset_types = {AssetType.domain}

    def supports(self, asset_type):
        return asset_type in self.applicable_asset_types

    def run(self, target):
        return ScanModuleResult(
            module=self.name,
            findings=[ScanFinding(title="x", description="y", severity=FindingSeverity.info, confidence=1.0)],
        )


# --- Cross-organization ID substitution (IDOR/BOLA) ---


def test_cannot_read_another_orgs_asset_by_id(client, register_user):
    org_a = register_user(org_name="Org A", email="a@example.com")
    org_b = register_user(org_name="Org B", email="b@example.com")
    asset = _confirmed_asset(client, org_a, "org-a-target.com")

    resp = client.get(f"/assets/{asset['id']}", headers=org_b)
    assert resp.status_code == 404


def test_cannot_confirm_authorization_on_another_orgs_asset(client, register_user):
    org_a = register_user(org_name="Org A", email="a2@example.com")
    org_b = register_user(org_name="Org B", email="b2@example.com")
    asset = client.post(
        "/assets", json={"asset_type": "domain", "value": "org-a-unconfirmed.com"}, headers=org_a
    ).json()

    resp = client.post(
        f"/assets/{asset['id']}/confirm-authorization",
        json={"authorization_confirmed": True},
        headers=org_b,
    )
    assert resp.status_code == 404

    check = client.get(f"/assets/{asset['id']}", headers=org_a).json()
    assert check["authorization_confirmed"] is False


def test_cannot_revoke_authorization_on_another_orgs_asset(client, register_user):
    org_a = register_user(org_name="Org A", email="a3@example.com")
    org_b = register_user(org_name="Org B", email="b3@example.com")
    asset = _confirmed_asset(client, org_a, "org-a-confirmed.com")

    resp = client.post(f"/assets/{asset['id']}/revoke-authorization", json={}, headers=org_b)
    assert resp.status_code == 404

    check = client.get(f"/assets/{asset['id']}", headers=org_a).json()
    assert check["authorization_confirmed"] is True


def test_cannot_cancel_another_orgs_scan(client, register_user, monkeypatch):
    import app.services.scan_service as scan_service_module

    monkeypatch.setattr(scan_service_module, "MODULE_REGISTRY", {"whois": _FakeModule()})
    monkeypatch.setattr(scan_service_module, "get_module", lambda name: _FakeModule() if name == "whois" else None)
    monkeypatch.setattr(scan_service_module, "queue_scan", lambda scan: None)

    org_a = register_user(org_name="Org A", email="a4@example.com")
    org_b = register_user(org_name="Org B", email="b4@example.com")
    asset = _confirmed_asset(client, org_a, "org-a-scan-target.com")
    scan = client.post("/scans", json={"asset_id": asset["id"], "modules": ["whois"]}, headers=org_a).json()
    assert scan["status"] == "queued"

    resp = client.post(f"/scans/{scan['id']}/cancel", headers=org_b)
    assert resp.status_code == 404

    still_queued = client.get(f"/scans/{scan['id']}", headers=org_a).json()
    assert still_queued["status"] == "queued"


def test_cannot_generate_report_against_another_orgs_scan(client, register_user, monkeypatch, eager_celery):
    import app.services.scan_executor as scan_executor_module

    monkeypatch.setattr(scan_executor_module, "get_module", lambda name: _FakeModule())

    org_a = register_user(org_name="Org A", email="a5@example.com")
    org_b = register_user(org_name="Org B", email="b5@example.com")
    asset = _confirmed_asset(client, org_a, "org-a-report-target.com")
    scan = client.post("/scans", json={"asset_id": asset["id"], "modules": ["whois"]}, headers=org_a).json()
    assert scan["status"] == "completed"

    resp = client.post("/reports", json={"scan_id": scan["id"], "format": "json"}, headers=org_b)
    assert resp.status_code == 404


def test_cannot_patch_another_orgs_user(client, register_user):
    org_a = register_user(org_name="Org A", email="a6@example.com")
    org_b = register_user(org_name="Org B", email="b6@example.com")

    org_a_user = client.get("/users/me", headers=org_a).json()

    resp = client.patch(f"/users/{org_a_user['id']}", json={"is_active": False}, headers=org_b)
    assert resp.status_code == 404


def test_audit_logs_are_isolated_between_organizations(client, register_user):
    org_a = register_user(org_name="Org A", email="a7@example.com")
    org_b = register_user(org_name="Org B", email="b7@example.com")

    client.post("/assets", json={"asset_type": "domain", "value": "org-a-audit.com"}, headers=org_a)
    client.post("/assets", json={"asset_type": "domain", "value": "org-b-audit.com"}, headers=org_b)

    org_a_logs = client.get("/audit-logs", headers=org_a).json()
    org_b_logs = client.get("/audit-logs", headers=org_b).json()

    assert any(entry["details"] and entry["details"].get("value") == "org-a-audit.com" for entry in org_a_logs)
    assert not any(
        entry["details"] and entry["details"].get("value") == "org-b-audit.com" for entry in org_a_logs
    )
    assert any(entry["details"] and entry["details"].get("value") == "org-b-audit.com" for entry in org_b_logs)
    assert not any(
        entry["details"] and entry["details"].get("value") == "org-a-audit.com" for entry in org_b_logs
    )


# --- Privilege escalation: role boundaries on the new Phase 3a endpoints ---


def test_viewer_cannot_patch_users(client, register_user, login_as):
    admin = register_user(email="viewer-escalation-admin@example.com")
    client.post(
        "/users",
        json={
            "email": "viewer-escalation@example.com",
            "password": "correct-horse-battery",
            "full_name": "Viewer",
            "role": "viewer",
        },
        headers=admin,
    )
    viewer = login_as("viewer-escalation@example.com", "correct-horse-battery")
    other_user = client.get("/users/me", headers=admin).json()

    resp = client.patch(f"/users/{other_user['id']}", json={"is_active": False}, headers=viewer)
    assert resp.status_code == 403


def test_analyst_cannot_patch_users(client, register_user, login_as):
    admin = register_user(email="analyst-escalation-admin@example.com")
    client.post(
        "/users",
        json={
            "email": "analyst-escalation@example.com",
            "password": "correct-horse-battery",
            "full_name": "Analyst",
            "role": "analyst",
        },
        headers=admin,
    )
    analyst = login_as("analyst-escalation@example.com", "correct-horse-battery")
    other_user = client.get("/users/me", headers=admin).json()

    resp = client.patch(f"/users/{other_user['id']}", json={"role": "admin"}, headers=analyst)
    assert resp.status_code == 403


def test_analyst_cannot_read_audit_logs(client, register_user, login_as):
    """Audit logs are admin-only -- analyst is a write-capable role for
    scans/assets but must not be able to read the org's audit trail.
    """
    admin = register_user(email="analyst-audit-admin@example.com")
    client.post(
        "/users",
        json={
            "email": "analyst-audit@example.com",
            "password": "correct-horse-battery",
            "full_name": "Analyst",
            "role": "analyst",
        },
        headers=admin,
    )
    analyst = login_as("analyst-audit@example.com", "correct-horse-battery")

    resp = client.get("/audit-logs", headers=analyst)
    assert resp.status_code == 403


def test_viewer_cannot_read_audit_logs(client, register_user, login_as):
    admin = register_user(email="viewer-audit-admin@example.com")
    client.post(
        "/users",
        json={
            "email": "viewer-audit@example.com",
            "password": "correct-horse-battery",
            "full_name": "Viewer",
            "role": "viewer",
        },
        headers=admin,
    )
    viewer = login_as("viewer-audit@example.com", "correct-horse-battery")

    resp = client.get("/audit-logs", headers=viewer)
    assert resp.status_code == 403


def test_admin_cannot_modify_own_role_via_patch_endpoint(client, register_user):
    """Self-lockout guard: an admin (even a legitimate one) can't demote
    or deactivate themselves through this endpoint.
    """
    admin = register_user(email="self-lockout@example.com")
    me = client.get("/users/me", headers=admin).json()

    resp = client.patch(f"/users/{me['id']}", json={"is_active": False}, headers=admin)
    assert resp.status_code == 400


def test_viewer_role_field_in_unrelated_request_has_no_effect(client, register_user, login_as):
    """A viewer including a `role` field in a request body it doesn't
    belong in (e.g. trying to smuggle a role change into asset creation)
    must have no effect -- the field simply isn't part of that schema,
    and the request is still blocked by RBAC on its own merits.
    """
    admin = register_user(email="smuggle-admin@example.com")
    client.post(
        "/users",
        json={
            "email": "smuggle-viewer@example.com",
            "password": "correct-horse-battery",
            "full_name": "Viewer",
            "role": "viewer",
        },
        headers=admin,
    )
    viewer = login_as("smuggle-viewer@example.com", "correct-horse-battery")

    resp = client.post(
        "/assets",
        json={"asset_type": "domain", "value": "smuggle.com", "role": "admin"},
        headers=viewer,
    )
    assert resp.status_code == 403  # still blocked by RBAC, extra field is simply ignored

    me = client.get("/users/me", headers=viewer).json()
    assert me["role"] == "viewer"
