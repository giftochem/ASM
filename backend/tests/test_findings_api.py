from app.core.enums import AssetType, FindingSeverity
from app.scanners.base import ScanFinding, ScanModuleResult, ScannerModule


class FakeModule(ScannerModule):
    """Same fake-module pattern as test_scan_pipeline.py — avoids real
    network calls while still exercising the full create-asset -> run-scan
    -> persist-findings pipeline that GET /findings reads from.
    """

    name = "fake"
    applicable_asset_types = {AssetType.domain}

    def __init__(self, severity: FindingSeverity = FindingSeverity.medium, title: str = "Fake finding"):
        self.severity = severity
        self.title = title

    def run(self, target: str) -> ScanModuleResult:
        return ScanModuleResult(
            module=self.name,
            findings=[
                ScanFinding(
                    title=self.title,
                    description=f"Fake result for {target}",
                    severity=self.severity,
                    confidence=1.0,
                )
            ],
        )


def _patch_fake_module(monkeypatch, module: FakeModule):
    import app.services.scan_executor as scan_executor_module
    import app.services.scan_service as scan_service_module

    fake_lookup = lambda name: module if name == "fake" else None  # noqa: E731
    monkeypatch.setattr(scan_service_module, "MODULE_REGISTRY", {"fake": module})
    monkeypatch.setattr(scan_service_module, "get_module", fake_lookup)
    monkeypatch.setattr(scan_executor_module, "get_module", fake_lookup)


def _create_and_confirm_asset(client, headers, value="example.com"):
    asset = client.post(
        "/assets", json={"asset_type": "domain", "value": value}, headers=headers
    ).json()
    client.post(
        f"/assets/{asset['id']}/confirm-authorization",
        json={"authorization_confirmed": True},
        headers=headers,
    )
    return asset


def _run_scan(client, headers, asset_id, monkeypatch, eager_celery, severity=FindingSeverity.medium, title="Fake finding"):
    _patch_fake_module(monkeypatch, FakeModule(severity=severity, title=title))
    resp = client.post(
        "/scans", json={"asset_id": asset_id, "modules": ["fake"]}, headers=headers
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_findings_are_org_scoped(client, register_user, monkeypatch, eager_celery):
    org_a = register_user(org_name="Org A", email="org-a-admin@example.com")
    asset_a = _create_and_confirm_asset(client, org_a, value="org-a.example.com")
    _run_scan(client, org_a, asset_a["id"], monkeypatch, eager_celery)

    org_b = register_user(org_name="Org B", email="org-b-admin@example.com")
    asset_b = _create_and_confirm_asset(client, org_b, value="org-b.example.com")
    _run_scan(client, org_b, asset_b["id"], monkeypatch, eager_celery)

    resp_a = client.get("/findings", headers=org_a)
    assert resp_a.status_code == 200
    assert len(resp_a.json()) == 1
    assert resp_a.json()[0]["asset_id"] == asset_a["id"]

    resp_b = client.get("/findings", headers=org_b)
    assert resp_b.status_code == 200
    assert len(resp_b.json()) == 1
    assert resp_b.json()[0]["asset_id"] == asset_b["id"]


def test_findings_filter_by_severity(client, register_user, monkeypatch, eager_celery):
    headers = register_user()

    asset_med = _create_and_confirm_asset(client, headers, value="medium.example.com")
    _run_scan(client, headers, asset_med["id"], monkeypatch, eager_celery, severity=FindingSeverity.medium)

    asset_crit = _create_and_confirm_asset(client, headers, value="critical.example.com")
    _run_scan(client, headers, asset_crit["id"], monkeypatch, eager_celery, severity=FindingSeverity.critical)

    resp = client.get("/findings", params={"severity": "critical"}, headers=headers)
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 1
    assert results[0]["severity"] == "critical"


def test_findings_filter_by_module(client, register_user, monkeypatch, eager_celery):
    headers = register_user()
    asset = _create_and_confirm_asset(client, headers)
    _run_scan(client, headers, asset["id"], monkeypatch, eager_celery)

    resp = client.get("/findings", params={"module": "fake"}, headers=headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 1

    resp_none = client.get("/findings", params={"module": "nonexistent-module"}, headers=headers)
    assert resp_none.status_code == 200
    assert resp_none.json() == []


def test_findings_filter_by_asset_id(client, register_user, monkeypatch, eager_celery):
    headers = register_user()
    asset_1 = _create_and_confirm_asset(client, headers, value="one.example.com")
    _run_scan(client, headers, asset_1["id"], monkeypatch, eager_celery)

    asset_2 = _create_and_confirm_asset(client, headers, value="two.example.com")
    _run_scan(client, headers, asset_2["id"], monkeypatch, eager_celery)

    resp = client.get("/findings", params={"asset_id": asset_1["id"]}, headers=headers)
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 1
    assert results[0]["asset_id"] == asset_1["id"]


def test_findings_filter_by_scan_id(client, register_user, monkeypatch, eager_celery):
    headers = register_user()
    asset = _create_and_confirm_asset(client, headers)
    scan = _run_scan(client, headers, asset["id"], monkeypatch, eager_celery)

    resp = client.get("/findings", params={"scan_id": scan["id"]}, headers=headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    assert resp.json()[0]["scan_id"] == scan["id"]

    other_scan_id = "00000000-0000-0000-0000-000000000000"
    resp_none = client.get("/findings", params={"scan_id": other_scan_id}, headers=headers)
    assert resp_none.status_code == 200
    assert resp_none.json() == []


def test_findings_pagination(client, register_user, monkeypatch, eager_celery):
    headers = register_user()
    for i in range(3):
        asset = _create_and_confirm_asset(client, headers, value=f"host{i}.example.com")
        _run_scan(client, headers, asset["id"], monkeypatch, eager_celery, title=f"Finding {i}")

    resp_all = client.get("/findings", headers=headers)
    assert resp_all.status_code == 200
    assert len(resp_all.json()) == 3

    resp_page = client.get("/findings", params={"limit": 2, "offset": 0}, headers=headers)
    assert resp_page.status_code == 200
    assert len(resp_page.json()) == 2

    resp_rest = client.get("/findings", params={"limit": 2, "offset": 2}, headers=headers)
    assert resp_rest.status_code == 200
    assert len(resp_rest.json()) == 1


def test_findings_pagination_rejects_limit_over_500(client, register_user):
    headers = register_user()
    resp = client.get("/findings", params={"limit": 501}, headers=headers)
    assert resp.status_code == 422


def test_viewer_role_can_read_findings(client, register_user, monkeypatch, eager_celery, login_as):
    admin = register_user(email="findings-viewer-admin@example.com")
    asset = _create_and_confirm_asset(client, admin)
    _run_scan(client, admin, asset["id"], monkeypatch, eager_celery)

    client.post(
        "/users",
        json={
            "email": "findings-viewer@example.com",
            "password": "correct-horse-battery",
            "full_name": "Viewer",
            "role": "viewer",
        },
        headers=admin,
    )
    viewer = login_as("findings-viewer@example.com", "correct-horse-battery")

    resp = client.get("/findings", headers=viewer)
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_findings_requires_authentication(client):
    resp = client.get("/findings")
    assert resp.status_code == 401
