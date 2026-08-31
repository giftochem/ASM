from app.core.enums import AssetType, FindingSeverity
from app.scanners.base import ScanFinding, ScanModuleResult, ScannerModule


class FakeModule(ScannerModule):
    """Stands in for a real scanner module in tests so the suite never
    makes outbound WHOIS/DNS/TLS network calls.
    """

    name = "fake"
    applicable_asset_types = {AssetType.domain}

    def run(self, target: str) -> ScanModuleResult:
        return ScanModuleResult(
            module=self.name,
            findings=[
                ScanFinding(
                    title="Fake finding",
                    description=f"Fake result for {target}",
                    severity=FindingSeverity.medium,
                    confidence=1.0,
                )
            ],
        )


def _patch_fake_module(monkeypatch):
    """validate_scan_request (scan_service) and execute_scan
    (scan_executor) each import get_module/MODULE_REGISTRY from
    app.scanners.registry independently, binding their own local names —
    both need patching for the fake module to be visible end to end.
    """
    import app.services.scan_executor as scan_executor_module
    import app.services.scan_service as scan_service_module

    fake_lookup = lambda name: FakeModule() if name == "fake" else None  # noqa: E731
    monkeypatch.setattr(scan_service_module, "MODULE_REGISTRY", {"fake": FakeModule()})
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


def test_scan_blocked_without_authorization(client, register_user):
    headers = register_user()
    asset = client.post(
        "/assets", json={"asset_type": "domain", "value": "example.com"}, headers=headers
    ).json()

    resp = client.post("/scans", json={"asset_id": asset["id"]}, headers=headers)
    assert resp.status_code == 403
    assert "authorization_confirmed" in resp.json()["detail"]


def test_scan_runs_after_authorization_confirmed(client, register_user, monkeypatch, eager_celery):
    _patch_fake_module(monkeypatch)

    headers = register_user()
    asset = _create_and_confirm_asset(client, headers)

    resp = client.post(
        "/scans", json={"asset_id": asset["id"], "modules": ["fake"]}, headers=headers
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "completed"
    assert body["modules_requested"] == ["fake"]
    assert len(body["findings"]) == 1
    assert body["findings"][0]["title"] == "Fake finding"


def test_scan_without_eager_mode_starts_queued(client, register_user, monkeypatch):
    """Without eager mode, POST /scans reflects real async behavior: the
    scan is created and queued, but not yet executed by the time the
    response is built (task_always_eager defaults to False).
    """
    _patch_fake_module(monkeypatch)

    headers = register_user()
    asset = _create_and_confirm_asset(client, headers)

    def _noop_queue(scan):
        pass  # don't actually try to talk to a real broker in this test

    import app.services.scan_service as scan_service_module

    monkeypatch.setattr(scan_service_module, "queue_scan", _noop_queue)

    resp = client.post(
        "/scans", json={"asset_id": asset["id"], "modules": ["fake"]}, headers=headers
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "queued"
    assert body["findings"] == []


def test_scan_rejects_unknown_module(client, register_user, monkeypatch):
    _patch_fake_module(monkeypatch)

    headers = register_user()
    asset = _create_and_confirm_asset(client, headers)

    resp = client.post(
        "/scans", json={"asset_id": asset["id"], "modules": ["does-not-exist"]}, headers=headers
    )
    assert resp.status_code == 400


def test_scan_of_nonexistent_asset_is_404(client, register_user):
    headers = register_user()
    resp = client.post(
        "/scans",
        json={"asset_id": "00000000-0000-0000-0000-000000000000"},
        headers=headers,
    )
    assert resp.status_code == 404


def test_viewer_cannot_trigger_scan(client, register_user, login_as):
    admin_headers = register_user(email="scan-org-admin@example.com")
    asset = _create_and_confirm_asset(client, admin_headers)

    client.post(
        "/users",
        json={
            "email": "scan-viewer@example.com",
            "password": "correct-horse-battery",
            "full_name": "Viewer Person",
            "role": "viewer",
        },
        headers=admin_headers,
    )
    viewer_headers = login_as("scan-viewer@example.com", "correct-horse-battery")

    resp = client.post("/scans", json={"asset_id": asset["id"]}, headers=viewer_headers)
    assert resp.status_code == 403


def test_cancel_queued_scan(client, register_user, monkeypatch):
    _patch_fake_module(monkeypatch)

    def _noop_queue(scan):
        pass

    import app.services.scan_service as scan_service_module

    monkeypatch.setattr(scan_service_module, "queue_scan", _noop_queue)

    headers = register_user()
    asset = _create_and_confirm_asset(client, headers)
    scan = client.post(
        "/scans", json={"asset_id": asset["id"], "modules": ["fake"]}, headers=headers
    ).json()
    assert scan["status"] == "queued"

    cancel_resp = client.post(f"/scans/{scan['id']}/cancel", headers=headers)
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["status"] == "cancelled"


def test_cancel_non_queued_scan_is_rejected(client, register_user, monkeypatch, eager_celery):
    _patch_fake_module(monkeypatch)

    headers = register_user()
    asset = _create_and_confirm_asset(client, headers)
    scan = client.post(
        "/scans", json={"asset_id": asset["id"], "modules": ["fake"]}, headers=headers
    ).json()
    assert scan["status"] == "completed"

    cancel_resp = client.post(f"/scans/{scan['id']}/cancel", headers=headers)
    assert cancel_resp.status_code == 409


def test_list_scans_filter_by_asset_id(client, register_user, monkeypatch, eager_celery):
    _patch_fake_module(monkeypatch)

    headers = register_user()
    asset_1 = _create_and_confirm_asset(client, headers, value="asset-one.example.com")
    scan_1 = client.post(
        "/scans", json={"asset_id": asset_1["id"], "modules": ["fake"]}, headers=headers
    ).json()

    asset_2 = _create_and_confirm_asset(client, headers, value="asset-two.example.com")
    client.post("/scans", json={"asset_id": asset_2["id"], "modules": ["fake"]}, headers=headers)

    resp = client.get("/scans", params={"asset_id": asset_1["id"]}, headers=headers)
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 1
    assert results[0]["id"] == scan_1["id"]


def test_list_scans_without_filter_returns_all_org_scans(client, register_user, monkeypatch, eager_celery):
    _patch_fake_module(monkeypatch)

    headers = register_user()
    asset_1 = _create_and_confirm_asset(client, headers, value="asset-a.example.com")
    client.post("/scans", json={"asset_id": asset_1["id"], "modules": ["fake"]}, headers=headers)

    asset_2 = _create_and_confirm_asset(client, headers, value="asset-b.example.com")
    client.post("/scans", json={"asset_id": asset_2["id"], "modules": ["fake"]}, headers=headers)

    resp = client.get("/scans", headers=headers)
    assert resp.status_code == 200
    assert len(resp.json()) == 2


def test_list_scans_asset_id_filter_is_org_scoped(client, register_user, monkeypatch, eager_celery):
    """A caller cannot use ?asset_id= to probe another org's scans — the
    Asset.organization_id join filter applies before the asset_id filter,
    so a foreign asset_id simply yields an empty (not 403/404) result,
    consistent with never revealing whether the ID exists elsewhere.
    """
    _patch_fake_module(monkeypatch)

    org_a = register_user(org_name="Scan Org A", email="scan-org-a-admin@example.com")
    asset_a = _create_and_confirm_asset(client, org_a, value="org-a-scan.example.com")
    client.post("/scans", json={"asset_id": asset_a["id"], "modules": ["fake"]}, headers=org_a)

    org_b = register_user(org_name="Scan Org B", email="scan-org-b-admin@example.com")

    resp = client.get("/scans", params={"asset_id": asset_a["id"]}, headers=org_b)
    assert resp.status_code == 200
    assert resp.json() == []
