from app.core.enums import FindingSeverity
from app.scanners.base import ScanFinding, ScanModuleResult
from app.scanners.registry import MODULE_REGISTRY


class _FakeWhois:
    name = "whois"
    applicable_asset_types = MODULE_REGISTRY["whois"].applicable_asset_types

    def supports(self, asset_type):
        return asset_type in self.applicable_asset_types

    def run(self, target):
        return ScanModuleResult(
            module=self.name,
            findings=[
                ScanFinding(
                    title="Domain registration expiring soon",
                    description="expires in 6 days",
                    severity=FindingSeverity.medium,
                    confidence=0.9,
                    exposure=1.0,
                    exploitability=0.3,
                )
            ],
        )


def _create_confirmed_asset_and_completed_scan(client, headers, monkeypatch):
    import app.services.scan_executor as scan_executor_module

    monkeypatch.setattr(scan_executor_module, "get_module", lambda name: _FakeWhois())

    asset = client.post(
        "/assets", json={"asset_type": "domain", "value": "example.com"}, headers=headers
    ).json()
    client.post(
        f"/assets/{asset['id']}/confirm-authorization",
        json={"authorization_confirmed": True},
        headers=headers,
    )
    scan = client.post(
        "/scans", json={"asset_id": asset["id"], "modules": ["whois"]}, headers=headers
    ).json()
    assert scan["status"] == "completed", scan
    return asset, scan


def test_generate_and_download_json_report(client, register_user, monkeypatch, eager_celery):
    headers = register_user()
    _, scan = _create_confirmed_asset_and_completed_scan(client, headers, monkeypatch)

    create_resp = client.post(
        "/reports", json={"scan_id": scan["id"], "format": "json"}, headers=headers
    )
    assert create_resp.status_code == 201, create_resp.text
    report = create_resp.json()
    assert report["status"] == "completed"
    assert report["storage_path"] is not None

    download_resp = client.get(f"/reports/{report['id']}/download", headers=headers)
    assert download_resp.status_code == 200
    assert download_resp.headers["content-type"].startswith("application/json")
    body = download_resp.json()
    assert body["asset"]["value"] == "example.com"
    assert body["risk_summary"]["risk_score"] is not None


def test_generate_and_download_csv_report(client, register_user, monkeypatch, eager_celery):
    headers = register_user()
    _, scan = _create_confirmed_asset_and_completed_scan(client, headers, monkeypatch)

    create_resp = client.post(
        "/reports", json={"scan_id": scan["id"], "format": "csv"}, headers=headers
    )
    assert create_resp.status_code == 201
    report = create_resp.json()

    download_resp = client.get(f"/reports/{report['id']}/download", headers=headers)
    assert download_resp.status_code == 200
    assert download_resp.headers["content-type"].startswith("text/csv")
    assert b"# Executive Summary" in download_resp.content


def test_generate_and_download_pdf_report(client, register_user, monkeypatch, eager_celery):
    headers = register_user()
    _, scan = _create_confirmed_asset_and_completed_scan(client, headers, monkeypatch)

    create_resp = client.post(
        "/reports", json={"scan_id": scan["id"], "format": "pdf"}, headers=headers
    )
    assert create_resp.status_code == 201
    report = create_resp.json()

    download_resp = client.get(f"/reports/{report['id']}/download", headers=headers)
    assert download_resp.status_code == 200
    assert download_resp.headers["content-type"] == "application/pdf"
    assert download_resp.content.startswith(b"%PDF-")


def test_viewer_can_download_but_not_generate_report(client, register_user, login_as, monkeypatch, eager_celery):
    admin_headers = register_user(email="report-admin@example.com")
    _, scan = _create_confirmed_asset_and_completed_scan(client, admin_headers, monkeypatch)

    report = client.post(
        "/reports", json={"scan_id": scan["id"], "format": "json"}, headers=admin_headers
    ).json()

    client.post(
        "/users",
        json={
            "email": "report-viewer@example.com",
            "password": "correct-horse-battery",
            "full_name": "Viewer",
            "role": "viewer",
        },
        headers=admin_headers,
    )
    viewer_headers = login_as("report-viewer@example.com", "correct-horse-battery")

    generate_resp = client.post(
        "/reports", json={"scan_id": scan["id"], "format": "csv"}, headers=viewer_headers
    )
    assert generate_resp.status_code == 403

    download_resp = client.get(f"/reports/{report['id']}/download", headers=viewer_headers)
    assert download_resp.status_code == 200


def test_reports_are_isolated_between_organizations(client, register_user, monkeypatch, eager_celery):
    org_a_headers = register_user(org_name="Org A", email="a-admin@example.com")
    _, scan_a = _create_confirmed_asset_and_completed_scan(client, org_a_headers, monkeypatch)
    report_a = client.post(
        "/reports", json={"scan_id": scan_a["id"], "format": "json"}, headers=org_a_headers
    ).json()

    org_b_headers = register_user(org_name="Org B", email="b-admin@example.com")
    resp = client.get(f"/reports/{report_a['id']}", headers=org_b_headers)
    assert resp.status_code == 404
