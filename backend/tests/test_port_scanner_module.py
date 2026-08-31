from app.core.enums import AssetType
from app.models.port_scan_result import PortScanResult
from app.scanners.port_scanner_module import PortScannerModule
from app.scanners.registry import MODULE_REGISTRY
from app.services import scan_service

_PUBLIC_IP = "93.184.216.34"  # literal IP -> resolve_and_validate needs no real DNS


def test_port_scanner_requires_explicit_opt_in():
    module = MODULE_REGISTRY["port_scanner"]
    assert module.requires_explicit_opt_in is True


def test_port_scanner_only_applies_to_ip_address():
    module = PortScannerModule()
    assert module.applicable_asset_types == {AssetType.ip_address}
    assert not module.supports(AssetType.ip_range)
    assert not module.supports(AssetType.domain)


def test_default_scan_resolution_excludes_port_scanner(db):
    from app.models.asset import Asset

    # validate_scan_request only needs authorization_confirmed + asset_type;
    # build a minimal in-memory Asset without persisting it.
    asset = Asset(organization_id=None, asset_type=AssetType.ip_address, value=_PUBLIC_IP)
    asset.authorization_confirmed = True
    resolved = scan_service.validate_scan_request(asset, None)
    assert "port_scanner" not in resolved


def test_explicit_request_for_port_scanner_is_honored():
    from app.models.asset import Asset

    asset = Asset(organization_id=None, asset_type=AssetType.ip_address, value=_PUBLIC_IP)
    asset.authorization_confirmed = True
    resolved = scan_service.validate_scan_request(asset, ["port_scanner"])
    assert resolved == ["port_scanner"]


def test_port_scanner_rejected_for_domain_asset_type():
    from app.models.asset import Asset

    asset = Asset(organization_id=None, asset_type=AssetType.domain, value="example.com")
    asset.authorization_confirmed = True
    try:
        scan_service.validate_scan_request(asset, ["port_scanner"])
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "port_scanner" in str(exc)


def test_run_reports_open_closed_and_filtered_states(monkeypatch):
    def fake_probe(ip, port):
        return {80: "open", 443: "open", 8080: "closed", 8443: "filtered"}.get(port, "closed")

    monkeypatch.setattr("app.scanners.port_scanner_module._probe", fake_probe)

    result = PortScannerModule().run(_PUBLIC_IP)
    assert result.error is None

    states = {p["port"]: p["state"] for p in result.raw_data["ports"]}
    assert states[80] == "open"
    assert states[443] == "open"
    assert states[8080] == "closed"
    assert states[8443] == "filtered"

    open_port_findings = [f for f in result.findings if f.title.startswith("Open port")]
    assert {f.evidence["port"] for f in open_port_findings} == {80, 443}
    # Never critical/high -- an open port alone is a low-severity observation.
    assert all(f.severity.value in ("info", "low") for f in result.findings)


def test_run_blocks_private_target_even_if_directly_invoked(monkeypatch):
    """Defense in depth: even though asset creation already rejects
    private IPs (app.core.validation), the module itself must not blindly
    trust whatever string it's given.
    """

    def fail_if_called(ip, port):
        raise AssertionError("must never actually probe a blocked target")

    monkeypatch.setattr("app.scanners.port_scanner_module._probe", fail_if_called)

    result = PortScannerModule().run("10.0.0.5")
    assert result.error is not None
    assert "blocked" in result.error.lower()
    assert result.findings == []


def test_full_scan_pipeline_persists_port_scan_results(client, register_user, db, monkeypatch, eager_celery):
    def fake_probe(ip, port):
        return "open" if port == 443 else "closed"

    monkeypatch.setattr("app.scanners.port_scanner_module._probe", fake_probe)

    headers = register_user()
    asset = client.post(
        "/assets", json={"asset_type": "ip_address", "value": _PUBLIC_IP}, headers=headers
    ).json()
    client.post(
        f"/assets/{asset['id']}/confirm-authorization",
        json={"authorization_confirmed": True},
        headers=headers,
    )

    scan_resp = client.post(
        "/scans", json={"asset_id": asset["id"], "modules": ["port_scanner"]}, headers=headers
    )
    assert scan_resp.status_code == 201
    scan = scan_resp.json()
    assert scan["status"] == "completed"

    results = db.query(PortScanResult).filter(PortScanResult.scan_id == scan["id"]).all()
    assert len(results) > 0
    open_results = [r for r in results if r.state == "open"]
    assert {r.port for r in open_results} == {443}
