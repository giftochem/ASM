import pytest


def test_create_asset_and_confirm_authorization(client, register_user):
    headers = register_user()

    create_resp = client.post(
        "/assets", json={"asset_type": "domain", "value": "Example.com"}, headers=headers
    )
    assert create_resp.status_code == 201
    asset = create_resp.json()
    # normalized to lowercase
    assert asset["value"] == "example.com"
    assert asset["authorization_confirmed"] is False

    confirm_resp = client.post(
        f"/assets/{asset['id']}/confirm-authorization",
        json={"authorization_confirmed": True, "attestation_note": "engagement #123"},
        headers=headers,
    )
    assert confirm_resp.status_code == 200
    confirmed = confirm_resp.json()
    assert confirmed["authorization_confirmed"] is True
    assert confirmed["authorization_confirmed_by"] is not None
    assert confirmed["authorization_confirmed_at"] is not None


def test_confirm_authorization_requires_true(client, register_user):
    headers = register_user()
    asset = client.post(
        "/assets", json={"asset_type": "domain", "value": "example.com"}, headers=headers
    ).json()

    resp = client.post(
        f"/assets/{asset['id']}/confirm-authorization",
        json={"authorization_confirmed": False},
        headers=headers,
    )
    assert resp.status_code == 400


def test_duplicate_asset_rejected(client, register_user):
    headers = register_user()
    payload = {"asset_type": "domain", "value": "example.com"}
    first = client.post("/assets", json=payload, headers=headers)
    assert first.status_code == 201
    second = client.post("/assets", json=payload, headers=headers)
    assert second.status_code == 409


def test_invalid_domain_value_rejected(client, register_user):
    headers = register_user()
    resp = client.post(
        "/assets", json={"asset_type": "domain", "value": "not a domain!"}, headers=headers
    )
    assert resp.status_code == 422


def test_oversized_ip_range_rejected(client, register_user):
    headers = register_user()
    resp = client.post(
        "/assets", json={"asset_type": "ip_range", "value": "10.0.0.0/8"}, headers=headers
    )
    assert resp.status_code == 422


def test_viewer_cannot_create_asset(client, register_user, login_as):
    admin_headers = register_user(email="viewer-org-admin@example.com")
    viewer_resp = client.post(
        "/users",
        json={
            "email": "viewer@example.com",
            "password": "correct-horse-battery",
            "full_name": "Viewer Person",
            "role": "viewer",
        },
        headers=admin_headers,
    )
    assert viewer_resp.status_code == 201

    viewer_headers = login_as("viewer@example.com", "correct-horse-battery")

    resp = client.post(
        "/assets", json={"asset_type": "domain", "value": "example.com"}, headers=viewer_headers
    )
    assert resp.status_code == 403


def test_assets_are_isolated_between_organizations(client, register_user):
    org_a_headers = register_user(org_name="Org A", email="a-admin@example.com")
    org_b_headers = register_user(org_name="Org B", email="b-admin@example.com")

    asset = client.post(
        "/assets", json={"asset_type": "domain", "value": "example.com"}, headers=org_a_headers
    ).json()

    resp = client.get(f"/assets/{asset['id']}", headers=org_b_headers)
    assert resp.status_code == 404


def test_created_asset_exposes_intelligence_defaults(client, register_user):
    headers = register_user()
    asset = client.post(
        "/assets", json={"asset_type": "domain", "value": "example.com"}, headers=headers
    ).json()

    assert asset["status"] == "active"
    assert asset["source"] == "manual"
    assert asset["confidence"] == 1.0
    assert asset["environment"] is None
    assert asset["criticality"] is None
    assert asset["owner"] is None
    assert asset["tags"] == []
    assert asset["first_seen"] is not None
    assert asset["last_seen"] is not None


@pytest.mark.parametrize(
    "asset_type,value",
    [
        ("asn", "AS15169"),
        ("http_endpoint", "https://api.example.com/v1"),
        ("api", "stripe-api"),
        ("cloud_resource", "AWS"),
        ("repository", "https://github.com/example/repo"),
    ],
)
def test_newly_creatable_asset_types_succeed(client, register_user, asset_type, value):
    headers = register_user(email=f"{asset_type}@example.com")
    resp = client.post("/assets", json={"asset_type": asset_type, "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    assert resp.json()["asset_type"] == asset_type


def test_asn_normalizes_bare_number(client, register_user):
    headers = register_user()
    resp = client.post("/assets", json={"asset_type": "asn", "value": "15169"}, headers=headers)
    assert resp.status_code == 201
    assert resp.json()["value"] == "AS15169"


@pytest.mark.parametrize(
    "asset_type",
    ["service", "tls_certificate", "web3_contract", "web3_program", "web3_token", "web3_wallet", "rpc_endpoint"],
)
def test_reserved_asset_types_are_not_yet_creatable(client, register_user, asset_type):
    headers = register_user(email=f"reserved-{asset_type}@example.com")
    resp = client.post("/assets", json={"asset_type": asset_type, "value": "placeholder"}, headers=headers)
    assert resp.status_code == 422
