def _create_asset(client, headers, value, asset_type="domain"):
    resp = client.post("/assets", json={"asset_type": asset_type, "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def test_create_relationship(client, register_user):
    headers = register_user()
    source_id = _create_asset(client, headers, "example.com")
    target_id = _create_asset(client, headers, "93.184.216.34", asset_type="ip_address")

    resp = client.post(
        f"/assets/{source_id}/relationships",
        json={"target_asset_id": target_id, "relationship_type": "resolves_to"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["source_asset_id"] == source_id
    assert body["target_asset_id"] == target_id
    assert body["relationship_type"] == "resolves_to"
    assert body["status"] == "active"
    assert body["confidence"] == 1.0


def test_duplicate_relationship_refreshes_instead_of_duplicating(client, register_user):
    headers = register_user()
    source_id = _create_asset(client, headers, "example.com")
    target_id = _create_asset(client, headers, "93.184.216.34", asset_type="ip_address")
    payload = {"target_asset_id": target_id, "relationship_type": "resolves_to"}

    first = client.post(f"/assets/{source_id}/relationships", json=payload, headers=headers)
    assert first.status_code == 201
    second = client.post(f"/assets/{source_id}/relationships", json=payload, headers=headers)
    assert second.status_code == 201
    assert first.json()["id"] == second.json()["id"]

    listed = client.get(f"/assets/{source_id}/relationships", headers=headers)
    assert len(listed.json()) == 1


def test_self_relationship_rejected(client, register_user):
    headers = register_user()
    asset_id = _create_asset(client, headers, "example.com")

    resp = client.post(
        f"/assets/{asset_id}/relationships",
        json={"target_asset_id": asset_id, "relationship_type": "related_to"},
        headers=headers,
    )
    assert resp.status_code == 400
    listed = client.get(f"/assets/{asset_id}/relationships", headers=headers)
    assert listed.json() == []


def test_relationship_to_another_orgs_asset_is_rejected(client, register_user):
    org_a_headers = register_user(org_name="Org A", email="a-admin@example.com")
    org_b_headers = register_user(org_name="Org B", email="b-admin@example.com")

    source_id = _create_asset(client, org_a_headers, "example.com")
    other_org_asset_id = _create_asset(client, org_b_headers, "example.org")

    resp = client.post(
        f"/assets/{source_id}/relationships",
        json={"target_asset_id": other_org_asset_id, "relationship_type": "related_to"},
        headers=org_a_headers,
    )
    assert resp.status_code == 404


def test_viewer_cannot_create_relationship(client, register_user, login_as):
    admin_headers = register_user(email="rel-org-admin@example.com")
    source_id = _create_asset(client, admin_headers, "example.com")
    target_id = _create_asset(client, admin_headers, "93.184.216.34", asset_type="ip_address")

    viewer_resp = client.post(
        "/users",
        json={
            "email": "rel-viewer@example.com",
            "password": "correct-horse-battery",
            "full_name": "Viewer Person",
            "role": "viewer",
        },
        headers=admin_headers,
    )
    assert viewer_resp.status_code == 201
    viewer_headers = login_as("rel-viewer@example.com", "correct-horse-battery")

    resp = client.post(
        f"/assets/{source_id}/relationships",
        json={"target_asset_id": target_id, "relationship_type": "resolves_to"},
        headers=viewer_headers,
    )
    assert resp.status_code == 403


def test_list_relationships_shows_both_directions(client, register_user):
    headers = register_user()
    a = _create_asset(client, headers, "a.example.com")
    b = _create_asset(client, headers, "b.example.com")
    c = _create_asset(client, headers, "c.example.com")

    client.post(
        f"/assets/{a}/relationships",
        json={"target_asset_id": b, "relationship_type": "related_to"},
        headers=headers,
    )
    client.post(
        f"/assets/{c}/relationships",
        json={"target_asset_id": b, "relationship_type": "related_to"},
        headers=headers,
    )

    resp = client.get(f"/assets/{b}/relationships", headers=headers)
    assert resp.status_code == 200
    relationships = resp.json()
    assert len(relationships) == 2
    endpoints = {(r["source_asset_id"], r["target_asset_id"]) for r in relationships}
    assert (a, b) in endpoints
    assert (c, b) in endpoints


def test_mark_relationship_disappeared_is_soft(client, register_user):
    headers = register_user()
    source_id = _create_asset(client, headers, "example.com")
    target_id = _create_asset(client, headers, "93.184.216.34", asset_type="ip_address")

    created = client.post(
        f"/assets/{source_id}/relationships",
        json={"target_asset_id": target_id, "relationship_type": "resolves_to"},
        headers=headers,
    ).json()

    resp = client.post(
        f"/assets/{source_id}/relationships/{created['id']}/mark-disappeared", headers=headers
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "disappeared"

    # Still present in the list -- soft removal, not a delete.
    listed = client.get(f"/assets/{source_id}/relationships", headers=headers)
    assert len(listed.json()) == 1
    assert listed.json()[0]["status"] == "disappeared"
