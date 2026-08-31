def _create_asset(client, headers, value, asset_type="domain"):
    resp = client.post("/assets", json={"asset_type": asset_type, "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def test_asset_creation_writes_an_observation(client, register_user):
    headers = register_user()
    asset_id = _create_asset(client, headers, "example.com")

    resp = client.get(f"/assets/{asset_id}/observations", headers=headers)
    assert resp.status_code == 200
    observations = resp.json()
    assert len(observations) == 1
    assert observations[0]["change_type"] == "asset_created"
    assert observations[0]["current_value"] == "example.com"


def test_relationship_creation_and_removal_write_observations(client, register_user):
    headers = register_user()
    source_id = _create_asset(client, headers, "example.com")
    target_id = _create_asset(client, headers, "93.184.216.34", asset_type="ip_address")

    relationship = client.post(
        f"/assets/{source_id}/relationships",
        json={"target_asset_id": target_id, "relationship_type": "resolves_to"},
        headers=headers,
    ).json()

    observations = client.get(f"/assets/{source_id}/observations", headers=headers).json()
    change_types = [o["change_type"] for o in observations]
    assert "asset_created" in change_types
    assert "relationship_created" in change_types

    client.post(
        f"/assets/{source_id}/relationships/{relationship['id']}/mark-disappeared", headers=headers
    )
    observations = client.get(f"/assets/{source_id}/observations", headers=headers).json()
    assert "relationship_removed" in [o["change_type"] for o in observations]


def test_observations_ordered_newest_first(client, register_user):
    headers = register_user()
    source_id = _create_asset(client, headers, "example.com")
    target_id = _create_asset(client, headers, "93.184.216.34", asset_type="ip_address")

    client.post(
        f"/assets/{source_id}/relationships",
        json={"target_asset_id": target_id, "relationship_type": "resolves_to"},
        headers=headers,
    )

    observations = client.get(f"/assets/{source_id}/observations", headers=headers).json()
    timestamps = [o["observed_at"] for o in observations]
    assert timestamps == sorted(timestamps, reverse=True)
    # Most recent event (the relationship) should be first, the asset's
    # own creation last.
    assert observations[0]["change_type"] == "relationship_created"
    assert observations[-1]["change_type"] == "asset_created"


def test_observations_are_isolated_between_organizations(client, register_user):
    org_a_headers = register_user(org_name="Org A", email="obs-a-admin@example.com")
    org_b_headers = register_user(org_name="Org B", email="obs-b-admin@example.com")

    asset_id = _create_asset(client, org_a_headers, "example.com")

    resp = client.get(f"/assets/{asset_id}/observations", headers=org_b_headers)
    assert resp.status_code == 404
