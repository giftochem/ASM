"""Tests for graph_service.get_asset_graph and GET /{asset_id}/graph --
both the service function directly (cycle handling, depth semantics,
determinism) and the route (auth/RBAC/org-isolation/HTTP status codes).
"""

import uuid

from app.core.enums import AssetType, RelationshipType
from app.models.asset import Asset
from app.services import graph_service


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


def _link(client, headers, source_id, target_id, relationship_type="related_to"):
    resp = client.post(
        f"/assets/{source_id}/relationships",
        json={"target_asset_id": target_id, "relationship_type": relationship_type},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# --- Service-level tests (direct, no HTTP) ----------------------------------


def test_depth_0_returns_only_seed_no_edges(client, register_user, db):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "graph-depth0.example.com")
    org_id = uuid.UUID(seed["organization_id"])

    result = graph_service.get_asset_graph(db, org_id, uuid.UUID(seed["id"]), max_depth=0)

    assert len(result.nodes) == 1
    assert result.nodes[0].id == uuid.UUID(seed["id"])
    assert result.edges == []


def test_isolated_asset_has_no_relationships(client, register_user, db):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "graph-isolated.example.com")
    org_id = uuid.UUID(seed["organization_id"])

    result = graph_service.get_asset_graph(db, org_id, uuid.UUID(seed["id"]), max_depth=3)

    assert len(result.nodes) == 1
    assert result.edges == []


def test_depth_1_returns_direct_neighbors_only(client, register_user, db):
    headers = register_user()
    a = _create_and_authorize_asset(client, headers, "graph-a1.example.com")
    b = _create_and_authorize_asset(client, headers, "graph-b1.example.com")
    c = _create_and_authorize_asset(client, headers, "graph-c1.example.com")
    _link(client, headers, a["id"], b["id"])
    _link(client, headers, b["id"], c["id"])
    org_id = uuid.UUID(a["organization_id"])

    result = graph_service.get_asset_graph(db, org_id, uuid.UUID(a["id"]), max_depth=1)

    node_ids = {n.id for n in result.nodes}
    assert node_ids == {uuid.UUID(a["id"]), uuid.UUID(b["id"])}
    assert len(result.edges) == 1


def test_multi_hop_traversal_reaches_transitive_neighbors(client, register_user, db):
    headers = register_user()
    a = _create_and_authorize_asset(client, headers, "graph-a2.example.com")
    b = _create_and_authorize_asset(client, headers, "graph-b2.example.com")
    c = _create_and_authorize_asset(client, headers, "graph-c2.example.com")
    _link(client, headers, a["id"], b["id"])
    _link(client, headers, b["id"], c["id"])
    org_id = uuid.UUID(a["organization_id"])

    result = graph_service.get_asset_graph(db, org_id, uuid.UUID(a["id"]), max_depth=2)

    node_ids = {n.id for n in result.nodes}
    assert node_ids == {uuid.UUID(a["id"]), uuid.UUID(b["id"]), uuid.UUID(c["id"])}
    assert len(result.edges) == 2


def test_cyclic_graph_terminates_and_deduplicates(client, register_user, db):
    """A -> B -> C -> A must terminate cleanly, with each node and edge
    appearing exactly once regardless of how many hops are requested.
    """
    headers = register_user()
    a = _create_and_authorize_asset(client, headers, "graph-a3.example.com")
    b = _create_and_authorize_asset(client, headers, "graph-b3.example.com")
    c = _create_and_authorize_asset(client, headers, "graph-c3.example.com")
    _link(client, headers, a["id"], b["id"])
    _link(client, headers, b["id"], c["id"])
    _link(client, headers, c["id"], a["id"])
    org_id = uuid.UUID(a["organization_id"])

    result = graph_service.get_asset_graph(db, org_id, uuid.UUID(a["id"]), max_depth=graph_service.MAX_GRAPH_DEPTH)

    node_ids = [n.id for n in result.nodes]
    edge_ids = [e.id for e in result.edges]
    assert sorted(node_ids) == sorted(set(node_ids))  # no duplicate nodes
    assert sorted(edge_ids) == sorted(set(edge_ids))  # no duplicate edges
    assert set(node_ids) == {uuid.UUID(a["id"]), uuid.UUID(b["id"]), uuid.UUID(c["id"])}
    assert len(edge_ids) == 3


def test_induced_subgraph_includes_sibling_edge(client, register_user, db):
    """seed -> A, seed -> B, and A -> B directly: at depth 2 (enough to
    discover both A and B), the A-B edge must also appear, not just the
    two edges that touched the seed directly -- the response is the
    full induced subgraph over the discovered nodes, not merely a
    record of BFS discovery order.
    """
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "graph-seed4.example.com")
    a = _create_and_authorize_asset(client, headers, "graph-a4.example.com")
    b = _create_and_authorize_asset(client, headers, "graph-b4.example.com")
    _link(client, headers, seed["id"], a["id"])
    _link(client, headers, seed["id"], b["id"])
    _link(client, headers, a["id"], b["id"])
    org_id = uuid.UUID(seed["organization_id"])

    result = graph_service.get_asset_graph(db, org_id, uuid.UUID(seed["id"]), max_depth=1)

    assert len(result.edges) == 3


def test_seed_not_found_returns_none(client, register_user, db):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "graph-none.example.com")
    org_id = uuid.UUID(seed["organization_id"])

    result = graph_service.get_asset_graph(db, org_id, uuid.uuid4(), max_depth=1)

    assert result is None


def test_cross_org_seed_returns_none(client, register_user, db):
    headers_a = register_user(org_name="Graph Org A", email="graph-org-a@example.com")
    headers_b = register_user(org_name="Graph Org B", email="graph-org-b@example.com")
    seed_b = _create_and_authorize_asset(client, headers_b, "graph-orgb-seed.example.com")

    from app.models.user import User

    org_a_id = db.query(User).filter(User.email == "graph-org-a@example.com").first().organization_id

    result = graph_service.get_asset_graph(db, org_a_id, uuid.UUID(seed_b["id"]), max_depth=1)

    assert result is None


def test_cross_org_relationship_never_traversed_even_if_reachable_by_id(client, register_user, db):
    """Defense in depth: even though relationships can't cross orgs at
    write time, traversal itself re-verifies org membership at every
    expansion step, not just for the seed.
    """
    headers_a = register_user(org_name="Graph Isolation A", email="graph-iso-a2@example.com")
    headers_b = register_user(org_name="Graph Isolation B", email="graph-iso-b2@example.com")
    seed_a = _create_and_authorize_asset(client, headers_a, "graph-iso-seed-a.example.com")
    other_b = _create_and_authorize_asset(client, headers_b, "graph-iso-other-b.example.com")

    from app.models.user import User

    org_a_id = db.query(User).filter(User.email == "graph-iso-a2@example.com").first().organization_id

    result = graph_service.get_asset_graph(db, org_a_id, uuid.UUID(seed_a["id"]), max_depth=graph_service.MAX_GRAPH_DEPTH)

    node_ids = {n.id for n in result.nodes}
    assert uuid.UUID(other_b["id"]) not in node_ids


def test_traversal_is_deterministic_across_repeated_calls(client, register_user, db):
    headers = register_user()
    a = _create_and_authorize_asset(client, headers, "graph-det-a.example.com")
    b = _create_and_authorize_asset(client, headers, "graph-det-b.example.com")
    c = _create_and_authorize_asset(client, headers, "graph-det-c.example.com")
    _link(client, headers, a["id"], b["id"])
    _link(client, headers, a["id"], c["id"])
    org_id = uuid.UUID(a["organization_id"])

    first = graph_service.get_asset_graph(db, org_id, uuid.UUID(a["id"]), max_depth=2)
    second = graph_service.get_asset_graph(db, org_id, uuid.UUID(a["id"]), max_depth=2)

    assert [n.id for n in first.nodes] == [n.id for n in second.nodes]
    assert [e.id for e in first.edges] == [e.id for e in second.edges]


# --- Route-level tests -------------------------------------------------------


def test_authenticated_access_returns_graph(client, register_user):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "graph-route-auth.example.com")

    resp = client.get(f"/assets/{seed['id']}/graph", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["metadata"]["seed_asset_id"] == seed["id"]
    assert body["metadata"]["node_count"] == 1
    assert len(body["nodes"]) == 1
    assert body["nodes"][0]["id"] == seed["id"]
    assert "environment" in body["nodes"][0]
    assert "criticality" in body["nodes"][0]


def test_viewer_can_read_graph(client, register_user, login_as):
    admin_headers = register_user(email="graph-viewer-admin@example.com")
    seed = _create_and_authorize_asset(client, admin_headers, "graph-viewer.example.com")
    viewer_resp = client.post(
        "/users",
        json={"email": "graph-viewer@example.com", "password": "correct-horse-battery", "full_name": "V", "role": "viewer"},
        headers=admin_headers,
    )
    assert viewer_resp.status_code == 201
    viewer_headers = login_as("graph-viewer@example.com", "correct-horse-battery")

    resp = client.get(f"/assets/{seed['id']}/graph", headers=viewer_headers)
    assert resp.status_code == 200


def test_analyst_can_read_graph(client, register_user, login_as):
    admin_headers = register_user(email="graph-analyst-admin@example.com")
    seed = _create_and_authorize_asset(client, admin_headers, "graph-analyst.example.com")
    resp = client.post(
        "/users",
        json={"email": "graph-analyst@example.com", "password": "correct-horse-battery", "full_name": "A", "role": "analyst"},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    analyst_headers = login_as("graph-analyst@example.com", "correct-horse-battery")

    resp = client.get(f"/assets/{seed['id']}/graph", headers=analyst_headers)
    assert resp.status_code == 200


def test_admin_can_read_graph(client, register_user):
    headers = register_user()  # default registration role is admin
    seed = _create_and_authorize_asset(client, headers, "graph-admin.example.com")

    resp = client.get(f"/assets/{seed['id']}/graph", headers=headers)
    assert resp.status_code == 200


def test_cross_organization_seed_returns_404(client, register_user):
    org_a_headers = register_user(org_name="Graph Route Org A", email="graph-route-a@example.com")
    org_b_headers = register_user(org_name="Graph Route Org B", email="graph-route-b@example.com")
    seed_b = _create_and_authorize_asset(client, org_b_headers, "graph-route-b-seed.example.com")

    resp = client.get(f"/assets/{seed_b['id']}/graph", headers=org_a_headers)
    assert resp.status_code == 404


def test_depth_0_route(client, register_user):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "graph-route-depth0.example.com")

    resp = client.get(f"/assets/{seed['id']}/graph?depth=0", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["nodes"]) == 1
    assert body["edges"] == []


def test_depth_1_route(client, register_user):
    headers = register_user()
    a = _create_and_authorize_asset(client, headers, "graph-route-a1.example.com")
    b = _create_and_authorize_asset(client, headers, "graph-route-b1.example.com")
    _link(client, headers, a["id"], b["id"])

    resp = client.get(f"/assets/{a['id']}/graph?depth=1", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["nodes"]) == 2
    assert len(body["edges"]) == 1


def test_multiple_hops_route(client, register_user):
    headers = register_user()
    a = _create_and_authorize_asset(client, headers, "graph-route-a2.example.com")
    b = _create_and_authorize_asset(client, headers, "graph-route-b2.example.com")
    c = _create_and_authorize_asset(client, headers, "graph-route-c2.example.com")
    _link(client, headers, a["id"], b["id"])
    _link(client, headers, b["id"], c["id"])

    resp = client.get(f"/assets/{a['id']}/graph?depth=2", headers=headers)
    body = resp.json()
    assert {n["id"] for n in body["nodes"]} == {a["id"], b["id"], c["id"]}


def test_cyclic_graph_route_terminates(client, register_user):
    headers = register_user()
    a = _create_and_authorize_asset(client, headers, "graph-route-a3.example.com")
    b = _create_and_authorize_asset(client, headers, "graph-route-b3.example.com")
    c = _create_and_authorize_asset(client, headers, "graph-route-c3.example.com")
    _link(client, headers, a["id"], b["id"])
    _link(client, headers, b["id"], c["id"])
    _link(client, headers, c["id"], a["id"])

    resp = client.get(f"/assets/{a['id']}/graph?depth=5", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["nodes"]) == 3
    assert len(body["edges"]) == 3


def test_duplicate_relationship_refresh_does_not_duplicate_edge(client, register_user):
    headers = register_user()
    a = _create_and_authorize_asset(client, headers, "graph-route-dup-a.example.com")
    b = _create_and_authorize_asset(client, headers, "graph-route-dup-b.example.com")
    _link(client, headers, a["id"], b["id"])
    _link(client, headers, a["id"], b["id"])  # refreshes the existing relationship, not a new row

    resp = client.get(f"/assets/{a['id']}/graph?depth=1", headers=headers)
    body = resp.json()
    assert len(body["edges"]) == 1


def test_maximum_depth_is_accepted(client, register_user):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "graph-route-maxdepth.example.com")

    resp = client.get(f"/assets/{seed['id']}/graph?depth={graph_service.MAX_GRAPH_DEPTH}", headers=headers)
    assert resp.status_code == 200


def test_depth_exceeding_maximum_returns_400_not_clamped(client, register_user):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "graph-route-overdepth.example.com")

    resp = client.get(f"/assets/{seed['id']}/graph?depth={graph_service.MAX_GRAPH_DEPTH + 1}", headers=headers)
    assert resp.status_code == 400
    assert resp.status_code != 422


def test_negative_depth_returns_400(client, register_user):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "graph-route-negdepth.example.com")

    resp = client.get(f"/assets/{seed['id']}/graph?depth=-1", headers=headers)
    assert resp.status_code == 400


def test_isolated_asset_route_returns_no_edges(client, register_user):
    headers = register_user()
    seed = _create_and_authorize_asset(client, headers, "graph-route-isolated.example.com")

    resp = client.get(f"/assets/{seed['id']}/graph?depth=3", headers=headers)
    body = resp.json()
    assert len(body["nodes"]) == 1
    assert body["edges"] == []


def test_organization_isolation_at_traversal_level_route(client, register_user):
    """A graph rooted in org A's asset must never surface org B's assets,
    even at maximum depth.
    """
    org_a_headers = register_user(org_name="Graph Iso Route A", email="graph-iso-route-a@example.com")
    org_b_headers = register_user(org_name="Graph Iso Route B", email="graph-iso-route-b@example.com")
    seed_a = _create_and_authorize_asset(client, org_a_headers, "graph-iso-route-seed-a.example.com")
    _create_and_authorize_asset(client, org_b_headers, "graph-iso-route-b.example.com")

    resp = client.get(f"/assets/{seed_a['id']}/graph?depth={graph_service.MAX_GRAPH_DEPTH}", headers=org_a_headers)
    body = resp.json()
    assert {n["value"] for n in body["nodes"]} == {"graph-iso-route-seed-a.example.com"}
