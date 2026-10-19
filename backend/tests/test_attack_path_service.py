"""Stage B: the Exposure Path Engine (app.services.attack_path_service).
Synthetic rows only, assessed at the fixed AS_OF."""

import socket
from datetime import timedelta

import pytest
from sqlalchemy import event

from app.core.enums import AssetCriticality, AssetSource, AssetType, ChangeType, LifecycleStatus, RelationshipType
from app.models.asset import Asset
from app.models.audit_log import AuditLog
from app.models.discovery_run import DiscoveryRun
from app.models.observation import Observation
from app.models.scan import Scan
from app.services import attack_path_service as engine
from app.services import relationship_traversal_rules as rules
from app.services.attack_path_service import NOT_ASSESSED, PathBasis, PathLimits, StepBasis
from app.services.exposure_evidence_service import EvidenceType
from tests.attack_path_fixtures import (
    AS_OF,
    ago,
    analyst_link,
    certificate_row,
    dns_result,
    http_result,
    make_asset,
    make_org,
    make_scan,
    observation,
    observed_dns,
    port_result,
    relate,
    tls_result,
)
from tests.conftest import test_engine

CRITICAL = {"criticality": AssetCriticality.critical}
HIGH = {"criticality": AssetCriticality.high}


@pytest.fixture
def org(db):
    return make_org(db, "Path Org")


def _find(db, org_row, **limits):
    return engine.find_exposure_paths(db, org_row.id, as_of=AS_OF, limits=PathLimits(**limits))


def _summary(result):
    return [([node.value for node in path.nodes], path.basis.value) for path in result.paths]


def _exposed(db, org_row, user, asset, *, at=None):
    """Current HTTP evidence (the http provider's stored shape)."""
    return http_result(db, org_row, user, asset, "https", at=at or ago(days=1))


# --- 1-3. Targets and zero-hop paths ---------------------------------------------------


def test_exposed_high_asset_is_a_zero_hop_path(db, org):
    org_row, user = org
    app = make_asset(db, org_row, "app.example.com", **HIGH)
    evidence = _exposed(db, org_row, user, app)

    result = _find(db, org_row)

    (path,) = result.paths
    assert path.is_zero_hop and path.hop_count == 0 and path.steps == ()
    assert path.basis is PathBasis.direct_exposure
    assert path.entry_point == path.target and path.target.criticality == "high"
    (item,) = path.entry_evidence
    assert item.evidence_type is EvidenceType.http_response and item.result_id == evidence.id
    assert path.interpretation.startswith("Observed exposure:") and path.interpretation.endswith(NOT_ASSESSED)
    assert path.limitations[0] == NOT_ASSESSED


def test_exposed_critical_asset_is_a_zero_hop_path(db, org):
    org_row, user = org
    api = make_asset(db, org_row, "api.example.com", **CRITICAL)
    tls_result(db, org_row, user, api, at=ago(days=2))

    (path,) = _find(db, org_row).paths

    assert path.is_zero_hop and path.target.criticality == "critical"
    assert [e.evidence_type for e in path.entry_evidence] == [EvidenceType.tls_handshake]


@pytest.mark.parametrize("criticality", [AssetCriticality.low, AssetCriticality.medium, None])
def test_exposed_asset_below_high_is_not_a_target(db, org, criticality):
    org_row, user = org
    site = make_asset(db, org_row, "site.example.com", criticality=criticality)
    _exposed(db, org_row, user, site)

    result = _find(db, org_row)

    assert result.paths == () and result.eligible_target_count == 0 and not result.truncated


# --- 4-5. One-hop and multi-hop ---------------------------------------------------------


def test_one_hop_observed_dns_path(db, org):
    org_row, user = org
    site = make_asset(db, org_row, "www.example.com")
    database = make_asset(db, org_row, "198.51.100.10", AssetType.ip_address, **CRITICAL)
    _exposed(db, org_row, user, site)
    relationship = observed_dns(db, org_row, user, site, database, at=ago(days=1))

    (path,) = _find(db, org_row).paths

    assert _summary(_find(db, org_row)) == [(["www.example.com", "198.51.100.10"], "observed_dns_association")]
    (step,) = path.steps
    assert step.relationship_id == relationship.id and step.direction == "forward"
    assert step.basis is StepBasis.observed_dns_association and step.provenance.source == "discovery"
    assert step.provenance.dns_evidence.observed_at == ago(days=1)
    assert path.interpretation.startswith("Observed infrastructure association")
    assert "does not show that compromise" in path.interpretation
    assert any("name-to-address association only" in limitation for limitation in path.limitations)


def test_multi_hop_mixed_path(db, org):
    org_row, user = org
    edge_ip = make_asset(db, org_row, "198.51.100.20", AssetType.ip_address, authorization_confirmed=True)
    app = make_asset(db, org_row, "app.example.com")
    backend = make_asset(db, org_row, "backend.app.example.com", AssetType.subdomain, **CRITICAL)
    port_result(db, make_scan(db, user, edge_ip, ["port_scanner"], completed_at=ago(days=1)), 443, "open")
    hosts = analyst_link(db, org_row, user, edge_ip, app, RelationshipType.hosts)
    cname = observed_dns(db, org_row, user, app, backend, record_type="CNAME")

    (path,) = _find(db, org_row).paths

    assert [node.value for node in path.nodes] == ["198.51.100.20", "app.example.com", "backend.app.example.com"]
    assert [step.relationship_id for step in path.steps] == [hosts.id, cname.id]
    assert [step.basis for step in path.steps] == [StepBasis.analyst_asserted, StepBasis.observed_dns_association]
    assert path.basis is PathBasis.observed_dns_and_analyst_asserted and path.hop_count == 2
    assert path.steps[0].provenance.audit_log_id is not None
    assert [e.evidence_type for e in path.entry_evidence] == [EvidenceType.open_port]


def test_three_hop_path_and_hop_limit(db, org):
    org_row, user = org
    entry = make_asset(db, org_row, "entry.example.com")
    alias = make_asset(db, org_row, "alias.example.com", AssetType.subdomain)
    host_ip = make_asset(db, org_row, "198.51.100.30", AssetType.ip_address)
    vault = make_asset(db, org_row, "vault.internal.example.com", AssetType.subdomain, **CRITICAL)
    _exposed(db, org_row, user, entry)
    observed_dns(db, org_row, user, entry, alias, record_type="CNAME")
    observed_dns(db, org_row, user, alias, host_ip)
    analyst_link(db, org_row, user, host_ip, vault, RelationshipType.hosts)

    assert _summary(_find(db, org_row)) == [
        (["entry.example.com", "alias.example.com", "198.51.100.30", "vault.internal.example.com"],
         "observed_dns_and_analyst_asserted")
    ]
    # Paths are defined as at most max_hops long: a shorter limit simply
    # finds none here, and that isn't a truncation.
    shorter = _find(db, org_row, max_hops=2)
    assert shorter.paths == () and not shorter.truncated


def test_analyst_only_path_is_labeled_as_an_assertion(db, org):
    org_row, user = org
    edge = make_asset(db, org_row, "edge.example.com")
    payroll = make_asset(db, org_row, "payroll.example.com", **HIGH)
    _exposed(db, org_row, user, edge)
    analyst_link(db, org_row, user, edge, payroll, RelationshipType.exposes)

    (path,) = _find(db, org_row).paths

    assert path.basis is PathBasis.analyst_asserted
    assert path.interpretation.startswith("Analyst-asserted path")
    assert any("analyst-asserted relationships" in limitation for limitation in path.limitations)


# --- 6-7. Direction and entry evidence -------------------------------------------------


def test_reverse_only_relationship_gives_no_path(db, org):
    org_row, user = org
    crown = make_asset(db, org_row, "crown.example.com", **CRITICAL)
    exposed_ip = make_asset(db, org_row, "198.51.100.40", AssetType.ip_address, authorization_confirmed=True)
    port_result(db, make_scan(db, user, exposed_ip, ["port_scanner"], completed_at=ago(days=1)), 22, "open")
    observed_dns(db, org_row, user, crown, exposed_ip)  # crown -> ip: following it from the ip would be reverse

    result = _find(db, org_row)

    assert result.paths == () and result.entry_point_count == 0  # the ip isn't even reached as a predecessor


def test_dns_only_asset_is_not_an_entry_point(db, org):
    org_row, user = org
    named = make_asset(db, org_row, "named.example.com")
    database = make_asset(db, org_row, "198.51.100.41", AssetType.ip_address, **CRITICAL)
    observation(db, named, ChangeType.dns_records_observed, at=ago(hours=3), field_name="dns_metadata")
    certificate_row(db, named, at=ago(hours=3))
    observed_dns(db, org_row, user, named, database)

    result = _find(db, org_row)

    assert result.paths == () and result.entry_point_count == 0 and result.examined_node_count == 2


# --- 8-11. Freshness ------------------------------------------------------------------------


def test_stale_http_and_tls_exposure_is_rejected(db, org):
    org_row, user = org
    old = make_asset(db, org_row, "old.example.com", **CRITICAL)
    http_result(db, org_row, user, old, "https", at=ago(days=8))
    tls_result(db, org_row, user, old, at=ago(days=10))

    assert _find(db, org_row).paths == ()


def test_stale_dns_evidence_is_rejected(db, org):
    org_row, user = org
    site = make_asset(db, org_row, "site-stale-dns.example.com")
    database = make_asset(db, org_row, "198.51.100.42", AssetType.ip_address, **CRITICAL)
    _exposed(db, org_row, user, site)
    relationship = observed_dns(db, org_row, user, site, database, at=ago(days=8))  # still active

    assert _find(db, org_row).paths == ()
    (decision,) = rules.evaluate_forward_traversals(
        db, org_row.id, [relationship], as_of=AS_OF, dns_freshness_window=engine.FRESHNESS_WINDOW
    )
    assert not decision.allowed and decision.rule == "dns_evidence_stale"


def test_dns_freshness_boundary_is_seven_days(db, org):
    org_row, user = org
    site = make_asset(db, org_row, "edge-of-window.example.com")
    inside = make_asset(db, org_row, "198.51.100.43", AssetType.ip_address, **CRITICAL)
    outside = make_asset(db, org_row, "198.51.100.44", AssetType.ip_address, **CRITICAL)
    _exposed(db, org_row, user, site)
    observed_dns(db, org_row, user, site, inside, at=AS_OF - timedelta(days=7))
    observed_dns(db, org_row, user, site, outside, at=AS_OF - timedelta(days=7, seconds=1))

    assert [path.target.value for path in _find(db, org_row).paths] == ["198.51.100.43"]


def test_fresh_dns_evidence_is_accepted_and_newer_evidence_after_as_of_ignored(db, org):
    org_row, user = org
    site = make_asset(db, org_row, "point-in-time.example.com")
    database = make_asset(db, org_row, "198.51.100.45", AssetType.ip_address, **CRITICAL)
    _exposed(db, org_row, user, site)
    fresh = dns_result(db, org_row, user, site, database, at=ago(days=2))
    dns_result(db, org_row, user, site, database, at=AS_OF + timedelta(hours=1))  # after the assessment time
    relate(db, site, database, RelationshipType.resolves_to)

    (path,) = _find(db, org_row).paths

    assert path.steps[0].provenance.dns_evidence.result_id == fresh.id


def test_manual_dns_relationship_is_rejected(db, org):
    org_row, user = org
    site = make_asset(db, org_row, "asserted.example.com")
    database = make_asset(db, org_row, "198.51.100.46", AssetType.ip_address, **CRITICAL)
    _exposed(db, org_row, user, site)
    analyst_link(db, org_row, user, site, database, RelationshipType.resolves_to)

    assert _find(db, org_row).paths == ()


# --- 12-16. False positives and isolation --------------------------------------------------


def test_shared_ip_never_connects_unrelated_domains(db, org):
    org_row, user = org
    tenant_a = make_asset(db, org_row, "tenant-a.example.com")
    tenant_b = make_asset(db, org_row, "tenant-b.example.com", **CRITICAL)
    shared_ip = make_asset(db, org_row, "198.51.100.50", AssetType.ip_address)
    _exposed(db, org_row, user, tenant_a)
    observed_dns(db, org_row, user, tenant_a, shared_ip)
    observed_dns(db, org_row, user, tenant_b, shared_ip)

    result = _find(db, org_row)

    assert result.paths == ()
    assert result.examined_node_count == 1  # nothing points INTO tenant-b in its permitted direction


@pytest.mark.parametrize(
    "relationship_type",
    [t for t in RelationshipType if t not in (RelationshipType.resolves_to, RelationshipType.hosts, RelationshipType.exposes)],
    ids=lambda t: t.value,
)
def test_unsupported_relationship_types_are_never_paths(db, org, relationship_type):
    org_row, user = org
    site = make_asset(db, org_row, "linked.example.com")
    crown = make_asset(db, org_row, "crown-jewel.example.com", AssetType.subdomain, **CRITICAL)
    _exposed(db, org_row, user, site)
    analyst_link(db, org_row, user, site, crown, relationship_type)  # even analyst-entered with provenance

    result = _find(db, org_row)

    assert result.paths == () and result.evaluated_relationship_count == 1 and result.examined_node_count == 1


def test_shared_certificate_asn_and_cloud_links_are_not_paths(db, org):
    org_row, user = org
    site = make_asset(db, org_row, "shared-cert.example.com")
    peer = make_asset(db, org_row, "peer.example.com", AssetType.subdomain, **CRITICAL)
    ip = make_asset(db, org_row, "198.51.100.51", AssetType.ip_address)
    asn = make_asset(db, org_row, "AS64500", AssetType.asn, **CRITICAL)
    cloud = make_asset(db, org_row, "cloud-account-1", AssetType.cloud_resource, **CRITICAL)
    _exposed(db, org_row, user, site)
    port_result(db, make_scan(db, user, ip, ["port_scanner"], completed_at=ago(days=1)), 443, "open")
    relate(db, site, peer, RelationshipType.related_to)  # certificate SAN co-occurrence
    relate(db, ip, asn, RelationshipType.announced_by)
    relate(db, site, cloud, RelationshipType.deployed_on)

    assert _find(db, org_row).paths == ()


@pytest.mark.parametrize("where", ["intermediate", "entry", "relationship"])
def test_disappeared_or_deactivated_elements_break_paths(db, org, where):
    org_row, user = org
    entry = make_asset(db, org_row, "entry-x.example.com", is_active=where != "entry")
    alias = make_asset(db, org_row, "alias-x.example.com", AssetType.subdomain,
                       status=LifecycleStatus.disappeared if where == "intermediate" else LifecycleStatus.active)
    database = make_asset(db, org_row, "198.51.100.52", AssetType.ip_address, **CRITICAL)
    _exposed(db, org_row, user, entry)
    observed_dns(db, org_row, user, entry, alias, record_type="CNAME",
                 status=LifecycleStatus.disappeared if where == "relationship" else LifecycleStatus.active)
    observed_dns(db, org_row, user, alias, database)

    assert _find(db, org_row).paths == ()


@pytest.mark.parametrize("fields", [{"status": LifecycleStatus.disappeared}, {"is_active": False}])
def test_disappeared_or_deactivated_targets_are_not_targets(db, org, fields):
    org_row, user = org
    gone = make_asset(db, org_row, "gone.example.com", **CRITICAL, **fields)
    _exposed(db, org_row, user, gone)

    result = _find(db, org_row)

    assert result.paths == () and result.eligible_target_count == 0


def test_cross_organization_edges_are_rejected(db, org):
    org_row, user = org
    other_org, other_user = make_org(db, "Other Path Org")
    their_site = make_asset(db, other_org, "their-site.example.com")
    _exposed(db, other_org, other_user, their_site)
    my_database = make_asset(db, org_row, "198.51.100.53", AssetType.ip_address, **CRITICAL)
    # A tampered cross-organization row (the service layer refuses these),
    # even with DNS evidence recorded in either organization.
    dns_result(db, other_org, other_user, their_site, my_database)
    dns_result(db, org_row, user, their_site, my_database)
    relate(db, their_site, my_database, RelationshipType.resolves_to)

    mine = _find(db, org_row)
    theirs = engine.find_exposure_paths(db, other_org.id, as_of=AS_OF)

    assert mine.paths == () and mine.examined_node_count == 1 and mine.evaluated_relationship_count == 1
    assert theirs.paths == () and theirs.eligible_target_count == 0


def test_cross_organization_evidence_is_rejected(db, org):
    org_row, user = org
    other_org, other_user = make_org(db, "Evidence Elsewhere Org")
    site = make_asset(db, org_row, "evidence-elsewhere.example.com")
    database = make_asset(db, org_row, "198.51.100.54", AssetType.ip_address, **CRITICAL)
    crown = make_asset(db, org_row, "crown-elsewhere.example.com", **CRITICAL)
    # Exposure evidence for `crown` and DNS evidence for site -> database,
    # both recorded under the other organization's runs.
    http_result(db, other_org, other_user, crown, "https", at=ago(days=1))
    _exposed(db, org_row, user, site)
    dns_result(db, other_org, other_user, site, database)
    relate(db, site, database, RelationshipType.resolves_to)

    assert _find(db, org_row).paths == ()


# --- 17-19. Cycles, multiple entry points and targets ---------------------------------------


def test_cycles_are_handled_without_repeating_assets(db, org):
    org_row, user = org
    entry = make_asset(db, org_row, "loop-entry.example.com")
    alias = make_asset(db, org_row, "loop-alias.example.com", AssetType.subdomain)
    database = make_asset(db, org_row, "198.51.100.60", AssetType.ip_address, **CRITICAL)
    _exposed(db, org_row, user, entry)
    observed_dns(db, org_row, user, entry, alias, record_type="CNAME")
    observed_dns(db, org_row, user, alias, entry, record_type="CNAME")  # alias -> entry closes a loop
    observed_dns(db, org_row, user, alias, database)
    observed_dns(db, org_row, user, entry, database)  # without the repeat check: entry -> alias -> entry -> database
    analyst_link(db, org_row, user, database, entry, RelationshipType.hosts)  # and a loop through the target

    result = _find(db, org_row)

    assert _summary(result) == [
        (["loop-entry.example.com", "198.51.100.60"], "observed_dns_association"),
        (["loop-entry.example.com", "loop-alias.example.com", "198.51.100.60"], "observed_dns_association"),
    ]
    for path in result.paths:
        assert len({node.asset_id for node in path.nodes}) == len(path.nodes)


def test_multiple_entry_points_to_one_target(db, org):
    org_row, user = org
    database = make_asset(db, org_row, "198.51.100.61", AssetType.ip_address, **CRITICAL)
    for name in ("zeta.example.com", "alpha.example.com"):
        site = make_asset(db, org_row, name)
        _exposed(db, org_row, user, site)
        observed_dns(db, org_row, user, site, database)

    result = _find(db, org_row)

    assert [path.entry_point.value for path in result.paths] == ["alpha.example.com", "zeta.example.com"]
    assert result.entry_point_count == 2


def test_multiple_targets_are_ordered_critical_first_then_by_hops(db, org):
    org_row, user = org
    high_app = make_asset(db, org_row, "a-high.example.com", **HIGH)
    _exposed(db, org_row, user, high_app)
    site = make_asset(db, org_row, "site-mt.example.com")
    database = make_asset(db, org_row, "198.51.100.62", AssetType.ip_address, **CRITICAL)
    _exposed(db, org_row, user, site)
    observed_dns(db, org_row, user, site, database)

    result = _find(db, org_row)

    assert [(path.target.value, path.hop_count) for path in result.paths] == [
        ("198.51.100.62", 1),  # critical first, even though longer
        ("a-high.example.com", 0),
    ]


# --- 20. Bounds, truncation and determinism --------------------------------------------------


def test_target_limit_truncates_and_says_so(db, org):
    org_row, user = org
    for name in ("c.example.com", "a.example.com", "b.example.com"):
        _exposed(db, org_row, user, make_asset(db, org_row, name, **CRITICAL))

    result = _find(db, org_row, max_targets=2)

    assert [path.target.value for path in result.paths] == ["a.example.com", "b.example.com"]
    assert result.truncated and [t.limit for t in result.truncations] == ["max_targets"]
    assert result.eligible_target_count == 3 and result.examined_target_count == 2


def test_path_limit_truncates_to_a_prefix_of_the_order(db, org):
    org_row, user = org
    database = make_asset(db, org_row, "198.51.100.63", AssetType.ip_address, **CRITICAL)
    for name in ("s3.example.com", "s1.example.com", "s2.example.com"):
        site = make_asset(db, org_row, name)
        _exposed(db, org_row, user, site)
        observed_dns(db, org_row, user, site, database)

    full = _find(db, org_row)
    limited = _find(db, org_row, max_paths=2)

    assert [path.entry_point.value for path in limited.paths] == ["s1.example.com", "s2.example.com"]
    assert limited.paths == full.paths[:2]
    assert limited.truncated and [t.limit for t in limited.truncations] == ["max_paths"] and not full.truncated


def test_node_limit_stops_the_search_and_says_so(db, org):
    org_row, user = org
    database = make_asset(db, org_row, "198.51.100.64", AssetType.ip_address, **CRITICAL)
    for name in ("n3.example.com", "n1.example.com", "n2.example.com"):
        site = make_asset(db, org_row, name)
        _exposed(db, org_row, user, site)
        observed_dns(db, org_row, user, site, database)

    result = _find(db, org_row, max_nodes=2)

    assert result.examined_node_count == 2
    assert [path.entry_point.value for path in result.paths] == ["n1.example.com"]
    assert result.truncated and "max_nodes" in [t.limit for t in result.truncations]


def test_relationship_and_expansion_budgets_stop_cleanly(db, org, monkeypatch):
    org_row, user = org
    database = make_asset(db, org_row, "198.51.100.65", AssetType.ip_address, **CRITICAL)
    for name in ("r1.example.com", "r2.example.com", "r3.example.com"):
        site = make_asset(db, org_row, name)
        _exposed(db, org_row, user, site)
        observed_dns(db, org_row, user, site, database)

    monkeypatch.setattr(engine, "MAX_RELATIONSHIPS", 2)
    by_relationships = _find(db, org_row)
    monkeypatch.setattr(engine, "MAX_RELATIONSHIPS", 2_000)
    monkeypatch.setattr(engine, "MAX_PATH_EXPANSIONS", 1)
    by_expansions = _find(db, org_row)

    assert by_relationships.evaluated_relationship_count == 2 and len(by_relationships.paths) == 2
    assert [t.limit for t in by_relationships.truncations] == ["relationship_budget"]
    assert by_expansions.paths == ()  # the target isn't exposed itself; every path needs an expansion
    assert [t.limit for t in by_expansions.truncations] == ["expansion_budget"]


@pytest.mark.parametrize(
    "limits",
    [{"max_hops": -1}, {"max_hops": 4}, {"max_targets": 0}, {"max_targets": 26}, {"max_paths": 0},
     {"max_paths": 101}, {"max_nodes": 0}, {"max_nodes": 501}],
)
def test_invalid_limits_are_rejected(db, org, limits):
    org_row, _ = org
    with pytest.raises(ValueError, match="must be between"):
        engine.find_exposure_paths(db, org_row.id, as_of=AS_OF, limits=PathLimits(**limits))


def test_results_are_deterministic_whatever_the_insertion_order(db):
    def build(name, order):
        org_row, user = make_org(db, name)
        database = make_asset(db, org_row, "198.51.100.66", AssetType.ip_address, **CRITICAL)
        app = make_asset(db, org_row, "app-det.example.com", **HIGH)
        _exposed(db, org_row, user, app)
        for value in order:
            site = make_asset(db, org_row, value)
            _exposed(db, org_row, user, site)
            observed_dns(db, org_row, user, site, database)
        return org_row

    forward = build("Det Org A", ["d1.example.com", "d2.example.com", "d3.example.com"])
    backward = build("Det Org B", ["d3.example.com", "d2.example.com", "d1.example.com"])

    first, again = engine.find_exposure_paths(db, forward.id, as_of=AS_OF), engine.find_exposure_paths(db, forward.id, as_of=AS_OF)
    other = engine.find_exposure_paths(db, backward.id, as_of=AS_OF)

    assert first == again
    assert _summary(first) == _summary(other) == [
        (["d1.example.com", "198.51.100.66"], "observed_dns_association"),
        (["d2.example.com", "198.51.100.66"], "observed_dns_association"),
        (["d3.example.com", "198.51.100.66"], "observed_dns_association"),
        (["app-det.example.com"], "direct_exposure"),
    ]


# --- 24-28. Safety, empty cases, interpretation, ties, efficiency -------------------------------


def test_engine_is_read_only_and_offline(db, org, monkeypatch):
    org_row, user = org
    site = make_asset(db, org_row, "offline-path.example.com")
    database = make_asset(db, org_row, "198.51.100.67", AssetType.ip_address, **CRITICAL)
    _exposed(db, org_row, user, site)
    observed_dns(db, org_row, user, site, database)
    db.commit()

    def counts():
        return [db.query(model).count() for model in (Asset, DiscoveryRun, Scan, Observation, AuditLog)]

    before = counts()

    def refuse(*args, **kwargs):
        raise AssertionError("the path engine attempted network access")

    for name in ("create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, refuse)

    result = _find(db, org_row)

    assert len(result.paths) == 1 and counts() == before and not db.new and not db.dirty


def test_empty_organization_and_no_path_cases(db, org):
    org_row, user = org
    empty = _find(db, org_row)
    assert empty.paths == () and empty.eligible_target_count == 0 and empty.examined_node_count == 0
    assert not empty.truncated and empty.entry_point_count == 0

    make_asset(db, org_row, "unexposed-crown.example.com", **CRITICAL)
    unreached = _find(db, org_row)
    assert unreached.paths == () and unreached.eligible_target_count == 1 and unreached.entry_point_count == 0


def test_every_path_carries_the_interpretation_limits(db, org):
    org_row, user = org
    app = make_asset(db, org_row, "every.example.com", **HIGH)
    site = make_asset(db, org_row, "every-site.example.com")
    database = make_asset(db, org_row, "198.51.100.68", AssetType.ip_address, **CRITICAL)
    for asset in (app, site):
        _exposed(db, org_row, user, asset)
    observed_dns(db, org_row, user, site, database)

    result = _find(db, org_row)

    assert engine.DISCLAIMER == "Observed exposure paths; exploitability not assessed."
    assert len(result.paths) == 2
    for path in result.paths:
        assert path.limitations[0] == NOT_ASSESSED and NOT_ASSESSED in path.interpretation
    assert any("current stored values" in limitation for limitation in result.limitations)


def test_same_time_evidence_orders_deterministically(db, org):
    org_row, user = org
    database = make_asset(db, org_row, "198.51.100.69", AssetType.ip_address, **CRITICAL)
    same_time = ago(days=1)
    for name in ("tie-b.example.com", "tie-a.example.com"):
        site = make_asset(db, org_row, name)
        http_result(db, org_row, user, site, "https", at=same_time)
        first = dns_result(db, org_row, user, site, database, at=same_time)
        second = dns_result(db, org_row, user, site, database, at=same_time)
        relate(db, site, database, RelationshipType.resolves_to)
        expected = max((first.id, second.id), key=str)
        if name == "tie-a.example.com":
            expected_a = expected

    result = _find(db, org_row)

    assert [path.entry_point.value for path in result.paths] == ["tie-a.example.com", "tie-b.example.com"]
    assert result.paths[0].steps[0].provenance.dns_evidence.result_id == expected_a
    assert _find(db, org_row) == result


def test_query_count_does_not_grow_with_graph_size(db, org):
    org_row, user = org

    def build_and_count(prefix: str, size: int) -> int:
        database = make_asset(db, org_row, f"198.51.{100 + size}.70", AssetType.ip_address, **CRITICAL)
        for index in range(size):
            site = make_asset(db, org_row, f"{prefix}-{index}.example.com")
            _exposed(db, org_row, user, site)
            observed_dns(db, org_row, user, site, database)
        db.flush()
        counts = {"n": 0}

        def on_execute(*args, **kwargs):
            counts["n"] += 1

        event.listen(test_engine, "before_cursor_execute", on_execute)
        try:
            result = _find(db, org_row)
        finally:
            event.remove(test_engine, "before_cursor_execute", on_execute)
        assert result.paths
        return counts["n"]

    small = build_and_count("small", 2)
    large = build_and_count("large", 25)

    assert large == small


# --- Vercel-style infrastructure ------------------------------------------------------------


@pytest.fixture
def vercel_graph(db):
    org_row, user = make_org(db, "Vercel Path Org")
    app = make_asset(db, org_row, "shop.vercel.app", authorization_confirmed=True, **CRITICAL)
    www = make_asset(db, org_row, "www.shop.vercel.app", AssetType.subdomain, source=AssetSource.discovery, **HIGH)
    anycast = make_asset(db, org_row, "216.198.79.67", AssetType.ip_address, source=AssetSource.discovery, **HIGH)
    gone_ip = make_asset(db, org_row, "216.198.79.3", AssetType.ip_address, source=AssetSource.discovery,
                         status=LifecycleStatus.disappeared, **HIGH)
    neighbour = make_asset(db, org_row, "neighbour.vercel.app", **CRITICAL)
    asn = make_asset(db, org_row, "AS16509", AssetType.asn, source=AssetSource.discovery, **CRITICAL)

    certificate_row(db, app, at=ago(days=40))
    for days in (40, 17, 2):
        tls_result(db, org_row, user, app, at=ago(days=days))
    http_result(db, org_row, user, app, "https", at=ago(days=17))
    observed_dns(db, org_row, user, app, anycast, at=ago(days=2))
    observed_dns(db, org_row, user, app, gone_ip, at=ago(days=39), status=LifecycleStatus.disappeared)
    observed_dns(db, org_row, user, neighbour, anycast, at=ago(days=2))  # another site on the same anycast IP
    relate(db, www, app, RelationshipType.belongs_to)
    relate(db, anycast, asn, RelationshipType.announced_by)
    return {"org": org_row, "app": app, "anycast": anycast, "neighbour": neighbour, "www": www, "asn": asn}


def test_vercel_graph_paths(db, vercel_graph):
    result = engine.find_exposure_paths(db, vercel_graph["org"].id, as_of=AS_OF)

    assert _summary(result) == [
        (["shop.vercel.app"], "direct_exposure"),
        (["shop.vercel.app", "216.198.79.67"], "observed_dns_association"),
    ]
    zero_hop = result.paths[0]
    assert [e.evidence_type for e in zero_hop.entry_evidence] == [EvidenceType.tls_handshake]  # HTTP is stale
    targets = {path.target.value for path in result.paths}
    assert "neighbour.vercel.app" not in targets and "AS16509" not in targets and "www.shop.vercel.app" not in targets
    assert result.eligible_target_count == 5  # the disappeared IP is never a target


def test_vercel_graph_has_no_paths_once_evidence_ages_out(db, vercel_graph):
    last_handshake = ago(days=2)

    result = engine.find_exposure_paths(
        db, vercel_graph["org"].id, as_of=last_handshake + engine.FRESHNESS_WINDOW + timedelta(seconds=1)
    )

    assert result.paths == () and result.entry_point_count == 0
