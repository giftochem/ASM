"""Stage A.2: relationship traversal semantics
(app.services.relationship_traversal_rules)."""

import socket
import uuid

import pytest

from app.core.enums import AssetSource, AssetType, DiscoveryResultOutcome, DiscoveryRunStatus, LifecycleStatus, RelationshipType
from app.models.user import User
from app.services import relationship_traversal_rules as rules
from tests.attack_path_fixtures import ago, creation_audit, dns_result, make_asset, make_org, observed_dns, relate

ALLOWED_TYPES = {RelationshipType.resolves_to, RelationshipType.hosts, RelationshipType.exposes}
NEVER_TYPES = [t for t in RelationshipType if t not in ALLOWED_TYPES]


@pytest.fixture
def org(db):
    return make_org(db, "Traversal Org")


def _decision(db, org_row, from_asset, relationship):
    decisions = rules.evaluate_asset_relationships(db, org_row.id, from_asset.id)
    matching = [d for d in decisions if d.relationship_id == relationship.id]
    assert len(matching) == 1
    return matching[0]


def _traversable(db, org_row, user, source, target, relationship_type):
    """A relationship of an allowed type with exactly the provenance its
    rule requires."""
    if relationship_type is RelationshipType.resolves_to:
        return observed_dns(db, org_row, user, source, target)
    relationship = relate(db, source, target, relationship_type, source_kind=AssetSource.manual)
    creation_audit(db, org_row, user, relationship)
    return relationship


# --- the rule table ------------------------------------------------------------------


def test_every_relationship_type_has_an_explicit_rule():
    assert set(rules.TYPE_RULES) == set(RelationshipType)
    allowed = {t for t, (rule, _) in rules.TYPE_RULES.items() if rule is not rules.TypeRule.never}
    assert allowed == ALLOWED_TYPES


# --- resolves_to: observed DNS only --------------------------------------------------------


@pytest.mark.parametrize(
    "target_type,target_value,record_type",
    [(AssetType.ip_address, "203.0.113.20", "A"), (AssetType.subdomain, "cname-target.example.com", "CNAME")],
)
def test_discovered_resolves_to_with_dns_evidence_is_followed_forward(db, org, target_type, target_value, record_type):
    org_row, user = org
    domain = make_asset(db, org_row, "www.example.com", AssetType.subdomain)
    target = make_asset(db, org_row, target_value, target_type)
    stored = dns_result(db, org_row, user, domain, target, at=ago(days=1), record_type=record_type)
    relationship = relate(db, domain, target, RelationshipType.resolves_to)

    decision = _decision(db, org_row, domain, relationship)

    assert decision.allowed and decision.rule == "dns_resolution_forward"
    assert decision.direction == "forward" and decision.to_asset_id == target.id
    assert decision.provenance.source == "discovery"
    evidence = decision.provenance.dns_evidence
    assert evidence.result_id == stored.id and evidence.discovery_run_id == stored.discovery_run_id
    assert evidence.observed_at == stored.created_at and evidence.record_type == record_type
    assert str(stored.id) in decision.reason


def test_latest_dns_evidence_is_reported(db, org):
    org_row, user = org
    domain = make_asset(db, org_row, "repeat.example.com")
    ip = make_asset(db, org_row, "203.0.113.30", AssetType.ip_address)
    dns_result(db, org_row, user, domain, ip, at=ago(days=5))
    latest = dns_result(db, org_row, user, domain, ip, at=ago(days=1), outcome=DiscoveryResultOutcome.unchanged)
    relationship = relate(db, domain, ip, RelationshipType.resolves_to)

    assert _decision(db, org_row, domain, relationship).provenance.dns_evidence.result_id == latest.id


def test_manual_resolves_to_is_rejected(db, org):
    org_row, _ = org
    domain = make_asset(db, org_row, "asserted.example.com")
    ip = make_asset(db, org_row, "203.0.113.31", AssetType.ip_address)
    relationship = relate(db, domain, ip, RelationshipType.resolves_to, source_kind=AssetSource.manual)

    decision = _decision(db, org_row, domain, relationship)

    assert not decision.allowed and decision.rule == "dns_not_observed"
    assert "not an observed DNS fact" in decision.reason


def test_manual_resolves_to_with_audit_provenance_is_still_rejected(client, register_user, db):
    """End to end through the real relationship route: an analyst-entered
    resolves_to has a visible audit trail, and v0.1 still doesn't treat it
    as an observed DNS fact."""
    headers = register_user(email="dns-assertion@example.com")
    domain = client.post("/assets", json={"asset_type": "domain", "value": "asserted-dns.example.com"}, headers=headers).json()
    ip = client.post("/assets", json={"asset_type": "ip_address", "value": "93.184.216.34"}, headers=headers).json()
    created = client.post(
        f"/assets/{domain['id']}/relationships",
        json={"target_asset_id": ip["id"], "relationship_type": "resolves_to"},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    user = db.query(User).filter(User.email == "dns-assertion@example.com").one()

    (decision,) = rules.evaluate_asset_relationships(db, user.organization_id, uuid.UUID(domain["id"]))

    assert not decision.allowed and decision.rule == "dns_not_observed"
    assert decision.provenance.source == "manual" and decision.provenance.audit_log_id is not None


def test_manual_resolves_to_later_seen_by_discovery_stays_rejected(db, org):
    """create_relationship keeps a row's original source on
    re-confirmation, so this row is still analyst-entered -- v0.1 keeps
    rejecting it rather than relabeling an assertion as observed."""
    org_row, user = org
    domain = make_asset(db, org_row, "hybrid.example.com")
    ip = make_asset(db, org_row, "203.0.113.32", AssetType.ip_address)
    dns_result(db, org_row, user, domain, ip)
    relationship = relate(db, domain, ip, RelationshipType.resolves_to, source_kind=AssetSource.manual)

    assert _decision(db, org_row, domain, relationship).rule == "dns_not_observed"


def test_discovered_resolves_to_without_dns_evidence_is_rejected(db, org):
    org_row, _ = org
    domain = make_asset(db, org_row, "unbacked.example.com")
    ip = make_asset(db, org_row, "203.0.113.33", AssetType.ip_address)
    relationship = relate(db, domain, ip, RelationshipType.resolves_to)

    decision = _decision(db, org_row, domain, relationship)

    assert not decision.allowed and decision.rule == "dns_evidence_missing"
    assert decision.provenance.dns_evidence is None


@pytest.mark.parametrize(
    "variant",
    ["reverse_direction", "other_provider", "stub_provider", "failed_run", "running_run", "rejected_outcome", "other_organization"],
)
def test_dns_evidence_must_support_this_exact_resolution(db, org, variant):
    org_row, user = org
    domain = make_asset(db, org_row, "strict.example.com", AssetType.subdomain)
    target = make_asset(db, org_row, "edge.strict.example.com", AssetType.subdomain)
    if variant == "reverse_direction":
        dns_result(db, org_row, user, target, domain)  # target resolved to domain, not the other way
    elif variant == "other_provider":
        dns_result(db, org_row, user, domain, target, provider="certificate")
    elif variant == "stub_provider":
        dns_result(db, org_row, user, domain, target, provider="stub")
    elif variant == "failed_run":
        dns_result(db, org_row, user, domain, target, run_status=DiscoveryRunStatus.failed)
    elif variant == "running_run":
        dns_result(db, org_row, user, domain, target, run_status=DiscoveryRunStatus.running)
    elif variant == "rejected_outcome":
        dns_result(db, org_row, user, domain, target, outcome=DiscoveryResultOutcome.rejected)
    elif variant == "other_organization":
        other_org, other_user = make_org(db, "Foreign DNS Org")
        dns_result(db, other_org, other_user, domain, target)
    relationship = relate(db, domain, target, RelationshipType.resolves_to)

    decision = _decision(db, org_row, domain, relationship)

    assert not decision.allowed and decision.rule == "dns_evidence_missing"


def test_evidence_for_the_opposite_direction_never_backs_a_relationship(db, org):
    """Two resolves_to rows pointing opposite ways, DNS evidence for only
    one: the other stays unbacked even though both assets appear in the
    evidence lookup."""
    org_row, user = org
    first = make_asset(db, org_row, "loop-a.example.com", AssetType.subdomain)
    second = make_asset(db, org_row, "loop-b.example.com", AssetType.subdomain)
    dns_result(db, org_row, user, second, first, record_type="CNAME")
    forward = relate(db, first, second, RelationshipType.resolves_to)
    backed = relate(db, second, first, RelationshipType.resolves_to)

    assert _decision(db, org_row, first, forward).rule == "dns_evidence_missing"
    assert _decision(db, org_row, second, backed).allowed


def test_resolves_to_from_a_non_hostname_is_rejected(db, org):
    org_row, user = org
    ip = make_asset(db, org_row, "203.0.113.21", AssetType.ip_address)
    other = make_asset(db, org_row, "203.0.113.22", AssetType.ip_address)
    relationship = observed_dns(db, org_row, user, ip, other)

    decision = _decision(db, org_row, ip, relationship)

    assert not decision.allowed and decision.rule == "resolution_endpoint_types"


# --- directionality -------------------------------------------------------------------


@pytest.mark.parametrize("relationship_type", sorted(ALLOWED_TYPES, key=lambda t: t.value))
def test_reverse_traversal_is_rejected(db, org, relationship_type):
    org_row, user = org
    source = make_asset(db, org_row, "src.example.com")
    target = make_asset(db, org_row, "203.0.113.23", AssetType.ip_address)
    relationship = _traversable(db, org_row, user, source, target, relationship_type)

    forward = _decision(db, org_row, source, relationship)
    reverse = _decision(db, org_row, target, relationship)

    assert forward.allowed
    assert not reverse.allowed and reverse.rule == "reverse_traversal"
    assert reverse.direction == "reverse" and reverse.to_asset_id == source.id


def test_relationship_not_touching_the_asset_is_not_incident(db, org):
    org_row, _ = org
    a = make_asset(db, org_row, "a.example.com")
    b = make_asset(db, org_row, "203.0.113.24", AssetType.ip_address)
    bystander = make_asset(db, org_row, "bystander.example.com")
    relationship = relate(db, a, b, RelationshipType.resolves_to)

    decision = rules.evaluate_traversal(
        relationship, from_asset_id=bystander.id, organization_id=org_row.id, source_asset=a, target_asset=b
    )

    assert not decision.allowed and decision.rule == "not_incident" and decision.to_asset_id is None


# --- lifecycle ------------------------------------------------------------------------


@pytest.mark.parametrize("status", [LifecycleStatus.disappeared, LifecycleStatus.stale])
def test_inactive_relationships_are_rejected(db, org, status):
    org_row, user = org
    domain = make_asset(db, org_row, "old-dns.example.com")
    ip = make_asset(db, org_row, "203.0.113.25", AssetType.ip_address)
    relationship = observed_dns(db, org_row, user, domain, ip, status=status)  # evidence alone doesn't revive it

    decision = _decision(db, org_row, domain, relationship)

    assert not decision.allowed and decision.rule == "relationship_inactive"


def test_first_seen_relationship_is_current(db, org):
    org_row, user = org
    domain = make_asset(db, org_row, "new-dns.example.com")
    ip = make_asset(db, org_row, "203.0.113.26", AssetType.ip_address)
    relationship = observed_dns(db, org_row, user, domain, ip, status=LifecycleStatus.first_seen)

    assert _decision(db, org_row, domain, relationship).allowed


@pytest.mark.parametrize("endpoint_fields", [{"status": LifecycleStatus.disappeared}, {"is_active": False}])
def test_inactive_endpoint_is_rejected(db, org, endpoint_fields):
    org_row, user = org
    domain = make_asset(db, org_row, "points-away.example.com")
    ip = make_asset(db, org_row, "203.0.113.27", AssetType.ip_address, **endpoint_fields)
    relationship = observed_dns(db, org_row, user, domain, ip)

    decision = _decision(db, org_row, domain, relationship)

    assert not decision.allowed and decision.rule == "endpoint_inactive"


# --- analyst-entered hosts/exposes -----------------------------------------------------


@pytest.mark.parametrize("relationship_type", ["hosts", "exposes"])
def test_analyst_entered_relationship_with_visible_provenance_is_followed(client, register_user, db, relationship_type):
    """End to end through the real relationship-create route, so the
    provenance checked is the audit record that route actually writes."""
    headers = register_user(email=f"{relationship_type}@example.com")
    host = client.post("/assets", json={"asset_type": "ip_address", "value": "93.184.216.34"}, headers=headers).json()
    app = client.post("/assets", json={"asset_type": "domain", "value": "app.example.com"}, headers=headers).json()
    created = client.post(
        f"/assets/{host['id']}/relationships",
        json={"target_asset_id": app["id"], "relationship_type": relationship_type},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    user = db.query(User).filter(User.email == f"{relationship_type}@example.com").one()

    decisions = rules.evaluate_asset_relationships(db, user.organization_id, uuid.UUID(host["id"]))

    assert len(decisions) == 1
    decision = decisions[0]
    assert decision.allowed and decision.rule == "analyst_entered_forward"
    assert decision.provenance.source == "manual"
    assert decision.provenance.entered_by_user_id == user.id and decision.provenance.audit_log_id is not None


@pytest.mark.parametrize("relationship_type", [RelationshipType.hosts, RelationshipType.exposes])
def test_discovered_hosts_or_exposes_is_rejected(db, org, relationship_type):
    org_row, user = org
    host = make_asset(db, org_row, "203.0.113.41", AssetType.ip_address)
    app = make_asset(db, org_row, "svc.example.com")
    relationship = relate(db, host, app, relationship_type, source_kind=AssetSource.discovery)
    creation_audit(db, org_row, user, relationship)

    decision = _decision(db, org_row, host, relationship)

    assert not decision.allowed and decision.rule == "not_analyst_entered"


def test_manual_relationship_without_visible_provenance_is_rejected(db, org):
    org_row, _ = org
    host = make_asset(db, org_row, "203.0.113.42", AssetType.ip_address)
    app = make_asset(db, org_row, "noaudit.example.com")
    relationship = relate(db, host, app, RelationshipType.hosts, source_kind=AssetSource.manual)

    decision = _decision(db, org_row, host, relationship)

    assert not decision.allowed and decision.rule == "provenance_not_visible"


def test_provenance_from_another_organizations_audit_log_does_not_count(db, org):
    org_row, _ = org
    other_org, other_user = make_org(db, "Audit Elsewhere Org")
    host = make_asset(db, org_row, "203.0.113.43", AssetType.ip_address)
    app = make_asset(db, org_row, "foreign-audit.example.com")
    relationship = relate(db, host, app, RelationshipType.exposes, source_kind=AssetSource.manual)
    creation_audit(db, other_org, other_user, relationship)

    assert _decision(db, org_row, host, relationship).rule == "provenance_not_visible"


# --- never-traversed types and shared infrastructure ------------------------------------


@pytest.mark.parametrize("relationship_type", NEVER_TYPES, ids=lambda t: t.value)
def test_non_mvp_types_are_never_followed(db, org, relationship_type):
    org_row, user = org
    source = make_asset(db, org_row, "src-never.example.com")
    target = make_asset(db, org_row, "dst-never.example.com", AssetType.subdomain)
    # Even analyst-entered with visible provenance.
    relationship = relate(db, source, target, relationship_type, source_kind=AssetSource.manual)
    creation_audit(db, org_row, user, relationship)

    decision = _decision(db, org_row, source, relationship)

    assert not decision.allowed and decision.rule == "type_not_traversable"
    assert relationship_type.value in decision.reason


def test_shared_ip_does_not_connect_the_domains_that_share_it(db, org):
    org_row, user = org
    first = make_asset(db, org_row, "tenant-a.example.com")
    second = make_asset(db, org_row, "tenant-b.example.com")
    shared_ip = make_asset(db, org_row, "203.0.113.50", AssetType.ip_address)
    observed_dns(db, org_row, user, first, shared_ip)
    observed_dns(db, org_row, user, second, shared_ip)

    from_ip = rules.evaluate_asset_relationships(db, org_row.id, shared_ip.id)

    assert len(from_ip) == 2 and not any(d.allowed for d in from_ip)
    assert {d.rule for d in from_ip} == {"reverse_traversal"}


def test_customers_sharing_an_ip_never_reach_each_other(db, org):
    """Two organizations each hold their own asset for the same shared IP.
    Each one's DNS evidence and walk stay inside that organization."""
    org_row, user = org
    other_org, other_user = make_org(db, "Co-tenant Org")
    mine = make_asset(db, org_row, "mine-shared.example.com")
    my_ip = make_asset(db, org_row, "198.51.100.80", AssetType.ip_address)
    theirs = make_asset(db, other_org, "theirs-shared.example.com")
    their_ip = make_asset(db, other_org, "198.51.100.80", AssetType.ip_address)
    my_link = observed_dns(db, org_row, user, mine, my_ip)
    observed_dns(db, other_org, other_user, theirs, their_ip)

    my_decisions = rules.evaluate_asset_relationships(db, org_row.id, mine.id)
    from_my_ip = rules.evaluate_asset_relationships(db, org_row.id, my_ip.id)

    assert [(d.relationship_id, d.allowed) for d in my_decisions] == [(my_link.id, True)]
    assert {d.to_asset_id for d in my_decisions + from_my_ip} <= {mine.id, my_ip.id}
    assert not any(d.allowed for d in from_my_ip)
    assert rules.evaluate_asset_relationships(db, org_row.id, their_ip.id) == []


def test_shared_certificate_asn_and_nameservers_are_not_paths(db, org):
    org_row, _ = org
    seed = make_asset(db, org_row, "seed-shared.example.com")
    san_peer = make_asset(db, org_row, "san-peer.example.com", AssetType.subdomain)
    ip = make_asset(db, org_row, "203.0.113.51", AssetType.ip_address)
    asn = make_asset(db, org_row, "AS64500", AssetType.asn)
    nameserver = make_asset(db, org_row, "ns1.example.com", AssetType.subdomain)
    relate(db, seed, san_peer, RelationshipType.related_to)
    relate(db, ip, asn, RelationshipType.announced_by)
    relate(db, seed, nameserver, RelationshipType.served_by)

    decisions = rules.evaluate_asset_relationships(db, org_row.id, seed.id) + rules.evaluate_asset_relationships(
        db, org_row.id, ip.id
    )

    assert decisions and not any(d.allowed for d in decisions)
    assert {d.rule for d in decisions} == {"type_not_traversable"}


# --- confidence and organization isolation -----------------------------------------------


def test_confidence_never_changes_the_decision(db, org):
    org_row, user = org
    domain = make_asset(db, org_row, "confidence.example.com")
    low = observed_dns(db, org_row, user, domain, make_asset(db, org_row, "203.0.113.60", AssetType.ip_address), confidence=0.01)
    high = observed_dns(db, org_row, user, domain, make_asset(db, org_row, "203.0.113.61", AssetType.ip_address), confidence=1.0)

    low_decision, high_decision = _decision(db, org_row, domain, low), _decision(db, org_row, domain, high)

    assert low_decision.allowed and high_decision.allowed and low_decision.rule == high_decision.rule
    assert not any("exploit" in name for name in rules.TraversalDecision.__dataclass_fields__)


def test_cross_organization_relationship_is_rejected(db, org):
    org_row, user = org
    other_org, _ = make_org(db, "Neighbor Org")
    mine = make_asset(db, org_row, "mine-x.example.com")
    theirs = make_asset(db, other_org, "203.0.113.70", AssetType.ip_address)
    # Written directly -- the service layer refuses this, so it can only
    # exist through a bug or manual tampering. Even DNS evidence recorded
    # in this organization doesn't make it followable.
    relationship = observed_dns(db, org_row, user, mine, theirs)

    decision = _decision(db, org_row, mine, relationship)

    assert not decision.allowed and decision.rule == "cross_organization"


def test_another_organizations_asset_yields_no_decisions(db, org):
    org_row, _ = org
    other_org, other_user = make_org(db, "Walled Org")
    theirs = make_asset(db, other_org, "theirs-x.example.com")
    observed_dns(db, other_org, other_user, theirs, make_asset(db, other_org, "203.0.113.71", AssetType.ip_address))

    assert rules.evaluate_asset_relationships(db, org_row.id, theirs.id) == []


def test_missing_endpoint_is_treated_as_cross_organization(db, org):
    org_row, _ = org
    domain = make_asset(db, org_row, "dangling.example.com")
    ip = make_asset(db, org_row, "203.0.113.72", AssetType.ip_address)
    relationship = relate(db, domain, ip, RelationshipType.resolves_to)

    decision = rules.evaluate_traversal(
        relationship, from_asset_id=domain.id, organization_id=org_row.id, source_asset=domain, target_asset=None
    )

    assert not decision.allowed and decision.rule == "cross_organization"


# --- determinism and no network ----------------------------------------------------------


def test_decisions_are_deterministic_and_offline(db, org, monkeypatch):
    org_row, user = org
    domain = make_asset(db, org_row, "det.example.com")
    for index in range(3):
        target = make_asset(db, org_row, f"203.0.113.{80 + index}", AssetType.ip_address)
        # Two same-time dns results for each: the reported one is chosen
        # by a total order, never by row order.
        dns_result(db, org_row, user, domain, target, at=ago(days=1))
        dns_result(db, org_row, user, domain, target, at=ago(days=1))
        relate(db, domain, target, RelationshipType.resolves_to)
    relate(db, make_asset(db, org_row, "child.det.example.com", AssetType.subdomain), domain, RelationshipType.belongs_to)

    def refuse(*args, **kwargs):
        raise AssertionError("traversal rules attempted network access")

    for name in ("create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, refuse)

    first = rules.evaluate_asset_relationships(db, org_row.id, domain.id)
    second = rules.evaluate_asset_relationships(db, org_row.id, domain.id)

    assert first == second and len(first) == 4
    assert [d.direction for d in first] == ["forward", "forward", "forward", "reverse"]
    assert [d.allowed for d in first] == [True, True, True, False]
