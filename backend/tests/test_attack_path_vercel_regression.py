"""Stage A.2 regression: a synthetic replica of the shape real Vercel
discovery data takes (read from the development database's demo
organization, which is never touched -- every value here is synthetic):

- a manually added domain with repeated certificate-provider handshakes
  (created, then unchanged), the latest one recent;
- HTTP results for both schemes that succeeded on several runs, then
  failed on the latest run with a temporary DNS resolution error -- the
  exact failure text the real data holds;
- `resolves_to` edges recorded by dns discovery to Vercel-anycast-style
  IPs, some active, some disappeared along with their IP assets; the IPs
  carry no service evidence of their own;
- a discovered `www` subdomain linked by `belongs_to` (subdomain ->
  domain), and an IP `announced_by` a shared ASN.
"""

from datetime import timedelta

import pytest

from app.core.enums import AssetSource, AssetType, DiscoveryResultOutcome, LifecycleStatus, RelationshipType
from app.services import exposure_evidence_service as exposure
from app.services import relationship_traversal_rules as rules
from app.services.exposure_evidence_service import EvidenceType, Freshness
from tests.attack_path_fixtures import (
    AS_OF,
    ago,
    certificate_row,
    http_result,
    make_asset,
    make_org,
    observed_dns,
    relate,
    tls_result,
)

TEMPORARY_DNS_FAILURE = (
    "blocked target '{url}': DNS resolution failed for 'synthetic-target.vercel.app': "
    "[Errno -3] Temporary failure in name resolution"
)


@pytest.fixture
def vercel_shape(db):
    org, user = make_org(db, "Synthetic Vercel Shape Org")
    domain = make_asset(db, org, "synthetic-target.vercel.app", authorization_confirmed=True)
    www = make_asset(db, org, "www.synthetic-target.vercel.app", AssetType.subdomain,
                     source=AssetSource.discovery, status=LifecycleStatus.first_seen)
    active_ips = [make_asset(db, org, value, AssetType.ip_address, source=AssetSource.discovery)
                  for value in ("216.198.79.67", "64.29.17.67")]
    gone_ips = [make_asset(db, org, value, AssetType.ip_address, source=AssetSource.discovery,
                           status=LifecycleStatus.disappeared) for value in ("216.198.79.3", "64.29.17.3")]
    asn = make_asset(db, org, "AS16509", AssetType.asn, source=AssetSource.discovery)

    certificate_row(db, domain, at=ago(days=45))
    tls_result(db, org, user, domain, at=ago(days=45))
    for days in (39, 38, 36, 17, 2):
        tls_result(db, org, user, domain, at=ago(days=days), outcome=DiscoveryResultOutcome.unchanged)
    for scheme in ("https", "http"):
        http_result(db, org, user, domain, scheme, at=ago(days=45))
        for days in (39, 38, 36, 17):
            http_result(db, org, user, domain, scheme, at=ago(days=days), outcome=DiscoveryResultOutcome.unchanged)
        failed = http_result(db, org, user, domain, scheme, at=ago(days=2), outcome=DiscoveryResultOutcome.failed)
        failed.evidence = {**failed.evidence, "failure_reason": TEMPORARY_DNS_FAILURE.format(url=failed.evidence["requested_url"])}
    db.flush()

    for ip in active_ips:
        observed_dns(db, org, user, domain, ip, at=ago(days=17))
    for ip in gone_ips:
        observed_dns(db, org, user, domain, ip, at=ago(days=39), status=LifecycleStatus.disappeared)
    relate(db, www, domain, RelationshipType.belongs_to)
    relate(db, active_ips[0], asn, RelationshipType.announced_by)
    return {"org": org, "user": user, "domain": domain, "www": www, "active_ips": active_ips, "gone_ips": gone_ips, "asn": asn}


def test_vercel_domain_is_an_entry_point_through_tls_only(db, vercel_shape):
    result = exposure.assess_asset_exposure(db, vercel_shape["org"].id, vercel_shape["domain"].id, as_of=AS_OF)

    assert result.is_observed_entry_point is True
    by_type = {}
    for evidence in result.evidence:
        by_type.setdefault(evidence.evidence_type, []).append(evidence)
    (tls,) = by_type[EvidenceType.tls_handshake]
    assert tls.qualifies and tls.freshness is Freshness.current and tls.last_confirmed_at == ago(days=2)
    # The temporary DNS failure doesn't contradict the HTTP history -- it
    # stays visible -- but the last real response is 17 days old, so the
    # HTTP evidence has aged out rather than being treated as current.
    http = by_type[EvidenceType.http_response]
    assert {e.subject for e in http} == {"http", "https"}
    for evidence in http:
        assert evidence.freshness is Freshness.stale and not evidence.qualifies
        assert evidence.last_confirmed_at == ago(days=17) and evidence.contradicted_at is None
        assert evidence.inconclusive_attempts == 1 and evidence.latest_inconclusive_at == ago(days=2)


def test_vercel_domain_stops_qualifying_once_tls_ages_out(db, vercel_shape):
    """The demo data's situation at release time: with no new discovery
    run, the last handshake leaves the window and nothing qualifies."""
    org_id, domain_id = vercel_shape["org"].id, vercel_shape["domain"].id
    edge = ago(days=2) + exposure.FRESHNESS_WINDOW

    at_edge = exposure.assess_asset_exposure(db, org_id, domain_id, as_of=edge)
    past_edge = exposure.assess_asset_exposure(db, org_id, domain_id, as_of=edge + timedelta(seconds=1))

    assert at_edge.is_observed_entry_point is True
    assert past_edge.is_observed_entry_point is False
    service = [e for e in past_edge.evidence if e.evidence_type in exposure.SERVICE_EVIDENCE_TYPES]
    assert service and {e.freshness for e in service} == {Freshness.stale}


def test_vercel_ips_and_subdomain_are_not_entry_points(db, vercel_shape):
    org = vercel_shape["org"]
    assessed = exposure.assess_exposure(db, org.id, as_of=AS_OF)

    for asset in [*vercel_shape["active_ips"], *vercel_shape["gone_ips"], vercel_shape["www"], vercel_shape["asn"]]:
        assert assessed[asset.id].is_observed_entry_point is False, asset.value
    assert "asset type 'ip_address' alone does not establish exposure" in assessed[vercel_shape["active_ips"][0].id].limitations


def test_vercel_traversal_follows_only_current_observed_dns_resolution(db, vercel_shape):
    org, domain = vercel_shape["org"], vercel_shape["domain"]

    decisions = rules.evaluate_asset_relationships(db, org.id, domain.id)

    allowed = {d.to_asset_id: d for d in decisions if d.allowed}
    assert set(allowed) == {ip.id for ip in vercel_shape["active_ips"]}
    assert all(d.rule == "dns_resolution_forward" and d.provenance.dns_evidence is not None for d in allowed.values())
    rejected = {d.to_asset_id: d.rule for d in decisions if not d.allowed}
    for ip in vercel_shape["gone_ips"]:
        assert rejected[ip.id] == "relationship_inactive"
    assert rejected[vercel_shape["www"].id] == "reverse_traversal"


def test_vercel_manual_dns_assertion_is_not_followed(db, vercel_shape):
    org, domain = vercel_shape["org"], vercel_shape["domain"]
    asserted_ip = make_asset(db, org, "76.76.21.21", AssetType.ip_address)
    relationship = relate(db, domain, asserted_ip, RelationshipType.resolves_to, source_kind=AssetSource.manual)

    (decision,) = [d for d in rules.evaluate_asset_relationships(db, org.id, domain.id) if d.relationship_id == relationship.id]

    assert not decision.allowed and decision.rule == "dns_not_observed"


def test_vercel_shared_anycast_ip_and_asn_lead_nowhere(db, vercel_shape):
    org, user = vercel_shape["org"], vercel_shape["user"]
    shared_ip = vercel_shape["active_ips"][0]
    # A second, unrelated tenant domain on the same anycast IP.
    other_tenant = make_asset(db, org, "another-tenant.vercel.app")
    observed_dns(db, org, user, other_tenant, shared_ip)

    decisions = rules.evaluate_asset_relationships(db, org.id, shared_ip.id)

    assert decisions and not any(d.allowed for d in decisions)
    assert {d.rule for d in decisions} == {"reverse_traversal", "type_not_traversable"}
