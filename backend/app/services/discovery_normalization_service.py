"""Turns provider-reported DiscoveryCandidates into real Asset/
AssetRelationship/Observation rows by calling the *existing* Step 8
services — this module owns dedup/create-or-refresh decisions and
DiscoveryResult bookkeeping, nothing else. It does not reimplement asset
creation, relationship creation, or observation writing.
"""

import json
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.core.enums import (
    AssetSource,
    AssetType,
    ChangeType,
    DiscoveryResultOutcome,
    DiscoveryRunStatus,
    LifecycleStatus,
    RelationshipType,
)
from app.core.exceptions import InvalidTargetError
from app.core.validation import normalize_asset_value
from app.discovery.base import (
    CertificateObservation,
    DiscoveryCandidate,
    HttpObservation,
    InfrastructureProviderData,
    NetworkObservation,
)
from app.discovery.cloud_classification import classify_infrastructure
from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.models.certificate import Certificate
from app.models.discovery_result import DiscoveryResult
from app.models.discovery_run import DiscoveryRun
from app.models.observation import Observation
from app.services import asset_relationship_service, observation_service

# Step 9.4: relationship types whose natural semantic direction is
# discovered-thing -> seed (child -> parent) rather than the default
# seed -> discovered-thing every other type uses. "A subdomain
# belongs_to its domain," not the reverse -- found as a real bug in Step
# 9.2 (the stub provider's only user of belongs_to stored it backwards),
# fixed here now that a real provider (subdomain discovery) needs the
# correct direction. Centralized here, not per-provider, so nothing
# using this pipeline needs to know about it.
_REVERSED_DIRECTION_RELATIONSHIP_TYPES = {RelationshipType.belongs_to}


def canonicalize_for_comparison(value):
    """Recursively normalizes a value for change-detection equality
    comparison (Step 9.9.4). Dict key order is already Python-equality-
    insensitive; the real gap this closes is LIST order -- two evidence
    payloads that differ only in the order their list-of-dicts entries
    happened to be produced in (e.g. security-header evidence, cloud-
    classification signals) must compare equal, not be reported as a
    spurious "changed" event.

    Deliberately does NOT do case normalization or strip timestamp
    fields -- those are domain-specific decisions each caller must make
    before its evidence dict reaches this function (e.g. a hostname
    should be lowercased first, but a Server header's exact case might
    be meaningful evidence; a raw timestamp should simply never be
    placed in a compared evidence dict at all, which is already this
    codebase's established convention -- see every record_*_observation
    function, none of which include one).
    """
    if isinstance(value, dict):
        return {key: canonicalize_for_comparison(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        canonicalized_items = [canonicalize_for_comparison(item) for item in value]
        try:
            return sorted(canonicalized_items, key=lambda item: json.dumps(item, sort_keys=True, default=str))
        except TypeError:
            # Genuinely unorderable/unsortable content (shouldn't occur
            # for JSON-shaped evidence) -- fall back to canonicalized-
            # but-unsorted rather than raising out of a comparison path.
            return canonicalized_items
    return value


def normalize_candidate(
    db: Session, run: DiscoveryRun, seed_asset: Asset, candidate: DiscoveryCandidate
) -> DiscoveryResult:
    """Always returns a DiscoveryResult, even for a rejected candidate —
    this is the durable record of what a provider reported, independent
    of whether it became an Asset.
    """
    try:
        normalized_value = normalize_asset_value(
            candidate.asset_type, candidate.value, settings.max_ip_range_prefix_length
        )
    except InvalidTargetError as exc:
        # This is the SSRF/scope-expansion boundary: the exact same
        # validation manual asset creation uses (app.core.validation),
        # so a candidate carrying a private/loopback/reserved IP -- or
        # any other invalid value, however it got there -- is rejected
        # here, before it ever reaches the database. Discovery introduces
        # no new validation surface; it inherits the existing one.
        return _record_result(
            db,
            run,
            candidate,
            outcome=DiscoveryResultOutcome.rejected,
            evidence={**candidate.evidence, "rejection_reason": str(exc)},
        )

    # organization_id always comes from the seed, never the candidate —
    # DiscoveryCandidate has no organization field to manipulate in the
    # first place, so a misbehaving provider has no path to create an
    # asset outside the requesting org even in principle.
    asset, outcome = _get_or_create_asset(
        db, seed_asset.organization_id, candidate.asset_type, normalized_value, candidate.confidence
    )

    if candidate.relationship_type is not None and asset.id != seed_asset.id:
        if candidate.relationship_type in _REVERSED_DIRECTION_RELATIONSHIP_TYPES:
            relationship_source, relationship_target = asset, seed_asset
        else:
            relationship_source, relationship_target = seed_asset, asset
        asset_relationship_service.create_relationship(
            db,
            source_asset=relationship_source,
            target_asset=relationship_target,
            relationship_type=candidate.relationship_type,
            confidence=candidate.confidence,
            source=AssetSource.discovery,
        )

    return _record_result(db, run, candidate, outcome=outcome, resulting_asset_id=asset.id)


def record_seed_evidence(
    db: Session,
    run: DiscoveryRun,
    seed_asset: Asset,
    evidence: dict,
    *,
    change_type: ChangeType = ChangeType.dns_records_observed,
) -> DiscoveryResult:
    """For provider output that's metadata about the seed itself (e.g.
    DNS TXT records, a CNAME/MX/NS target outside the authorized scope,
    or Certificate-Transparency wildcard/external names — see
    DiscoveryProviderResult.seed_evidence) rather than a new discoverable
    entity. Recorded as an Observation on the seed via the existing
    observation_service, never as a new Asset. Reuses _record_result
    unchanged, fed a synthetic candidate representing "the seed,
    annotated" — no existing DiscoveryResult bookkeeping logic is
    duplicated here.

    `change_type` defaults to the original Step 9.2 value so that call
    site is unaffected by this Step 9.4 widening -- pass a more specific
    value (e.g. ChangeType.certificate_transparency_observed) when the
    evidence didn't come from DNS.
    """
    observation_service.record_observation(
        db,
        seed_asset,
        change_type,
        field_name="dns_metadata" if change_type == ChangeType.dns_records_observed else "discovery_metadata",
        current_value=json.dumps(evidence, default=str),
        source=AssetSource.discovery,
        confidence=1.0,
    )

    synthetic_candidate = DiscoveryCandidate(
        asset_type=seed_asset.asset_type,
        value=seed_asset.value,
        confidence=1.0,
        evidence=evidence,
    )
    return _record_result(
        db, run, synthetic_candidate, outcome=DiscoveryResultOutcome.observed, resulting_asset_id=seed_asset.id
    )


def record_certificate_observation(
    db: Session, run: DiscoveryRun, seed_asset: Asset, cert_obs: CertificateObservation
) -> DiscoveryResult:
    """Populates the existing Certificate child-detail table (Step 8.1) —
    never a new Asset/graph node, per the Step 9.3 reconciliation
    decision. Dedup identity stays (asset_id, hostname, port), the
    existing unique constraint ("the current certificate we believe is
    at this slot"); fingerprint_sha256 is used here to decide *what kind*
    of Observation to write, not as a separate DB uniqueness key.
    """
    existing = (
        db.query(Certificate)
        .filter(
            Certificate.asset_id == seed_asset.id,
            Certificate.hostname == cert_obs.hostname,
            Certificate.port == cert_obs.port,
        )
        .first()
    )
    now = datetime.now(timezone.utc)
    evidence = {
        "fingerprint_sha256": cert_obs.fingerprint_sha256,
        "issuer": cert_obs.issuer,
        "subject": cert_obs.subject,
        "subject_alt_names": cert_obs.subject_alt_names,
        "in_scope_sans": cert_obs.in_scope_sans,
        "external_sans": cert_obs.external_sans,
        "is_expired": cert_obs.is_expired,
        "is_self_signed": cert_obs.is_self_signed,
        "valid_until": cert_obs.valid_until.isoformat() if cert_obs.valid_until else None,
    }

    if existing is None:
        certificate = Certificate(
            asset_id=seed_asset.id,
            first_seen=now,
            last_seen=now,
            source=AssetSource.discovery,
            status=LifecycleStatus.first_seen,
        )
        _apply_certificate_fields(certificate, cert_obs)
        db.add(certificate)
        db.flush()

        observation_service.record_observation(
            db,
            seed_asset,
            ChangeType.certificate_observed,
            field_name=f"{cert_obs.hostname}:{cert_obs.port}",
            current_value=json.dumps(evidence, default=str),
            source=AssetSource.discovery,
            confidence=cert_obs.confidence,
        )
        outcome = DiscoveryResultOutcome.created

    elif existing.fingerprint_sha256 != cert_obs.fingerprint_sha256:
        previous_fingerprint = existing.fingerprint_sha256
        _apply_certificate_fields(existing, cert_obs)
        existing.last_seen = now
        if existing.status in (LifecycleStatus.stale, LifecycleStatus.disappeared):
            existing.status = LifecycleStatus.active
        db.flush()

        observation_service.record_observation(
            db,
            seed_asset,
            ChangeType.certificate_changed,
            field_name=f"{cert_obs.hostname}:{cert_obs.port}",
            previous_value=previous_fingerprint,
            current_value=json.dumps(evidence, default=str),
            source=AssetSource.discovery,
            confidence=cert_obs.confidence,
        )
        outcome = DiscoveryResultOutcome.refreshed

    else:
        # Same fingerprint re-confirmed -- nothing meaningful changed, so
        # no new Observation (keeps the history signal, not noise).
        existing.last_seen = now
        if existing.status in (LifecycleStatus.stale, LifecycleStatus.disappeared):
            existing.status = LifecycleStatus.active
        db.flush()
        outcome = DiscoveryResultOutcome.unchanged

    synthetic_candidate = DiscoveryCandidate(
        asset_type=seed_asset.asset_type,
        value=f"{cert_obs.hostname}:{cert_obs.port}",
        confidence=cert_obs.confidence,
        evidence=evidence,
    )
    return _record_result(db, run, synthetic_candidate, outcome=outcome, resulting_asset_id=seed_asset.id)


def record_http_observation(
    db: Session, run: DiscoveryRun, seed_asset: Asset, http_obs: HttpObservation
) -> DiscoveryResult:
    """Records one scheme's HTTP intelligence as an Observation on the
    seed asset -- never a new Asset, never a relationship (Step 9.5
    section 12: the hostname is the one Asset; HTTP characteristics are
    evidence about it, not new graph nodes). field_name is scoped by
    scheme (`http:https`/`http:http`) so HTTPS and HTTP are tracked
    as independent signals, matching how the provider reports them.

    Mirrors record_certificate_observation's observed/unchanged/
    refreshed state machine -- first observation for this scheme is
    `observed`, an identical re-observation is `unchanged` (no new
    Observation -- keeps history free of noise), a differing one is
    `refreshed` with a new Observation recording what changed. A
    network-level failure is `failed`; a redirect that left the seed's
    authorized scope is `rejected` -- neither compares against history,
    since neither carries trustworthy evidence to compare.
    """
    field_name = f"http:{http_obs.scheme}"

    if not http_obs.succeeded:
        evidence = {
            "scheme": http_obs.scheme,
            "requested_url": http_obs.requested_url,
            "failure_reason": http_obs.failure_reason,
        }
        synthetic_candidate = DiscoveryCandidate(
            asset_type=seed_asset.asset_type, value=f"{seed_asset.value}:{http_obs.scheme}", evidence=evidence
        )
        return _record_result(
            db, run, synthetic_candidate, outcome=DiscoveryResultOutcome.failed, resulting_asset_id=seed_asset.id,
            evidence=evidence,
        )

    if http_obs.left_authorized_scope:
        evidence = {
            "scheme": http_obs.scheme,
            "requested_url": http_obs.requested_url,
            "final_url": http_obs.final_url,
            "external_redirect_host": http_obs.external_redirect_host,
            "rejection_reason": "redirect target left the seed's authorized scope",
        }
        synthetic_candidate = DiscoveryCandidate(
            asset_type=seed_asset.asset_type, value=f"{seed_asset.value}:{http_obs.scheme}", evidence=evidence
        )
        return _record_result(
            db, run, synthetic_candidate, outcome=DiscoveryResultOutcome.rejected, resulting_asset_id=seed_asset.id,
            evidence=evidence,
        )

    certificate_fingerprint = None
    if http_obs.scheme == "https":
        cert_host = urlparse(http_obs.final_url or http_obs.requested_url).hostname
        existing_cert = (
            db.query(Certificate)
            .filter(Certificate.asset_id == seed_asset.id, Certificate.hostname == cert_host, Certificate.port == 443)
            .first()
        )
        if existing_cert is not None:
            certificate_fingerprint = existing_cert.fingerprint_sha256

    evidence = {
        "scheme": http_obs.scheme,
        "requested_url": http_obs.requested_url,
        "final_url": http_obs.final_url,
        "status_code": http_obs.status_code,
        "content_type": http_obs.content_type,
        "redirect_count": http_obs.redirect_count,
        "server": http_obs.server,
        "x_powered_by": http_obs.x_powered_by,
        "title": http_obs.title,
        "security_headers": http_obs.security_headers,
        "cookie_security_flags": http_obs.cookie_security_flags,
        "technology_evidence": http_obs.technology_evidence,
        "certificate_fingerprint": certificate_fingerprint,
    }

    previous_observation = (
        db.query(Observation)
        .filter(
            Observation.asset_id == seed_asset.id,
            Observation.field_name == field_name,
            Observation.change_type.in_([ChangeType.http_observed, ChangeType.http_changed]),
        )
        .order_by(Observation.observed_at.desc())
        .first()
    )

    if previous_observation is None:
        observation_service.record_observation(
            db,
            seed_asset,
            ChangeType.http_observed,
            field_name=field_name,
            current_value=json.dumps(evidence, default=str),
            source=AssetSource.discovery,
            confidence=http_obs.confidence,
        )
        outcome = DiscoveryResultOutcome.observed
    elif canonicalize_for_comparison(json.loads(previous_observation.current_value)) != canonicalize_for_comparison(evidence):
        observation_service.record_observation(
            db,
            seed_asset,
            ChangeType.http_changed,
            field_name=field_name,
            previous_value=previous_observation.current_value,
            current_value=json.dumps(evidence, default=str),
            source=AssetSource.discovery,
            confidence=http_obs.confidence,
        )
        outcome = DiscoveryResultOutcome.refreshed
    else:
        outcome = DiscoveryResultOutcome.unchanged

    synthetic_candidate = DiscoveryCandidate(
        asset_type=seed_asset.asset_type,
        value=f"{seed_asset.value}:{http_obs.scheme}",
        confidence=http_obs.confidence,
        evidence=evidence,
    )
    return _record_result(db, run, synthetic_candidate, outcome=outcome, resulting_asset_id=seed_asset.id, evidence=evidence)


def record_network_observation(
    db: Session, run: DiscoveryRun, seed_asset: Asset, network_obs: NetworkObservation
) -> DiscoveryResult:
    """Records network/ASN intelligence about an ip_address seed as an
    Observation on it -- never a second representation of anything an
    ASN DiscoveryCandidate (processed separately, through the normal
    normalize_candidate path -- see NetworkDiscoveryProvider) already
    creates as a real Asset. field_name is a single constant
    ("network") since there is exactly one network observation per IP
    seed, unlike HTTP's per-scheme scoping.

    Mirrors record_http_observation's observed/unchanged/refreshed
    state machine exactly: first observation is `observed`, an
    identical re-observation is `unchanged` (no new Observation --
    keeps history free of noise), a differing one is `refreshed` with a
    new Observation recording what changed. A rejected (unsafe IP) or
    failed (no data from any source) result records its own outcome
    without comparing against history, since neither carries evidence
    worth diffing.
    """
    field_name = "network"

    if network_obs.rejected:
        evidence = {"ip": network_obs.ip, "rejection_reason": network_obs.rejection_reason}
        synthetic_candidate = DiscoveryCandidate(asset_type=seed_asset.asset_type, value=seed_asset.value, evidence=evidence)
        return _record_result(
            db, run, synthetic_candidate, outcome=DiscoveryResultOutcome.rejected, resulting_asset_id=seed_asset.id,
            evidence=evidence,
        )

    if not network_obs.succeeded:
        evidence = {"ip": network_obs.ip, "failure_reason": network_obs.failure_reason}
        synthetic_candidate = DiscoveryCandidate(asset_type=seed_asset.asset_type, value=seed_asset.value, evidence=evidence)
        return _record_result(
            db, run, synthetic_candidate, outcome=DiscoveryResultOutcome.failed, resulting_asset_id=seed_asset.id,
            evidence=evidence,
        )

    evidence = {
        "ip": network_obs.ip,
        "ip_version": network_obs.ip_version,
        "asn": network_obs.asn,
        "asn_organization": network_obs.asn_organization,
        "announced_prefix": network_obs.announced_prefix,
        "network_country": network_obs.network_country,
        "registry": network_obs.registry,
        "ptr_hostname": network_obs.ptr_hostname,
        "cloud_provider_evidence": network_obs.cloud_provider_evidence,
    }

    previous_observation = (
        db.query(Observation)
        .filter(
            Observation.asset_id == seed_asset.id,
            Observation.field_name == field_name,
            Observation.change_type.in_([ChangeType.network_observed, ChangeType.network_changed]),
        )
        .order_by(Observation.observed_at.desc())
        .first()
    )

    if previous_observation is None:
        observation_service.record_observation(
            db,
            seed_asset,
            ChangeType.network_observed,
            field_name=field_name,
            current_value=json.dumps(evidence, default=str),
            source=AssetSource.discovery,
            confidence=network_obs.confidence,
        )
        outcome = DiscoveryResultOutcome.observed
    elif canonicalize_for_comparison(json.loads(previous_observation.current_value)) != canonicalize_for_comparison(evidence):
        observation_service.record_observation(
            db,
            seed_asset,
            ChangeType.network_changed,
            field_name=field_name,
            previous_value=previous_observation.current_value,
            current_value=json.dumps(evidence, default=str),
            source=AssetSource.discovery,
            confidence=network_obs.confidence,
        )
        outcome = DiscoveryResultOutcome.refreshed
    else:
        outcome = DiscoveryResultOutcome.unchanged

    synthetic_candidate = DiscoveryCandidate(
        asset_type=seed_asset.asset_type,
        value=seed_asset.value,
        confidence=network_obs.confidence,
        evidence=evidence,
    )
    return _record_result(db, run, synthetic_candidate, outcome=outcome, resulting_asset_id=seed_asset.id, evidence=evidence)


def _gather_stored_http_and_tls_evidence(db: Session, ip_asset: Asset) -> tuple[str | None, str | None]:
    """Reads HTTP Server-header and TLS-issuer evidence already stored
    for hostnames that resolve_to this IP (Steps 9.5/9.3) -- no new
    network I/O. A hostname can `resolves_to` several IPs over time and
    vice versa; this takes the first hostname (by relationship recency
    isn't tracked at this granularity, so plain iteration order) that
    has each kind of evidence, rather than trying to merge conflicting
    values from multiple hostnames into one.
    """
    hostname_asset_ids = [
        row[0]
        for row in db.query(AssetRelationship.source_asset_id)
        .filter(
            AssetRelationship.target_asset_id == ip_asset.id,
            AssetRelationship.relationship_type == RelationshipType.resolves_to,
        )
        .all()
    ]
    if not hostname_asset_ids:
        return None, None

    http_server = None
    tls_issuer = None
    for hostname_id in hostname_asset_ids:
        if http_server is None:
            http_obs = (
                db.query(Observation)
                .filter(
                    Observation.asset_id == hostname_id,
                    Observation.field_name.in_(["http:https", "http:http"]),
                    Observation.change_type.in_([ChangeType.http_observed, ChangeType.http_changed]),
                )
                .order_by(Observation.observed_at.desc())
                .first()
            )
            if http_obs and http_obs.current_value:
                try:
                    http_server = json.loads(http_obs.current_value).get("server")
                except (ValueError, TypeError):
                    pass

        if tls_issuer is None:
            cert = (
                db.query(Certificate)
                .filter(Certificate.asset_id == hostname_id)
                .order_by(Certificate.last_seen.desc())
                .first()
            )
            if cert is not None:
                tls_issuer = cert.issuer

        if http_server is not None and tls_issuer is not None:
            break

    return http_server, tls_issuer


def record_infrastructure_observation(
    db: Session, run: DiscoveryRun, seed_asset: Asset, infra_data: InfrastructureProviderData
) -> DiscoveryResult:
    """Combines infra_data's fresh network signals (ASN/prefix/PTR, via
    NetworkDiscoveryProvider -- see cloud_provider.py) with HTTP/TLS
    evidence already stored for hostnames that resolve_to this IP, then
    classifies via cloud_classification.classify_infrastructure. Never
    creates an Asset or relationship -- see cloud_provider.py's module
    docstring for why. field_name is a single constant ("infrastructure"),
    matching record_network_observation's one-per-IP scoping.

    A total lookup failure (no fresh network data AND no stored HTTP/TLS
    evidence found at all) is `failed`. Otherwise this always proceeds
    to classification -- `provider=None` ("unknown") is itself a valid,
    informative result, not a failure; it only means no signal matched
    any known provider's signature, which is an honest, common outcome.
    """
    field_name = "infrastructure"

    if infra_data.rejected:
        evidence = {"ip": infra_data.ip, "rejection_reason": infra_data.rejection_reason}
        synthetic_candidate = DiscoveryCandidate(asset_type=seed_asset.asset_type, value=seed_asset.value, evidence=evidence)
        return _record_result(
            db, run, synthetic_candidate, outcome=DiscoveryResultOutcome.rejected, resulting_asset_id=seed_asset.id,
            evidence=evidence,
        )

    http_server, tls_issuer = _gather_stored_http_and_tls_evidence(db, seed_asset)

    if not infra_data.succeeded and http_server is None and tls_issuer is None:
        evidence = {"ip": infra_data.ip, "failure_reason": infra_data.failure_reason}
        synthetic_candidate = DiscoveryCandidate(asset_type=seed_asset.asset_type, value=seed_asset.value, evidence=evidence)
        return _record_result(
            db, run, synthetic_candidate, outcome=DiscoveryResultOutcome.failed, resulting_asset_id=seed_asset.id,
            evidence=evidence,
        )

    classification = classify_infrastructure(
        asn=infra_data.asn,
        asn_organization=infra_data.asn_organization,
        ptr_hostname=infra_data.ptr_hostname,
        http_server=http_server,
        tls_issuer=tls_issuer,
    )

    evidence = {
        "ip": infra_data.ip,
        "provider": classification.provider,
        "confidence": classification.confidence,
        "confidence_label": classification.confidence_label,
        "evidence": classification.evidence,
        "conflicting": classification.conflicting,
        "alternative_providers": classification.alternative_providers,
        "asn": infra_data.asn,
        "asn_organization": infra_data.asn_organization,
        "announced_prefix": infra_data.announced_prefix,
        "ptr_hostname": infra_data.ptr_hostname,
        "http_server": http_server,
        "tls_issuer": tls_issuer,
    }

    previous_observation = (
        db.query(Observation)
        .filter(
            Observation.asset_id == seed_asset.id,
            Observation.field_name == field_name,
            Observation.change_type.in_([ChangeType.infrastructure_observed, ChangeType.infrastructure_changed]),
        )
        .order_by(Observation.observed_at.desc())
        .first()
    )

    if previous_observation is None:
        observation_service.record_observation(
            db,
            seed_asset,
            ChangeType.infrastructure_observed,
            field_name=field_name,
            current_value=json.dumps(evidence, default=str),
            source=AssetSource.discovery,
            confidence=classification.confidence,
        )
        outcome = DiscoveryResultOutcome.observed
    elif canonicalize_for_comparison(json.loads(previous_observation.current_value)) != canonicalize_for_comparison(evidence):
        observation_service.record_observation(
            db,
            seed_asset,
            ChangeType.infrastructure_changed,
            field_name=field_name,
            previous_value=previous_observation.current_value,
            current_value=json.dumps(evidence, default=str),
            source=AssetSource.discovery,
            confidence=classification.confidence,
        )
        outcome = DiscoveryResultOutcome.refreshed
    else:
        outcome = DiscoveryResultOutcome.unchanged

    synthetic_candidate = DiscoveryCandidate(
        asset_type=seed_asset.asset_type,
        value=seed_asset.value,
        confidence=classification.confidence,
        evidence=evidence,
    )
    return _record_result(db, run, synthetic_candidate, outcome=outcome, resulting_asset_id=seed_asset.id, evidence=evidence)


def get_shared_infrastructure_groups(db: Session, organization_id) -> list[dict]:
    """Read-time correlation across an organization's ip_address assets
    (Step 9.7's "correlation across assets" requirement) -- groups them
    by their most recent infrastructure classification's (provider, ASN)
    pair. Deliberately NOT a stored relationship: two IPs that happen to
    share a provider have no direct edge between each other in the
    graph, only a shared classification each carries independently: this
    computes the grouping at read time from that existing data, rather
    than inventing an edge that doesn't represent anything concrete.

    An IP with no classification yet, or one classified as unknown
    (`provider=None`), is excluded -- grouping unknowns together would
    misleadingly imply they share infrastructure just because ASM
    couldn't attribute either of them.
    """
    ip_assets = (
        db.query(Asset)
        .filter(Asset.organization_id == organization_id, Asset.asset_type == AssetType.ip_address)
        .all()
    )

    groups: dict[tuple, dict] = {}
    for asset in ip_assets:
        latest = (
            db.query(Observation)
            .filter(
                Observation.asset_id == asset.id,
                Observation.field_name == "infrastructure",
                Observation.change_type.in_([ChangeType.infrastructure_observed, ChangeType.infrastructure_changed]),
            )
            .order_by(Observation.observed_at.desc())
            .first()
        )
        if latest is None or not latest.current_value:
            continue
        data = json.loads(latest.current_value)
        provider = data.get("provider")
        if provider is None:
            continue
        key = (provider, data.get("asn"))
        groups.setdefault(key, {"provider": provider, "asn": data.get("asn"), "assets": []})
        groups[key]["assets"].append({"asset_id": str(asset.id), "value": asset.value})

    return [group for group in groups.values() if len(group["assets"]) >= 1]


# Step 9.9.5: outcomes that mean "this candidate genuinely still
# exists" -- anything else (rejected/failed, or simply absent from a
# run's results) does not count as reconfirmation.
_RECONFIRMING_OUTCOMES = (
    DiscoveryResultOutcome.created,
    DiscoveryResultOutcome.refreshed,
    DiscoveryResultOutcome.unchanged,
)


def detect_and_mark_disappeared_candidates(
    db: Session, run: DiscoveryRun, seed_asset: Asset, provider_name: str
) -> list[AssetRelationship]:
    """Step 9.9.5 disappearance detection. Called ONLY after a run has
    been marked `completed` (see discovery_service.execute_run) -- never
    for a `failed` run. This is the core safety rule: a provider that
    failed outright tells us nothing about whether previously-found
    candidates are still there, so it must never be treated as evidence
    of disappearance. A provider that timed out on some sub-check but
    still returned `completed` overall is a harder case (see the
    zero-candidates guard below and the Step 9.9 README section for the
    full, honest discussion of what is and isn't caught here).

    Compares this run's reconfirmed candidates (DiscoveryResults with
    resulting_asset_id set and outcome in _RECONFIRMING_OUTCOMES,
    excluding the seed itself -- evidence *about* the seed, e.g. an
    HTTP/network/infrastructure observation, is not a "candidate" that
    can disappear in this sense) against the immediately preceding
    COMPLETED run for the same (seed, provider) pair. Anything found
    then but not now has its relationship from this seed marked
    disappeared via the existing, soft-remove
    asset_relationship_service.mark_relationship_disappeared -- history
    is preserved, never deleted. The candidate asset's OWN status is
    additionally marked disappeared, but only if NONE of its other
    relationships (from any other seed/provider) remain active -- an
    asset independently reconfirmed via a different path must not be
    marked disappeared just because this one path stopped confirming it.

    Safety guard: if this run reconfirmed zero candidates while the
    previous run had found at least one, nothing is marked disappeared.
    A provider's own "never raise, report an empty result" contract
    means a silent partial failure (e.g. one DNS record type timing out)
    is indistinguishable from "everything genuinely vanished" using only
    the run's overall `completed` status -- when the two are
    indistinguishable, this errs toward not destructively marking
    anything disappeared, per explicit instruction.
    """
    previous_run = (
        db.query(DiscoveryRun)
        .filter(
            DiscoveryRun.seed_asset_id == seed_asset.id,
            DiscoveryRun.provider_name == provider_name,
            DiscoveryRun.status == DiscoveryRunStatus.completed,
            DiscoveryRun.id != run.id,
        )
        .order_by(DiscoveryRun.completed_at.desc())
        .first()
    )
    if previous_run is None:
        return []  # first successful run for this (seed, provider) -- nothing to compare against yet

    def _candidate_asset_ids(discovery_run_id) -> set:
        return {
            row[0]
            for row in db.query(DiscoveryResult.resulting_asset_id)
            .filter(
                DiscoveryResult.discovery_run_id == discovery_run_id,
                DiscoveryResult.outcome.in_(_RECONFIRMING_OUTCOMES),
                DiscoveryResult.resulting_asset_id.isnot(None),
                DiscoveryResult.resulting_asset_id != seed_asset.id,
            )
            .all()
        }

    previous_candidate_ids = _candidate_asset_ids(previous_run.id)
    if not previous_candidate_ids:
        return []  # nothing was tracked before -- nothing can have disappeared

    current_candidate_ids = _candidate_asset_ids(run.id)
    if not current_candidate_ids:
        # Suspicious: a run that found nothing at all when the previous
        # run found something looks like a silent partial failure, not
        # genuine mass disappearance -- see the docstring above.
        return []

    disappeared_ids = previous_candidate_ids - current_candidate_ids
    if not disappeared_ids:
        return []

    marked_relationships: list[AssetRelationship] = []
    for candidate_id in disappeared_ids:
        relationships = (
            db.query(AssetRelationship)
            .filter(
                or_(
                    and_(AssetRelationship.source_asset_id == seed_asset.id, AssetRelationship.target_asset_id == candidate_id),
                    and_(AssetRelationship.source_asset_id == candidate_id, AssetRelationship.target_asset_id == seed_asset.id),
                ),
                AssetRelationship.status != LifecycleStatus.disappeared,
            )
            .all()
        )
        for relationship in relationships:
            asset_relationship_service.mark_relationship_disappeared(db, relationship)
            marked_relationships.append(relationship)

        _maybe_mark_asset_disappeared(db, candidate_id)

    return marked_relationships


def _maybe_mark_asset_disappeared(db: Session, asset_id) -> None:
    """Transitions an asset's own status to disappeared, but only once
    NONE of its relationships (as either source or target, from any
    seed or provider) remain active -- see
    detect_and_mark_disappeared_candidates's docstring for why this
    matters: an asset still vouched for via a different path must not
    be marked disappeared just because one path stopped confirming it.
    """
    has_active_relationship = (
        db.query(AssetRelationship)
        .filter(
            or_(AssetRelationship.source_asset_id == asset_id, AssetRelationship.target_asset_id == asset_id),
            AssetRelationship.status == LifecycleStatus.active,
        )
        .first()
        is not None
    )
    if has_active_relationship:
        return

    asset = db.get(Asset, asset_id)
    if asset is None or asset.status == LifecycleStatus.disappeared:
        return

    previous_status = asset.status
    asset.status = LifecycleStatus.disappeared
    db.flush()

    observation_service.record_observation(
        db,
        asset,
        ChangeType.asset_status_changed,
        field_name="asset_state",
        previous_value=json.dumps({"status": previous_status.value}),
        current_value=json.dumps({"status": LifecycleStatus.disappeared.value}),
        source=AssetSource.discovery,
    )


def _apply_certificate_fields(certificate: Certificate, cert_obs: CertificateObservation) -> None:
    certificate.hostname = cert_obs.hostname
    certificate.port = cert_obs.port
    certificate.issuer = cert_obs.issuer
    certificate.subject = cert_obs.subject
    certificate.valid_from = cert_obs.valid_from
    certificate.valid_until = cert_obs.valid_until
    certificate.serial_number = cert_obs.serial_number
    certificate.fingerprint_sha256 = cert_obs.fingerprint_sha256
    certificate.signature_algorithm = cert_obs.signature_algorithm
    certificate.protocol_version = cert_obs.protocol_version
    certificate.cipher_suite = cert_obs.cipher_suite
    certificate.subject_alt_names = cert_obs.subject_alt_names
    certificate.is_expired = cert_obs.is_expired
    certificate.is_self_signed = cert_obs.is_self_signed
    certificate.certificate_version = cert_obs.certificate_version
    certificate.public_key_algorithm = cert_obs.public_key_algorithm
    certificate.public_key_size = cert_obs.public_key_size
    certificate.confidence = cert_obs.confidence


def _get_or_create_asset(
    db: Session, organization_id, asset_type: AssetType, value: str, confidence: float
) -> tuple[Asset, DiscoveryResultOutcome]:
    existing = _find_asset(db, organization_id, asset_type, value)
    if existing is not None:
        return _refresh_asset(db, existing, confidence)

    asset = Asset(
        organization_id=organization_id,
        asset_type=asset_type,
        value=value,
        source=AssetSource.discovery,
        confidence=confidence,
        # Step 8.1 reserved this exact value for discovery-created rows —
        # a manually-created asset defaults to `active` (a deliberate,
        # confirmed action); a discovered one starts as a tentative
        # single observation.
        status=LifecycleStatus.first_seen,
    )
    try:
        # A SAVEPOINT, not a plain insert: on a unique-constraint
        # conflict (a concurrent discovery run creating the exact same
        # asset), only this savepoint rolls back -- not the whole
        # transaction, which would otherwise also discard this
        # DiscoveryRun and any DiscoveryResult rows already written
        # earlier in the same run.
        with db.begin_nested():
            db.add(asset)
            db.flush()
    except IntegrityError:
        existing = _find_asset(db, organization_id, asset_type, value)
        assert existing is not None, "unique-constraint conflict but no matching row found"
        return _refresh_asset(db, existing, confidence)

    observation_service.record_observation(
        db,
        asset,
        ChangeType.asset_created,
        current_value=asset.value,
        source=AssetSource.discovery,
        confidence=confidence,
    )
    return asset, DiscoveryResultOutcome.created


def _find_asset(db: Session, organization_id, asset_type: AssetType, value: str) -> Asset | None:
    return (
        db.query(Asset)
        .filter(Asset.organization_id == organization_id, Asset.asset_type == asset_type, Asset.value == value)
        .first()
    )


# Step 9.9.2: fields compared to decide whether a re-discovered asset
# has meaningfully changed. Deliberately excludes updated_at/last_seen
# (bookkeeping, not asset state) and confidence (a continuously-
# fluctuating signal-strength value, not "state" in this sense -- every
# provider's own confidence can drift slightly run to run without the
# asset itself having changed at all; treating that as a "change" would
# reintroduce exactly the noise this step exists to remove). Database
# IDs are never part of asset *state* to begin with, so there's nothing
# to exclude there.
_MEANINGFUL_ASSET_FIELDS = ("value", "asset_type", "status", "source", "environment", "criticality", "owner", "tags")


def _asset_state_snapshot(asset: Asset) -> dict:
    return {
        "value": asset.value,
        "asset_type": asset.asset_type.value,
        "status": asset.status.value,
        "source": asset.source.value,
        "environment": asset.environment.value if asset.environment else None,
        "criticality": asset.criticality.value if asset.criticality else None,
        "owner": asset.owner,
        # Tags are conceptually an unordered label set -- sorted so
        # reordering alone (e.g. from a future write path that doesn't
        # preserve insertion order) is never reported as a change.
        "tags": sorted(asset.tags) if asset.tags else [],
    }


def _diff_asset_state(previous: dict, current: dict) -> list[str]:
    return sorted(
        field
        for field in _MEANINGFUL_ASSET_FIELDS
        if canonicalize_for_comparison(previous[field]) != canonicalize_for_comparison(current[field])
    )


def _refresh_asset(db: Session, asset: Asset, confidence: float) -> tuple[Asset, DiscoveryResultOutcome]:
    """first_seen is never touched here -- only a genuinely new asset
    gets a first_seen. Re-observing something previously stale/
    disappeared revives it to active, matching
    asset_relationship_service.create_relationship's identical behavior
    for relationships.

    Step 9.9.2: an Observation is written ONLY when a meaningful field
    (see _MEANINGFUL_ASSET_FIELDS) actually differs from the asset's
    prior state -- a plain re-confirmation (the common case: same
    value/type/status/etc., just seen again) writes nothing and returns
    `unchanged`, closing the "every refresh writes a duplicate
    asset_updated row forever" gap disclosed since Step 9.1. A genuine
    change (most commonly a stale/disappeared -> active revival) writes
    one Observation capturing exactly which fields changed, previous
    and current values, and returns `refreshed`.
    """
    previous_state = _asset_state_snapshot(asset)

    asset.last_seen = datetime.now(timezone.utc)
    asset.confidence = confidence
    if asset.status in (LifecycleStatus.stale, LifecycleStatus.disappeared):
        asset.status = LifecycleStatus.active
    db.flush()

    current_state = _asset_state_snapshot(asset)
    changed_fields = _diff_asset_state(previous_state, current_state)

    if not changed_fields:
        return asset, DiscoveryResultOutcome.unchanged

    change_type = ChangeType.asset_status_changed if "status" in changed_fields else ChangeType.asset_updated
    observation_service.record_observation(
        db,
        asset,
        change_type,
        field_name="asset_state",
        previous_value=json.dumps({field: previous_state[field] for field in changed_fields}, default=str),
        current_value=json.dumps({field: current_state[field] for field in changed_fields}, default=str),
        source=AssetSource.discovery,
        confidence=confidence,
    )
    return asset, DiscoveryResultOutcome.refreshed


def _record_result(
    db: Session,
    run: DiscoveryRun,
    candidate: DiscoveryCandidate,
    *,
    outcome: DiscoveryResultOutcome,
    resulting_asset_id=None,
    evidence: dict | None = None,
) -> DiscoveryResult:
    result = DiscoveryResult(
        discovery_run_id=run.id,
        candidate_asset_type=candidate.asset_type,
        candidate_value=candidate.value,
        relationship_type=candidate.relationship_type,
        confidence=candidate.confidence,
        evidence=evidence if evidence is not None else (candidate.evidence or None),
        outcome=outcome,
        resulting_asset_id=resulting_asset_id,
    )
    db.add(result)
    db.flush()
    return result
