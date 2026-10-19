"""Synthetic builders for the Stage A.2 exposure-evidence and traversal
tests. Rows are written straight to the test database so each test
controls every timestamp; nothing here touches the network or any real
organization's data."""

import uuid
from datetime import datetime, timedelta, timezone

from app.core.enums import (
    AssetSource,
    AssetType,
    ChangeType,
    DiscoveryResultOutcome,
    DiscoveryRunStatus,
    LifecycleStatus,
    RelationshipType,
    ScanStatus,
    UserRole,
)
from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.models.audit_log import AuditLog
from app.models.certificate import Certificate
from app.models.discovery_result import DiscoveryResult
from app.models.discovery_run import DiscoveryRun
from app.models.observation import Observation
from app.models.organization import Organization
from app.models.port_scan_result import PortScanResult
from app.models.scan import Scan
from app.models.ssl_info import SSLInfo
from app.models.user import User

AS_OF = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)


def ago(**delta) -> datetime:
    return AS_OF - timedelta(**delta)


def make_org(db, name: str):
    org = Organization(name=name)
    db.add(org)
    db.flush()
    user = User(
        organization_id=org.id,
        email=f"{uuid.uuid4().hex[:10]}@example.com",
        hashed_password="not-a-real-hash",
        full_name="Analyst",
        role=UserRole.analyst,
    )
    db.add(user)
    db.flush()
    return org, user


def make_asset(db, org, value: str, asset_type: AssetType = AssetType.domain, **fields) -> Asset:
    asset = Asset(organization_id=org.id, asset_type=asset_type, value=value, **fields)
    db.add(asset)
    db.flush()
    return asset


def make_run(db, org, user, seed: Asset, provider: str, *, at: datetime, status=DiscoveryRunStatus.completed) -> DiscoveryRun:
    run = DiscoveryRun(
        organization_id=org.id,
        seed_asset_id=seed.id,
        initiated_by=user.id,
        provider_name=provider,
        status=status,
        started_at=at,
        completed_at=at if status in (DiscoveryRunStatus.completed, DiscoveryRunStatus.failed) else None,
    )
    db.add(run)
    db.flush()
    return run


def http_result(db, org, user, seed: Asset, scheme: str, *, at: datetime, status_code=200,
                outcome=DiscoveryResultOutcome.observed, provider="http", run_status=DiscoveryRunStatus.completed) -> DiscoveryResult:
    """Mirrors record_http_observation's stored shape."""
    run = make_run(db, org, user, seed, provider, at=at, status=run_status)
    if outcome is DiscoveryResultOutcome.failed:
        evidence = {"scheme": scheme, "requested_url": f"{scheme}://{seed.value}/", "failure_reason": "timed out"}
    elif outcome is DiscoveryResultOutcome.rejected:
        evidence = {"scheme": scheme, "requested_url": f"{scheme}://{seed.value}/", "final_url": "https://elsewhere.example.net/",
                    "external_redirect_host": "elsewhere.example.net",
                    "rejection_reason": "redirect target left the seed's authorized scope"}
    else:
        evidence = {"scheme": scheme, "requested_url": f"{scheme}://{seed.value}/", "final_url": f"{scheme}://{seed.value}/",
                    "status_code": status_code, "server": "Vercel"}
    result = DiscoveryResult(
        discovery_run_id=run.id, candidate_asset_type=seed.asset_type, candidate_value=f"{seed.value}:{scheme}",
        confidence=1.0, evidence=evidence, outcome=outcome, resulting_asset_id=seed.id, created_at=at,
    )
    db.add(result)
    db.flush()
    return result


def tls_result(db, org, user, seed: Asset, *, at: datetime, outcome=DiscoveryResultOutcome.created, port=443) -> DiscoveryResult:
    """Mirrors record_certificate_observation's stored shape (a result
    only exists after a completed handshake)."""
    run = make_run(db, org, user, seed, "certificate", at=at)
    result = DiscoveryResult(
        discovery_run_id=run.id, candidate_asset_type=seed.asset_type, candidate_value=f"{seed.value}:{port}",
        confidence=1.0, evidence={"fingerprint_sha256": "ab" * 32}, outcome=outcome, resulting_asset_id=seed.id, created_at=at,
    )
    db.add(result)
    db.flush()
    return result


def certificate_row(db, asset: Asset, *, at: datetime, port=443) -> Certificate:
    certificate = Certificate(asset_id=asset.id, hostname=asset.value, port=port, first_seen=at, last_seen=at,
                              source=AssetSource.discovery, fingerprint_sha256="ab" * 32)
    db.add(certificate)
    db.flush()
    return certificate


def observation(db, asset: Asset, change_type: ChangeType, *, at: datetime, field_name=None, current_value=None) -> Observation:
    row = Observation(asset_id=asset.id, change_type=change_type, field_name=field_name, current_value=current_value,
                      observed_at=at, source=AssetSource.discovery)
    db.add(row)
    db.flush()
    return row


def make_scan(db, user, asset: Asset, modules, *, completed_at, status=ScanStatus.completed) -> Scan:
    scan = Scan(asset_id=asset.id, initiated_by=user.id, status=status, modules_requested=list(modules),
                started_at=completed_at, completed_at=completed_at)
    db.add(scan)
    db.flush()
    return scan


def port_result(db, scan: Scan, port: int, state: str) -> PortScanResult:
    row = PortScanResult(asset_id=scan.asset_id, scan_id=scan.id, port=port, protocol="tcp", state=state)
    db.add(row)
    db.flush()
    return row


def ssl_result(db, scan: Scan, asset: Asset, port=443) -> SSLInfo:
    row = SSLInfo(asset_id=asset.id, scan_id=scan.id, hostname=asset.value, port=port)
    db.add(row)
    db.flush()
    return row


def relate(db, source: Asset, target: Asset, relationship_type: RelationshipType, *, source_kind=AssetSource.discovery,
           status=LifecycleStatus.active, confidence=1.0) -> AssetRelationship:
    relationship = AssetRelationship(
        source_asset_id=source.id, target_asset_id=target.id, relationship_type=relationship_type, status=status,
        source=source_kind, confidence=confidence, first_seen=ago(days=30), last_seen=ago(days=1),
    )
    db.add(relationship)
    db.flush()
    return relationship


def dns_result(db, org, user, source: Asset, target: Asset, *, at=None, record_type="A",
               outcome=DiscoveryResultOutcome.created, provider="dns", run_status=DiscoveryRunStatus.completed) -> DiscoveryResult:
    """Mirrors what normalize_candidate stores for an accepted dns
    candidate: the run's seed is the source, the result names the target
    and carries the relationship type and record evidence."""
    at = at or ago(days=1)
    run = make_run(db, org, user, source, provider, at=at, status=run_status)
    result = DiscoveryResult(
        discovery_run_id=run.id, candidate_asset_type=target.asset_type, candidate_value=target.value,
        relationship_type=RelationshipType.resolves_to, confidence=0.9,
        evidence={"record_type": record_type, "name": source.value}, outcome=outcome,
        resulting_asset_id=target.id, created_at=at,
    )
    db.add(result)
    db.flush()
    return result


def observed_dns(db, org, user, source: Asset, target: Asset, *, status=LifecycleStatus.active, at=None,
                 record_type="A", confidence=1.0) -> AssetRelationship:
    """A discovery-created resolves_to backed by its dns result."""
    dns_result(db, org, user, source, target, at=at, record_type=record_type)
    return relate(db, source, target, RelationshipType.resolves_to, status=status, confidence=confidence)


def creation_audit(db, org, user, relationship: AssetRelationship, *, at=None) -> AuditLog:
    entry = AuditLog(user_id=user.id, organization_id=org.id, action="asset.relationship.create",
                     resource_type="asset_relationship", resource_id=relationship.id, created_at=at or ago(days=3))
    db.add(entry)
    db.flush()
    return entry
