"""The actual scan pipeline: execute modules, normalize findings, persist,
score. Runs inside a Celery worker (via app.tasks.scan_tasks) — always
opens its own DB session rather than reusing a caller's, since a worker
process has no request-scoped session to borrow.

Authorization is re-checked here, immediately before any module runs,
even though app.services.scan_service already checked it once at
scan-creation time. That first check can go stale: time passes between a
scan being queued and a worker picking it up, and during that window an
admin/analyst can revoke authorization (POST /assets/{id}/revoke-
authorization), deactivate the asset, or cancel the scan outright. This
function is the one place that's guaranteed to run right before any
network call actually happens, so it's the only check that can't be
bypassed by that race — everything here fails closed: any doubt at all
means the scan is marked failed and nothing runs.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import update
from sqlalchemy.orm import Session

from app import database
from app.core.enums import AuditOutcome, ScanStatus
from app.models.asset import Asset
from app.models.dns_record import DNSRecord
from app.models.finding import Finding
from app.models.port_scan_result import PortScanResult
from app.models.scan import Scan
from app.models.ssl_info import SSLInfo
from app.models.technology import Technology
from app.models.user import User
from app.scanners.base import ScanModuleResult
from app.scanners.registry import get_module
from app.services import audit_service, risk_engine


@dataclass
class _BlockedReason:
    reason: str


def _check_still_authorized(db: Session, scan: Scan) -> tuple[Asset | None, _BlockedReason | None]:
    """Fail-closed re-validation. Returns (asset, None) if execution may
    proceed, or (asset_or_None, _BlockedReason) if it must not.
    """
    asset = db.get(Asset, scan.asset_id)
    if asset is None:
        return None, _BlockedReason("Asset no longer exists")
    if not asset.is_active:
        return asset, _BlockedReason("Asset has been deactivated and is outside authorized scope")
    if not asset.authorization_confirmed:
        return asset, _BlockedReason("Authorization was revoked before execution")
    if scan.status not in (ScanStatus.queued, ScanStatus.running):
        # `running` is allowed here because a Celery retry re-enters this
        # function for a scan its own earlier (failed) attempt already
        # marked running — that's a legitimate continuation, not a stale
        # scan. `cancelled`/`completed`/`failed` are not.
        return asset, _BlockedReason(
            f"Scan is not in a runnable state (status='{scan.status.value}'); refusing to execute"
        )

    user = db.get(User, scan.initiated_by)
    if user is None or not user.is_active:
        return asset, _BlockedReason("Initiating user no longer exists or is inactive")
    if user.organization_id != asset.organization_id:
        return asset, _BlockedReason(
            "Initiating user no longer has permission over this asset's organization"
        )

    return asset, None


def _mark_blocked(db: Session, scan: Scan, asset: Asset | None, blocked: _BlockedReason) -> None:
    # A scan already sitting in `cancelled` is in a deliberate, legitimate
    # terminal state a user chose — leave it alone rather than
    # relabeling it `failed`. Every other blocked reason (asset gone/
    # deactivated, authorization revoked, user no longer permitted) is a
    # genuine failure to execute.
    if scan.status != ScanStatus.cancelled:
        scan.status = ScanStatus.failed
        scan.error_message = blocked.reason
        scan.completed_at = datetime.now(timezone.utc)
    audit_service.log_action(
        db,
        user_id=scan.initiated_by,
        organization_id=asset.organization_id if asset else None,
        action="scan.blocked_at_execution",
        resource_type="scan",
        resource_id=scan.id,
        outcome=AuditOutcome.failure,
        details={"reason": blocked.reason},
    )
    db.commit()


def _persist_module_result(db: Session, scan: Scan, asset: Asset, result: ScanModuleResult) -> None:
    for finding in result.findings:
        db.add(
            Finding(
                scan_id=scan.id,
                asset_id=asset.id,
                module=result.module,
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                confidence=finding.confidence,
                exposure=finding.exposure,
                exploitability=finding.exploitability,
                evidence=finding.evidence,
            )
        )

    if result.error:
        db.add(
            Finding(
                scan_id=scan.id,
                asset_id=asset.id,
                module=result.module,
                title=f"{result.module} module could not complete",
                description=result.error,
                evidence={"error": True},
            )
        )
        return

    if result.module == "dns":
        for record in result.raw_data.get("records", []):
            db.add(
                DNSRecord(
                    asset_id=asset.id,
                    scan_id=scan.id,
                    record_type=record["type"],
                    name=record["name"],
                    value=record["value"],
                    ttl=record.get("ttl"),
                )
            )
    elif result.module == "ssl":
        data = result.raw_data
        if data:
            db.add(
                SSLInfo(
                    asset_id=asset.id,
                    scan_id=scan.id,
                    hostname=data["hostname"],
                    port=data["port"],
                    issuer=data.get("issuer"),
                    subject=data.get("subject"),
                    valid_from=datetime.fromisoformat(data["valid_from"]) if data.get("valid_from") else None,
                    valid_until=datetime.fromisoformat(data["valid_until"]) if data.get("valid_until") else None,
                    serial_number=data.get("serial_number"),
                    signature_algorithm=data.get("signature_algorithm"),
                    protocol_version=data.get("protocol_version"),
                    cipher_suite=data.get("cipher_suite"),
                    subject_alt_names=data.get("subject_alt_names"),
                    is_expired=data.get("is_expired", False),
                    is_self_signed=data.get("is_self_signed", False),
                )
            )
    elif result.module == "technology":
        for tech in result.raw_data.get("technologies", []):
            db.add(
                Technology(
                    asset_id=asset.id,
                    scan_id=scan.id,
                    name=tech["name"],
                    version=tech.get("version"),
                    category=tech.get("category"),
                    detection_method=tech.get("detection_method"),
                    confidence=tech.get("confidence"),
                )
            )
    elif result.module == "port_scanner":
        for port_result in result.raw_data.get("ports", []):
            db.add(
                PortScanResult(
                    asset_id=asset.id,
                    scan_id=scan.id,
                    port=port_result["port"],
                    protocol=port_result.get("protocol", "tcp"),
                    state=port_result["state"],
                )
            )


def execute_scan(scan_id: uuid.UUID | str) -> None:
    """Opens its own session via `database.SessionLocal` (looked up as a
    module attribute, not imported by value) specifically so tests can
    monkeypatch `app.database.SessionLocal` to point execution at the test
    database — see the `eager_celery` fixture in tests/conftest.py. A
    plain `from app.database import SessionLocal` would bind a frozen
    reference at import time that such a monkeypatch couldn't reach.
    """
    db = database.SessionLocal()
    try:
        scan = db.get(Scan, uuid.UUID(str(scan_id)))
        if scan is None:
            return

        asset, blocked = _check_still_authorized(db, scan)
        if blocked is not None:
            _mark_blocked(db, scan, asset, blocked)
            return

        # Atomic conditional transition, not read-then-write: the check
        # above and this UPDATE are two separate steps, and a concurrent
        # cancellation (or another worker retry) could land in between
        # them. The WHERE clause makes Postgres the arbiter of whether
        # this transition is still valid at the instant it actually
        # commits — if a cancellation won the race, rowcount is 0 and we
        # back off instead of clobbering it with status='running'.
        now = datetime.now(timezone.utc)
        result = db.execute(
            update(Scan)
            .where(Scan.id == scan.id, Scan.status.in_([ScanStatus.queued, ScanStatus.running]))
            .values(status=ScanStatus.running, started_at=now)
        )
        db.commit()
        db.refresh(scan)
        if result.rowcount == 0:
            audit_service.log_action(
                db,
                user_id=scan.initiated_by,
                organization_id=asset.organization_id,
                action="scan.blocked_at_execution",
                resource_type="scan",
                resource_id=scan.id,
                outcome=AuditOutcome.failure,
                details={"reason": "lost race transitioning to running", "status": scan.status.value},
            )
            db.commit()
            return

        module_errors: list[str] = []
        any_findings = False
        stopped_early_reason: str | None = None

        for module_name in scan.modules_requested:
            # Re-checked immediately before EACH module, not just once
            # before the batch: authorization can be revoked (or the
            # asset deactivated, or — belt and suspenders — the scan
            # itself cancelled) while earlier modules in a multi-module
            # scan are still running. Findings already persisted by
            # modules that ran under valid authorization are kept; no
            # further module runs once this trips.
            _, blocked = _check_still_authorized(db, scan)
            if blocked is not None:
                stopped_early_reason = blocked.reason
                audit_service.log_action(
                    db,
                    user_id=scan.initiated_by,
                    organization_id=asset.organization_id,
                    action="scan.blocked_at_execution",
                    resource_type="scan",
                    resource_id=scan.id,
                    outcome=AuditOutcome.failure,
                    details={"reason": blocked.reason, "stopped_before_module": module_name},
                )
                break

            module = get_module(module_name)
            if module is None:
                module_errors.append(f"{module_name}: module no longer registered")
                continue
            try:
                result = module.run(asset.value)
            except Exception as exc:  # a module must never take the whole scan down
                result = ScanModuleResult(module=module_name, error=f"unexpected error: {exc}")

            if result.error:
                module_errors.append(f"{module_name}: {result.error}")
            if result.findings:
                any_findings = True
            _persist_module_result(db, scan, asset, result)

        scan.completed_at = datetime.now(timezone.utc)
        if stopped_early_reason is not None:
            scan.status = ScanStatus.failed
            scan.error_message = f"Execution stopped: {stopped_early_reason}"
            if module_errors:
                scan.error_message += "; prior module errors: " + "; ".join(module_errors)
        elif module_errors and not any_findings:
            scan.status = ScanStatus.failed
            scan.error_message = "; ".join(module_errors)
        else:
            scan.status = ScanStatus.completed
            scan.error_message = "; ".join(module_errors) if module_errors else None

        db.flush()
        findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
        scan.risk_score, scan.risk_severity_band = risk_engine.compute_scan_risk(findings)

        audit_service.log_action(
            db,
            user_id=scan.initiated_by,
            organization_id=asset.organization_id,
            action="scan.execute",
            resource_type="scan",
            resource_id=scan.id,
            outcome=AuditOutcome.success if scan.status == ScanStatus.completed else AuditOutcome.failure,
            details={"modules": scan.modules_requested, "status": scan.status.value},
        )
        db.commit()
    finally:
        db.close()
