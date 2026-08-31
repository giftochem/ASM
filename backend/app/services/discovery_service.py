"""Synchronous orchestration for discovery runs: validate authorization +
provider, execute the provider, normalize each candidate. No Celery task
in this pass -- the stub provider does no I/O and completes instantly;
wiring a real async path (mirroring app.tasks.scan_tasks' thin-wrapper-
over-a-service pattern) is a small, additive change to make once a real,
slow provider exists, not built speculatively now.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.enums import DiscoveryRunStatus
from app.core.exceptions import AuthorizationNotConfirmedError
from app.discovery.base import DiscoveryProvider
from app.discovery.registry import get_provider
from app.models.asset import Asset
from app.models.discovery_run import DiscoveryRun
from app.models.user import User
from app.services import alert_service, discovery_normalization_service

logger = logging.getLogger(__name__)


def validate_discovery_request(seed_asset: Asset, provider_name: str) -> DiscoveryProvider:
    """The authorization guardrail's first enforcement point for
    discovery -- reuses the exact same authorization_confirmed flag and
    exception app.services.scan_service.validate_scan_request already
    uses for scans, not a parallel mechanism.
    """
    if not seed_asset.authorization_confirmed:
        raise AuthorizationNotConfirmedError(
            f"Asset '{seed_asset.value}' does not have authorization_confirmed=true. "
            "Confirm authorization via POST /assets/{id}/confirm-authorization before running discovery."
        )

    provider = get_provider(provider_name)
    if provider is None:
        raise ValueError(f"unknown discovery provider: '{provider_name}'")
    if not provider.supports(seed_asset.asset_type):
        raise ValueError(
            f"provider '{provider_name}' does not support asset_type '{seed_asset.asset_type.value}'"
        )
    return provider


def create_run(
    db: Session, seed_asset: Asset, provider_name: str, user: User, *, schedule_id=None
) -> DiscoveryRun:
    """`schedule_id` is optional and additive (Step 9.11) -- unset for
    every manually-triggered run (the overwhelming majority, and every
    existing caller), set by discovery_scheduler_executor to link a
    scheduled run back to the DiscoverySchedule that produced it.
    """
    run = DiscoveryRun(
        organization_id=seed_asset.organization_id,
        seed_asset_id=seed_asset.id,
        initiated_by=user.id,
        provider_name=provider_name,
        status=DiscoveryRunStatus.queued,
        schedule_id=schedule_id,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def execute_run(db: Session, run: DiscoveryRun, provider: DiscoveryProvider, seed_asset: Asset) -> DiscoveryRun:
    """Synchronous end-to-end execution: run the provider, normalize
    every candidate, finalize status. The provider call is wrapped in
    try/except as a last-resort safety net -- mirrors scan_executor's
    identical treatment of scanner modules -- on top of providers'
    own "never raise, report via result.error" contract.
    """
    run.status = DiscoveryRunStatus.running
    run.started_at = datetime.now(timezone.utc)
    db.commit()

    try:
        provider_result = provider.discover(seed_asset.value)
    except Exception as exc:
        return _fail_run(db, run, str(exc))

    if provider_result.error is not None:
        return _fail_run(db, run, provider_result.error)

    for candidate in provider_result.candidates:
        discovery_normalization_service.normalize_candidate(db, run, seed_asset, candidate)

    if provider_result.seed_evidence:
        discovery_normalization_service.record_seed_evidence(
            db, run, seed_asset, provider_result.seed_evidence, change_type=provider_result.seed_evidence_change_type
        )

    if provider_result.certificate_data:
        discovery_normalization_service.record_certificate_observation(
            db, run, seed_asset, provider_result.certificate_data
        )

    for http_obs in provider_result.http_observations:
        discovery_normalization_service.record_http_observation(db, run, seed_asset, http_obs)

    if provider_result.network_data:
        discovery_normalization_service.record_network_observation(db, run, seed_asset, provider_result.network_data)

    if provider_result.infrastructure_data:
        discovery_normalization_service.record_infrastructure_observation(
            db, run, seed_asset, provider_result.infrastructure_data
        )

    run.status = DiscoveryRunStatus.completed
    run.completed_at = datetime.now(timezone.utc)

    # Step 9.9.5: only a run that reached `completed` is eligible to
    # mark previously-found candidates disappeared -- deliberately after
    # the status assignment above, and never reached at all for a
    # failed run (which returns via _fail_run below, before this line).
    disappeared_relationships = discovery_normalization_service.detect_and_mark_disappeared_candidates(
        db, run, seed_asset, provider.name
    )

    # Step 9.12: alert evaluation runs in the same place, for the same
    # reason -- a failed run never reaches this line at all. Wrapped in
    # both a SAVEPOINT and try/except so a bug in alerting can never
    # turn a successful discovery into a failed one (Step 9.12.11's
    # explicit requirement): a plain try/except alone isn't sufficient
    # here, because alert_service does real writes (including a
    # `.with_for_update()` lock) that could, in the worst case (e.g. a
    # genuine deadlock under concurrent load), abort the whole
    # PostgreSQL transaction, not just raise a Python exception --
    # which would silently discard this run's own `completed` status
    # and the disappearance-detection results above along with it. The
    # SAVEPOINT confines any such failure to itself, exactly like
    # alert_service._create_or_update_alert already does one level
    # down for its own INSERT/conflict handling.
    new_alerts = []
    try:
        with db.begin_nested():
            new_alerts = alert_service.evaluate_run_for_alerts(
                db, run, seed_asset, disappeared_relationships=disappeared_relationships
            )
    except Exception:
        logger.exception("alert evaluation failed for discovery_run_id=%s -- run itself still completed", run.id)

    db.commit()
    db.refresh(run)

    # Notifications are only queued AFTER this commit succeeds -- never
    # for an alert that might not durably exist (Step 9.12.11's
    # "discovery -> alert -> queue notification" ordering).
    if new_alerts:
        try:
            alert_service.queue_notifications(db, new_alerts)
        except Exception:
            logger.exception("failed to queue alert notifications for discovery_run_id=%s", run.id)

    return run


def _fail_run(db: Session, run: DiscoveryRun, error_message: str) -> DiscoveryRun:
    run.status = DiscoveryRunStatus.failed
    run.error_message = error_message
    run.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(run)
    return run
