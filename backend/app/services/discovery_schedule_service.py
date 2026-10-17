"""Request-facing CRUD/validation for DiscoverySchedule (Step 9.11) --
mirrors scan_service.py's split from scan_executor.py exactly: this
module handles everything decidable synchronously in the HTTP request
(validation, creation, enable/disable, deletion); the worker-facing
half (discovery_scheduler_executor.py) handles everything that must
run inside a Celery worker, outside any request lifecycle.
"""

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.exceptions import AuthorizationNotConfirmedError
from app.discovery.registry import get_provider
from app.models.asset import Asset
from app.models.discovery_schedule import DiscoverySchedule
from app.models.user import User

MIN_INTERVAL_HOURS = 1
# One month -- a sane, documented upper bound. Not cron: this project
# deliberately doesn't parse arbitrary cron expressions (Step 9.11 non-
# goal) -- a plain interval is "the smallest explicit mechanism that is
# useful."
MAX_INTERVAL_HOURS = 24 * 30


def validate_schedule_request(seed_asset: Asset, provider_name: str, interval_hours: int) -> None:
    """Raises AuthorizationNotConfirmedError/ValueError for the route to
    translate into 403/400 -- reuses the exact same authorization
    guardrail app.services.discovery_service.validate_discovery_request
    already established for manual discovery, not a parallel check.
    """
    if not seed_asset.authorization_confirmed:
        raise AuthorizationNotConfirmedError(
            f"Asset '{seed_asset.value}' does not have authorization_confirmed=true. "
            "A schedule cannot be created for an asset that isn't currently authorized."
        )

    provider = get_provider(provider_name)
    if provider is None:
        raise ValueError(f"unknown discovery provider: '{provider_name}'")
    if not provider.supports(seed_asset.asset_type):
        raise ValueError(
            f"provider '{provider_name}' does not support asset_type '{seed_asset.asset_type.value}'"
        )

    _validate_interval(interval_hours)


def _validate_interval(interval_hours: int) -> None:
    if not (MIN_INTERVAL_HOURS <= interval_hours <= MAX_INTERVAL_HOURS):
        raise ValueError(f"interval_hours must be between {MIN_INTERVAL_HOURS} and {MAX_INTERVAL_HOURS}")


def create_schedule(
    db: Session, seed_asset: Asset, provider_name: str, interval_hours: int, user: User
) -> DiscoverySchedule:
    """Eligible immediately (`next_run_at=now`) -- the dispatcher's own
    claim query is the sole arbiter of actual execution timing, so
    there's no separate "first run" special case to get right here.
    """
    schedule = DiscoverySchedule(
        organization_id=seed_asset.organization_id,
        seed_asset_id=seed_asset.id,
        provider_name=provider_name,
        created_by=user.id,
        interval_hours=interval_hours,
        next_run_at=datetime.now(timezone.utc),
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return schedule


def update_schedule(
    db: Session, schedule: DiscoverySchedule, *, enabled: bool | None = None, interval_hours: int | None = None
) -> DiscoverySchedule:
    # Everything is validated before anything is mutated, so a rejected
    # request never leaves a half-applied change on the session.
    if interval_hours is not None:
        _validate_interval(interval_hours)
    if enabled and get_provider(schedule.provider_name) is None:
        # A schedule whose provider isn't available in this deployment
        # (e.g. one created for the test-only `stub` provider) can never
        # execute, so re-enabling it is refused rather than allowed to
        # fail on every tick. Disabling it is still allowed.
        raise ValueError(f"unknown discovery provider: '{schedule.provider_name}'")

    if interval_hours is not None:
        schedule.interval_hours = interval_hours

    if enabled is not None:
        schedule.enabled = enabled
        if enabled:
            # A person re-enabling a schedule (including one this
            # system auto-disabled for revoked authorization) is an
            # explicit new attestation that it's fine to run again --
            # clear the reason and make it immediately eligible,
            # matching create_schedule's own "eligible immediately"
            # behavior.
            schedule.disabled_reason = None
            schedule.next_run_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(schedule)
    return schedule


def delete_schedule(db: Session, schedule: DiscoverySchedule) -> None:
    db.delete(schedule)
    db.commit()
