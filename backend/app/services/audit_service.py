import uuid

from sqlalchemy.orm import Session

from app.core.enums import AuditOutcome
from app.models.audit_log import AuditLog


def log_action(
    db: Session,
    *,
    user_id: uuid.UUID | None,
    organization_id: uuid.UUID | None,
    action: str,
    resource_type: str,
    resource_id: uuid.UUID | None = None,
    outcome: AuditOutcome = AuditOutcome.success,
    details: dict | None = None,
    ip_address: str | None = None,
) -> AuditLog:
    """Adds an AuditLog row to the session without committing — the caller
    commits as part of the same transaction as the write action being
    logged, so an audit entry never survives a rolled-back write (or vice
    versa).

    `details` must never contain passwords, JWTs/refresh tokens, CSRF
    tokens, or any other secret — see app/models/audit_log.py.
    """
    entry = AuditLog(
        user_id=user_id,
        organization_id=organization_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        details=details,
        ip_address=ip_address,
    )
    db.add(entry)
    db.flush()
    return entry
