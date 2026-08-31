"""Worker-facing execution for Step 9.12 email delivery -- mirrors
scan_executor/discovery_scheduler_executor's shape: opens its own DB
session via `database.SessionLocal` looked up as a module attribute
(not `from app.database import SessionLocal`), the same reason those
modules do this -- a plain import binds a frozen reference at import
time that tests couldn't monkeypatch to redirect at the test database
(see `executor_uses_test_db` in tests/conftest.py).

RETRY SAFETY (Step 9.12.12): claiming a notification via an atomic
conditional UPDATE (`WHERE status IN ('pending', 'failed_transient')`)
before any SMTP I/O is what makes a retried/duplicate task invocation a
safe no-op -- a second call for the same notification_id finds
rowcount==0 and returns 'skipped' without sending twice. This is the
same atomic-conditional-UPDATE pattern used everywhere else in this
codebase for exactly this reason (scan_executor's queued->running
transition, discovery_scheduler_executor's run claim).
"""

import smtplib
import socket
import uuid
from datetime import datetime, timezone

from sqlalchemy import update

from app import database
from app.core.enums import NotificationStatus
from app.models.alert import Alert
from app.models.alert_notification import AlertNotification
from app.services import alert_notification_service

MAX_ATTEMPTS = 3

# SMTPRecipientsRefused/SMTPAuthenticationError/SMTPSenderRefused mean
# retrying with the exact same message/credentials will never succeed
# -- a permanent, not transient, failure. Everything else network/
# protocol-related (connection refused, disconnected mid-handshake,
# timeout) is assumed transient and retried up to MAX_ATTEMPTS.
_PERMANENT_EXCEPTIONS = (smtplib.SMTPRecipientsRefused, smtplib.SMTPAuthenticationError, smtplib.SMTPSenderRefused)
_TRANSIENT_EXCEPTIONS = (
    smtplib.SMTPConnectError,
    smtplib.SMTPServerDisconnected,
    smtplib.SMTPHeloError,
    TimeoutError,
    socket.timeout,
    ConnectionError,
    OSError,
)


def deliver(notification_id: str) -> str:
    """Returns one of: 'skipped', 'sent', 'transient_failure',
    'permanent_failure'. The Celery task wrapper (app.tasks.
    alert_notification_tasks) retries only on 'transient_failure'.
    """
    db = database.SessionLocal()
    try:
        notification_uuid = uuid.UUID(str(notification_id))

        result = db.execute(
            update(AlertNotification)
            .where(
                AlertNotification.id == notification_uuid,
                AlertNotification.status.in_([NotificationStatus.pending, NotificationStatus.failed_transient]),
            )
            .values(status=NotificationStatus.sending, last_attempt_at=datetime.now(timezone.utc))
        )
        db.commit()
        if result.rowcount == 0:
            return "skipped"

        notification = db.get(AlertNotification, notification_uuid)
        alert = db.get(Alert, notification.alert_id)
        notification.attempts += 1

        if alert is None:
            notification.status = NotificationStatus.failed_permanent
            notification.error_message = "Alert no longer exists"
            db.commit()
            return "permanent_failure"

        recipients = alert_notification_service.get_notification_recipients(db, alert.organization_id)
        if not recipients:
            notification.status = NotificationStatus.failed_permanent
            notification.error_message = "No active admin recipients found for this organization"
            db.commit()
            return "permanent_failure"

        message = alert_notification_service.render_alert_email(alert, recipients)
        try:
            alert_notification_service.send_email(message)
        except _PERMANENT_EXCEPTIONS as exc:
            notification.status = NotificationStatus.failed_permanent
            notification.error_message = str(exc)
            db.commit()
            return "permanent_failure"
        except _TRANSIENT_EXCEPTIONS as exc:
            if notification.attempts >= MAX_ATTEMPTS:
                notification.status = NotificationStatus.failed_permanent
                notification.error_message = f"Exceeded max attempts ({MAX_ATTEMPTS}): {exc}"
                db.commit()
                return "permanent_failure"
            notification.status = NotificationStatus.failed_transient
            notification.error_message = str(exc)
            db.commit()
            return "transient_failure"

        notification.status = NotificationStatus.sent
        notification.delivered_at = datetime.now(timezone.utc)
        db.commit()
        return "sent"
    finally:
        db.close()
