"""Step 9.12's one notification channel: email, via smtplib (Python's
standard library) against a configurable SMTP relay
(Settings.smtp_*) -- no third-party email API dependency added.
Delivery is entirely optional and config-gated
(Settings.alert_notification_email_enabled, default False) -- see
app.services.alert_service.queue_notifications for why a disabled
deployment never even creates an AlertNotification row.

The email body deliberately never includes an Alert's full `evidence`
JSON blob -- only title/description/priority/type/asset value/
timestamps/occurrence_count. Evidence is appropriate to show an
authenticated analyst inside the product (via GET /alerts/{id}) but
unnecessary to forward verbatim into an inbox outside ASM's own access
control.
"""

import smtplib
import ssl
from email.message import EmailMessage

from sqlalchemy.orm import Session

from app.config import settings
from app.core.enums import UserRole
from app.models.alert import Alert
from app.models.user import User


def get_notification_recipients(db: Session, organization_id) -> list[str]:
    """Org admins only -- no per-user notification-preference concept
    exists yet (an explicit non-goal for this pass, matching how
    `owner`/`tags` have no established vocabulary either); admins are
    the role already trusted with every other org-wide write action.
    """
    return [
        user.email
        for user in db.query(User)
        .filter(User.organization_id == organization_id, User.role == UserRole.admin, User.is_active.is_(True))
        .order_by(User.email)
        .all()
    ]


def render_alert_email(alert: Alert, recipients: list[str]) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = f"[ASM][{alert.priority.value.upper()}] {alert.title}"
    message["From"] = settings.smtp_from_address
    message["To"] = ", ".join(recipients)
    body_lines = [
        alert.description,
        "",
        f"Alert type: {alert.alert_type.value}",
        f"Priority: {alert.priority.value}",
        f"Status: {alert.status.value}",
        f"First seen: {alert.first_seen_at.isoformat()}",
        f"Last seen: {alert.last_seen_at.isoformat()}",
        f"Occurrences: {alert.occurrence_count}",
        "",
        f"View full evidence and act on this alert via the ASM API: GET /alerts/{alert.id}",
    ]
    message.set_content("\n".join(body_lines))
    return message


def send_email(message: EmailMessage) -> None:
    """The one I/O seam this module exposes -- unit tests monkeypatch
    this function directly (matching e.g. test_http_provider.py's
    convention of mocking at the outermost I/O call), while
    test_alert_notifications.py additionally runs one test against a
    genuine local SMTP-protocol socket server, the same "don't mock
    away the boundary in every test" precedent test_http_provider_ssrf.py
    already established for HTTP/TLS.
    """
    context = ssl.create_default_context()
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=settings.smtp_timeout_seconds) as client:
        if settings.smtp_use_tls:
            client.starttls(context=context)
        if settings.smtp_username:
            client.login(settings.smtp_username, settings.smtp_password)
        client.send_message(message)
