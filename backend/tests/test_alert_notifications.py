"""Step 9.12.10-12: email notification rendering, delivery, retry
safety, and idempotency. Unit tests monkeypatch
alert_notification_service.send_email directly (the same "mock at the
outermost I/O boundary" convention test_http_provider.py already
established for fetch_url); one test additionally runs the real,
unmocked send_email -> smtplib -> a genuine local TCP socket speaking
just enough SMTP to complete a send, mirroring test_certificate_provider.py's
local-TLS-server precedent for "don't mock away the boundary in every
test."
"""

import smtplib
import socket
import threading
import uuid
from datetime import datetime, timezone

import pytest

from app.config import settings
from app.core.enums import AlertPriority, AlertType, NotificationChannel, NotificationStatus
from app.models.alert import Alert
from app.models.alert_notification import AlertNotification
from app.models.asset import Asset
from app.models.user import User
from app.services import alert_delivery_executor, alert_notification_service, alert_service


def _seed_asset_and_admin(client, register_user, db, email, value):
    headers = register_user(email=email)
    resp = client.post("/assets", json={"asset_type": "domain", "value": value}, headers=headers)
    assert resp.status_code == 201, resp.text
    asset = resp.json()
    confirm = client.post(
        f"/assets/{asset['id']}/confirm-authorization", json={"authorization_confirmed": True}, headers=headers
    )
    assert confirm.status_code == 200, confirm.text
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))
    admin_user = db.query(User).filter(User.email == email).first()
    return seed_asset, admin_user


def _make_alert(db, seed_asset, identity="notif") -> Alert:
    candidate = alert_service.AlertCandidate(
        alert_type=AlertType.certificate_changed, asset_id=seed_asset.id, relationship_id=None,
        source_observation_id=None, discovery_run_id=None, priority=AlertPriority.high,
        title="Test alert", description="A test alert description",
        evidence={"api_key": "should-not-appear-in-email"},
        fingerprint=alert_service._fingerprint(seed_asset.organization_id, AlertType.certificate_changed, seed_asset.id, identity),
    )
    alert, _ = alert_service._create_or_update_alert(db, seed_asset.organization_id, None, candidate)
    db.commit()
    db.refresh(alert)
    return alert


def _make_notification(db, alert: Alert, status=NotificationStatus.pending) -> AlertNotification:
    notification = AlertNotification(alert_id=alert.id, channel=NotificationChannel.email, status=status)
    db.add(notification)
    db.commit()
    db.refresh(notification)
    return notification


# --- Rendering / recipients ---------------------------------------------------


def test_render_alert_email_never_includes_full_evidence(client, register_user, db):
    seed_asset, admin = _seed_asset_and_admin(client, register_user, db, "notif-render@example.com", "notif-render.example.com")
    alert = _make_alert(db, seed_asset)

    message = alert_notification_service.render_alert_email(alert, [admin.email])
    body = message.get_content()

    assert "should-not-appear-in-email" not in body  # evidence blob never dumped into the email
    assert alert.alert_type.value in body
    assert str(alert.id) in body
    assert message["To"] == admin.email


def test_get_notification_recipients_only_active_admins(client, register_user, login_as, db):
    headers = register_user(email="notif-recipients@example.com", org_name="Notif Org")
    resp = client.post(
        "/assets", json={"asset_type": "domain", "value": "notif-recipients.example.com"}, headers=headers
    )
    asset = resp.json()
    client.post(f"/assets/{asset['id']}/confirm-authorization", json={"authorization_confirmed": True}, headers=headers)
    seed_asset = db.get(Asset, uuid.UUID(asset["id"]))

    # A viewer in the same org must never receive alert emails.
    client.post(
        "/users", json={"email": "notif-viewer@example.com", "password": "correct-horse-battery", "full_name": "V", "role": "viewer"},
        headers=headers,
    )
    # A deactivated admin must not receive them either.
    resp2 = client.post(
        "/users", json={"email": "notif-inactive-admin@example.com", "password": "correct-horse-battery", "full_name": "IA", "role": "admin"},
        headers=headers,
    )
    inactive_admin_id = resp2.json()["id"]
    client.patch(f"/users/{inactive_admin_id}", json={"is_active": False}, headers=headers)

    recipients = alert_notification_service.get_notification_recipients(db, seed_asset.organization_id)
    assert "notif-viewer@example.com" not in recipients
    assert "notif-inactive-admin@example.com" not in recipients
    assert any(r.endswith("notif-recipients@example.com") for r in recipients)


# --- Delivery outcomes (send_email mocked at the I/O boundary) ----------------


def test_deliver_success_marks_sent(client, register_user, db, executor_uses_test_db, monkeypatch):
    seed_asset, admin = _seed_asset_and_admin(client, register_user, db, "notif-success@example.com", "notif-success.example.com")
    alert = _make_alert(db, seed_asset)
    notification = _make_notification(db, alert)

    sent_messages = []
    monkeypatch.setattr(alert_notification_service, "send_email", lambda message: sent_messages.append(message))

    outcome = alert_delivery_executor.deliver(str(notification.id))
    assert outcome == "sent"
    assert len(sent_messages) == 1

    db.refresh(notification)
    assert notification.status == NotificationStatus.sent
    assert notification.delivered_at is not None
    assert notification.attempts == 1


def test_deliver_transient_failure_marks_failed_transient(client, register_user, db, executor_uses_test_db, monkeypatch):
    seed_asset, admin = _seed_asset_and_admin(client, register_user, db, "notif-transient@example.com", "notif-transient.example.com")
    alert = _make_alert(db, seed_asset)
    notification = _make_notification(db, alert)

    def _raise(message):
        raise smtplib.SMTPServerDisconnected("connection reset")

    monkeypatch.setattr(alert_notification_service, "send_email", _raise)

    outcome = alert_delivery_executor.deliver(str(notification.id))
    assert outcome == "transient_failure"
    db.refresh(notification)
    assert notification.status == NotificationStatus.failed_transient
    assert notification.attempts == 1


def test_deliver_permanent_failure_marks_failed_permanent(client, register_user, db, executor_uses_test_db, monkeypatch):
    seed_asset, admin = _seed_asset_and_admin(client, register_user, db, "notif-permanent@example.com", "notif-permanent.example.com")
    alert = _make_alert(db, seed_asset)
    notification = _make_notification(db, alert)

    def _raise(message):
        raise smtplib.SMTPAuthenticationError(535, b"Authentication failed")

    monkeypatch.setattr(alert_notification_service, "send_email", _raise)

    outcome = alert_delivery_executor.deliver(str(notification.id))
    assert outcome == "permanent_failure"
    db.refresh(notification)
    assert notification.status == NotificationStatus.failed_permanent
    assert "Authentication failed" in notification.error_message


def test_deliver_exceeds_max_attempts_becomes_permanent(client, register_user, db, executor_uses_test_db, monkeypatch):
    seed_asset, admin = _seed_asset_and_admin(client, register_user, db, "notif-maxattempts@example.com", "notif-maxattempts.example.com")
    alert = _make_alert(db, seed_asset)
    notification = _make_notification(db, alert)
    notification.attempts = alert_delivery_executor.MAX_ATTEMPTS - 1
    db.commit()

    def _raise(message):
        raise smtplib.SMTPServerDisconnected("still down")

    monkeypatch.setattr(alert_notification_service, "send_email", _raise)

    outcome = alert_delivery_executor.deliver(str(notification.id))
    assert outcome == "permanent_failure"
    db.refresh(notification)
    assert notification.status == NotificationStatus.failed_permanent
    assert notification.attempts == alert_delivery_executor.MAX_ATTEMPTS


def test_deliver_no_recipients_is_permanent_failure(client, register_user, db, executor_uses_test_db, monkeypatch):
    seed_asset, admin = _seed_asset_and_admin(client, register_user, db, "notif-norecipients@example.com", "notif-norecipients.example.com")
    alert = _make_alert(db, seed_asset)
    notification = _make_notification(db, alert)

    monkeypatch.setattr(alert_notification_service, "get_notification_recipients", lambda db, org_id: [])
    sent_messages = []
    monkeypatch.setattr(alert_notification_service, "send_email", lambda message: sent_messages.append(message))

    outcome = alert_delivery_executor.deliver(str(notification.id))
    assert outcome == "permanent_failure"
    assert sent_messages == []  # never even attempted to send
    db.refresh(notification)
    assert notification.status == NotificationStatus.failed_permanent


# Note: `alert_delivery_executor.deliver`'s `if alert is None:` branch
# (a defensive fallback for a notification whose alert has vanished) is
# not separately tested here -- AlertNotification.alert_id is a NOT
# NULL FK with ondelete="CASCADE", so a notification can never durably
# exist without its alert (deleting the alert cascades to the
# notification too, and nothing in this codebase deletes an Alert at
# all). The check is harmless defense in depth, not a reachable path to
# construct a meaningful test around.


# --- Idempotency / duplicate-send prevention (Step 9.12.12) -------------------


def test_deliver_is_idempotent_for_an_already_sent_notification(client, register_user, db, executor_uses_test_db, monkeypatch):
    seed_asset, admin = _seed_asset_and_admin(client, register_user, db, "notif-idempotent@example.com", "notif-idempotent.example.com")
    alert = _make_alert(db, seed_asset)
    notification = _make_notification(db, alert)

    sent_messages = []
    monkeypatch.setattr(alert_notification_service, "send_email", lambda message: sent_messages.append(message))

    first = alert_delivery_executor.deliver(str(notification.id))
    assert first == "sent"
    assert len(sent_messages) == 1

    # A retried/duplicate Celery dispatch for the exact same notification.
    second = alert_delivery_executor.deliver(str(notification.id))
    assert second == "skipped"
    assert len(sent_messages) == 1  # never sent twice

    db.refresh(notification)
    assert notification.status == NotificationStatus.sent
    assert notification.attempts == 1  # the skipped call never touched it


def test_deliver_can_retry_a_transiently_failed_notification(client, register_user, db, executor_uses_test_db, monkeypatch):
    seed_asset, admin = _seed_asset_and_admin(client, register_user, db, "notif-retry@example.com", "notif-retry.example.com")
    alert = _make_alert(db, seed_asset)
    notification = _make_notification(db, alert)

    calls = {"n": 0}

    def _flaky(message):
        calls["n"] += 1
        if calls["n"] == 1:
            raise smtplib.SMTPServerDisconnected("first attempt fails")

    monkeypatch.setattr(alert_notification_service, "send_email", _flaky)

    first = alert_delivery_executor.deliver(str(notification.id))
    assert first == "transient_failure"

    second = alert_delivery_executor.deliver(str(notification.id))
    assert second == "sent"
    assert calls["n"] == 2

    db.refresh(notification)
    assert notification.status == NotificationStatus.sent
    assert notification.attempts == 2


# --- queue_notifications gating -------------------------------------------------


def test_queue_notifications_is_noop_when_email_disabled(client, register_user, db, monkeypatch):
    seed_asset, admin = _seed_asset_and_admin(client, register_user, db, "notif-disabled@example.com", "notif-disabled.example.com")
    alert = _make_alert(db, seed_asset)
    monkeypatch.setattr(settings, "alert_notification_email_enabled", False)

    alert_service.queue_notifications(db, [alert])

    assert db.query(AlertNotification).filter(AlertNotification.alert_id == alert.id).count() == 0


def test_queue_notifications_creates_notification_and_enqueues_when_enabled(client, register_user, db, eager_celery, monkeypatch):
    seed_asset, admin = _seed_asset_and_admin(client, register_user, db, "notif-enabled@example.com", "notif-enabled.example.com")
    alert = _make_alert(db, seed_asset)
    monkeypatch.setattr(settings, "alert_notification_email_enabled", True)
    monkeypatch.setattr(alert_notification_service, "send_email", lambda message: None)

    alert_service.queue_notifications(db, [alert])

    notifications = db.query(AlertNotification).filter(AlertNotification.alert_id == alert.id).all()
    assert len(notifications) == 1
    # eager_celery makes .delay() run synchronously in-process, so by
    # the time queue_notifications returns, delivery has already happened.
    assert notifications[0].status == NotificationStatus.sent


# --- Real, unmocked local SMTP server (Step 9.12.21 item 12) ------------------


class _FakeSmtpServer:
    """Accepts one connection and speaks just enough SMTP to complete a
    real smtplib send -- no mocking of smtplib/send_email itself,
    mirroring test_certificate_provider.py's local-TLS-server precedent
    for proving a real client against a real (if minimal) server.
    """

    def __init__(self):
        self.ip = "127.0.0.1"
        self.received_lines: list[str] = []
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.ip, 0))
        self._listener.listen(1)
        self.port = self._listener.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        self._listener.settimeout(5)
        try:
            conn, _ = self._listener.accept()
        except OSError:
            return
        conn.settimeout(5)
        f = conn.makefile("rwb")

        def _send(line: str) -> None:
            f.write((line + "\r\n").encode())
            f.flush()

        _send("220 fake.smtp.local ESMTP")
        in_data = False
        try:
            while True:
                raw = f.readline()
                if not raw:
                    break
                text = raw.decode(errors="replace").rstrip("\r\n")
                self.received_lines.append(text)
                if in_data:
                    if text == ".":
                        in_data = False
                        _send("250 OK: queued as 12345")
                    continue
                command = text.split(" ")[0].upper()
                if command in ("EHLO", "HELO"):
                    _send("250 fake.smtp.local")
                elif command == "MAIL":
                    _send("250 OK")
                elif command == "RCPT":
                    _send("250 OK")
                elif command == "DATA":
                    _send("354 End data with <CR><LF>.<CR><LF>")
                    in_data = True
                elif command == "QUIT":
                    _send("221 Bye")
                    break
                else:
                    _send("250 OK")
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        if self._stop:
            return
        self._stop = True
        self._listener.close()
        self._thread.join(timeout=2)


def test_send_email_against_a_real_local_smtp_server(monkeypatch):
    server = _FakeSmtpServer()
    try:
        monkeypatch.setattr(settings, "smtp_host", server.ip)
        monkeypatch.setattr(settings, "smtp_port", server.port)
        monkeypatch.setattr(settings, "smtp_use_tls", False)
        monkeypatch.setattr(settings, "smtp_username", "")
        monkeypatch.setattr(settings, "smtp_from_address", "alerts@example.invalid")

        from email.message import EmailMessage

        message = EmailMessage()
        message["Subject"] = "[ASM][HIGH] Real server test"
        message["From"] = "alerts@example.invalid"
        message["To"] = "admin@example.com"
        message.set_content("A real, unmocked send through a real local SMTP listener.")

        alert_notification_service.send_email(message)  # must not raise

        server._thread.join(timeout=5)
        joined = "\n".join(server.received_lines).lower()
        assert "mail from" in joined
        assert "rcpt to" in joined
        assert "data" in joined
    finally:
        server.close()
