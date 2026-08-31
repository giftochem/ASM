import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, Index, Integer, Text
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import NotificationChannel, NotificationStatus
from app.models.base import Base, TimestampMixin, UUIDPKMixin


class AlertNotification(Base, UUIDPKMixin, TimestampMixin):
    """Step 9.12 -- delivery tracking for ONE channel attempt against ONE
    alert, deliberately separate from Alert's own open/acknowledged/
    resolved lifecycle: whether an email went out is a delivery
    concern, not a fact about whether the underlying condition still
    deserves attention (the same "clean domain separation" the alert-
    vs-activity-feed decision below also follows). Only ever created
    when Settings.alert_notification_email_enabled is True AND a NEW
    alert (not a deduplicated update to an existing one) was just
    created -- see alert_service.queue_notifications -- so a deployment
    that hasn't configured SMTP never accumulates rows here, and a
    schedule repeating an already-alerted condition never queues a
    second email for it.
    """

    __tablename__ = "alert_notifications"
    __table_args__ = (Index("ix_alert_notifications_alert_id", "alert_id"),)

    alert_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False
    )
    channel: Mapped[NotificationChannel] = mapped_column(
        Enum(NotificationChannel, name="notification_channel"), nullable=False
    )
    status: Mapped[NotificationStatus] = mapped_column(
        Enum(NotificationStatus, name="notification_status"), nullable=False, default=NotificationStatus.pending
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    alert = relationship("Alert")
