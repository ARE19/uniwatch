from datetime import datetime

from sqlalchemy import BigInteger, Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utc_now_col


class AuditLog(Base):
    """Append-only: the app role is granted INSERT and SELECT only (see migration 0001)."""

    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_log_ts", "ts"),
        Index("ix_audit_log_action_ts", "action", "ts"),
        Index("ix_audit_log_username_ts", "username", "ts"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    ts: Mapped[datetime] = utc_now_col()
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    # Username is copied in so the trail survives user deletion and records failed logins for unknown names.
    username: Mapped[str | None] = mapped_column(String(64))
    client_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("clients.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    target: Mapped[str | None] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(400))
    details: Mapped[dict | None] = mapped_column(JSONB)
