from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, Integer, SmallInteger, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, utc_now_col

ROLE_ADMIN = "admin"
ROLE_ENGINEER = "engineer"
ROLE_CLIENT_READONLY = "client_readonly"
ALL_ROLES = (ROLE_ADMIN, ROLE_ENGINEER, ROLE_CLIENT_READONLY)


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    name: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, server_default="")


class User(Base):
    __tablename__ = "users"
    __table_args__ = (Index("uq_users_username_lower", text("lower(username)"), unique=True),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False, server_default="")
    email: Mapped[str | None] = mapped_column(String(320))
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id"), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    must_change_password: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    # TOTP secret encrypted with SECRET_KEY (Fernet). Set during enrolment, active once totp_enabled.
    totp_secret_enc: Mapped[str | None] = mapped_column(Text)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    # Last accepted TOTP time-step; codes at or before it are rejected (replay protection).
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger)
    password_changed_at: Mapped[datetime] = utc_now_col()
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = utc_now_col()

    role: Mapped[Role] = relationship(lazy="joined")


class UserClient(Base):
    """Which clients a user may see. Admins and engineers with no rows see all clients;
    client_readonly users only ever see the clients listed here."""

    __tablename__ = "user_clients"

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id", ondelete="CASCADE"), primary_key=True)


class WebSession(Base):
    """Server-side session. The cookie holds a random token; only its SHA-256 is stored."""

    __tablename__ = "web_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    mfa_ok: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    mfa_failures: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default="0")
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(400))
    created_at: Mapped[datetime] = utc_now_col()
    last_seen_at: Mapped[datetime] = utc_now_col()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
