from datetime import datetime

from sqlalchemy import CheckConstraint, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, utc_now_col


class Company(Base):
    """A customer with several client sites (e.g. CTS: UK, KL, SG, HK)."""

    __tablename__ = "companies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    created_at: Mapped[datetime] = utc_now_col()


class Client(Base):
    """An MSP client. Every tenant-owned row in the system carries client_id."""

    __tablename__ = "clients"
    __table_args__ = (
        CheckConstraint("slug ~ '^[a-z0-9][a-z0-9-]{1,30}$'", name="slug_format"),
        CheckConstraint("retention_days BETWEEN 1 AND 3650", name="retention_range"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    timezone: Mapped[str] = mapped_column(String(64), nullable=False, server_default="Asia/Hong_Kong")
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False, server_default="90")
    company_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("companies.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = utc_now_col()
