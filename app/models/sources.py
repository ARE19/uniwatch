from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, MACADDR
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, utc_now_col
from app.models.tenancy import Client

VENDORS = ("unifi", "fortinet", "dns", "other")


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    vendor: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False, server_default="")
    firmware: Mapped[str] = mapped_column(String(100), nullable=False, server_default="")
    site: Mapped[str] = mapped_column(String(200), nullable=False, server_default="")
    syslog_source_ip: Mapped[str | None] = mapped_column(INET, unique=True)
    # Other addresses the same device sends from (e.g. its second WAN). Mapped by the receiver like the primary.
    alt_source_ips: Mapped[list[str]] = mapped_column(ARRAY(INET), nullable=False, server_default="{}")
    # How long this device may be quiet before it counts as silent/offline (None = the rule / poller default).
    silent_after_minutes: Mapped[int | None] = mapped_column(Integer)
    mgmt_ip: Mapped[str | None] = mapped_column(INET)
    poll_config: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default="{}")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    last_log_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = utc_now_col()
    mac: Mapped[str | None] = mapped_column(MACADDR)
    firmware_latest: Mapped[str | None] = mapped_column(Text)
    upgradable: Mapped[bool | None] = mapped_column(Boolean)
    last_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    poll_status: Mapped[str | None] = mapped_column(Text)

    client: Mapped[Client] = relationship(lazy="joined")


class RawLog(Base):
    """Hypertable (see migration 0002). Primary key here is only for the ORM; the DB has a unique (id, ts_received)."""

    __tablename__ = "raw_logs"

    ts_received: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    client_id: Mapped[int] = mapped_column(ForeignKey("clients.id"), nullable=False)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), nullable=False)
    source_ip: Mapped[str] = mapped_column(INET, nullable=False)
    transport: Mapped[str] = mapped_column(String(8), nullable=False)
    raw: Mapped[str] = mapped_column(Text, nullable=False)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    parsed: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    parse_error: Mapped[str | None] = mapped_column(Text)


class UnknownSource(Base):
    __tablename__ = "unknown_sources"

    source_ip: Mapped[str] = mapped_column(INET, primary_key=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    count: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    last_transport: Mapped[str] = mapped_column(String(8), nullable=False, server_default="udp")
    sample: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    ignored: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
