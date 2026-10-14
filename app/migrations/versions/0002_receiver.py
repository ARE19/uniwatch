"""Phase 2: devices, raw_logs (hypertable), unknown_sources.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-06
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import INET, JSONB

from app.config import get_settings

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TS = sa.DateTime(timezone=True)
VENDORS = ("unifi", "fortinet", "other")


def upgrade() -> None:
    app_role = get_settings().db_app_user

    op.create_table(
        "devices",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("client_id", sa.Integer, sa.ForeignKey("clients.id", name="fk_devices_client_id_clients"), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("vendor", sa.String(32), nullable=False),
        sa.Column("model", sa.String(100), nullable=False, server_default=""),
        sa.Column("firmware", sa.String(100), nullable=False, server_default=""),
        sa.Column("site", sa.String(200), nullable=False, server_default=""),
        sa.Column("syslog_source_ip", INET),
        sa.Column("mgmt_ip", INET),
        sa.Column("poll_config", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("last_log_at", TS),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("syslog_source_ip", name="uq_devices_syslog_source_ip"),
        sa.CheckConstraint(f"vendor IN {VENDORS!r}", name="ck_devices_vendor"),
    )
    op.create_index("ix_devices_client_id", "devices", ["client_id"])

    # raw_logs: every accepted line, exactly as received. Hypertable on ts_received (1-day chunks).
    # bigserial rather than IDENTITY: simplest supported shape for hypertables. Unique key must include the time column.
    op.execute("""
        CREATE TABLE raw_logs (
            ts_received  timestamptz NOT NULL,
            id           bigserial   NOT NULL,
            client_id    integer     NOT NULL REFERENCES clients(id),
            device_id    integer     NOT NULL REFERENCES devices(id),
            source_ip    inet        NOT NULL,
            transport    varchar(8)  NOT NULL,
            raw          text        NOT NULL,
            truncated    boolean     NOT NULL DEFAULT false,
            parsed       boolean     NOT NULL DEFAULT false,
            parse_error  text
        )
    """)
    op.execute("SELECT create_hypertable('raw_logs', by_range('ts_received', INTERVAL '1 day'))")
    op.execute("CREATE UNIQUE INDEX uq_raw_logs_id_ts ON raw_logs (id, ts_received)")
    op.execute("CREATE INDEX ix_raw_logs_client_ts ON raw_logs (client_id, ts_received DESC)")
    op.execute("CREATE INDEX ix_raw_logs_device_ts ON raw_logs (device_id, ts_received DESC)")
    # Parser work queue (Phase 3): small partial index over rows not yet parsed.
    op.execute("CREATE INDEX ix_raw_logs_unparsed ON raw_logs (ts_received) WHERE NOT parsed")
    # Compress chunks older than 7 days (parsing is long finished by then).
    op.execute("""
        ALTER TABLE raw_logs SET (
            timescaledb.compress,
            timescaledb.compress_segmentby = 'client_id, device_id',
            timescaledb.compress_orderby = 'ts_received DESC, id DESC'
        )
    """)
    op.execute("SELECT add_compression_policy('raw_logs', INTERVAL '7 days')")

    op.create_table(
        "unknown_sources",
        sa.Column("source_ip", INET, primary_key=True),
        sa.Column("first_seen", TS, nullable=False),
        sa.Column("last_seen", TS, nullable=False),
        sa.Column("count", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("last_transport", sa.String(8), nullable=False, server_default="udp"),
        sa.Column("sample", sa.Text, nullable=False, server_default=""),
        sa.Column("ignored", sa.Boolean, nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_unknown_sources_last_seen", "unknown_sources", ["last_seen"])

    # Default privileges from 0001 already grant the app role DML on these tables; raw logs are never
    # deleted by the app (retention runs as the owner).
    op.execute(f'REVOKE DELETE, TRUNCATE ON raw_logs FROM "{app_role}"')


def downgrade() -> None:
    op.drop_table("unknown_sources")
    op.execute("DROP TABLE raw_logs")
    op.drop_table("devices")
