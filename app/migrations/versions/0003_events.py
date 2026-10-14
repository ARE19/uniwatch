"""Phase 3: events (normalised, hypertable), config_changes, ingest_stats, continuous aggregates.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-06
"""
from alembic import op

from app.config import get_settings

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

CATEGORIES = ("traffic", "firewall", "vpn", "config", "system", "wifi", "ids", "auth", "dns", "dhcp", "other")
SEVERITIES = ("low", "medium", "high", "critical")


def upgrade() -> None:
    app_role = get_settings().db_app_user

    op.execute(f"""
        CREATE TABLE events (
            ts            timestamptz NOT NULL,          -- event time (device clock / controller UTC), stored UTC
            id            bigserial   NOT NULL,
            client_id     integer     NOT NULL REFERENCES clients(id),
            device_id     integer     NOT NULL REFERENCES devices(id),
            raw_id        bigint      NOT NULL,          -- raw_logs (raw_id, raw_ts) for drill-down
            raw_ts        timestamptz NOT NULL,
            vendor        varchar(32) NOT NULL,
            category      varchar(16) NOT NULL CHECK (category IN {CATEGORIES!r}),
            severity      varchar(8)  NOT NULL CHECK (severity IN {SEVERITIES!r}),
            severity_raw  varchar(32),
            event_class   varchar(128) NOT NULL,
            event_name    text,
            action        varchar(64),
            outcome       varchar(32),
            src_ip        inet,
            src_port      integer,
            dst_ip        inet,
            dst_port      integer,
            protocol      varchar(16),
            src_mac       macaddr,
            dst_mac       macaddr,
            user_name     text,
            rule          text,
            interface     text,
            bytes_in      bigint,
            bytes_out     bigint,
            host          text,
            process       text,
            message       text,
            src_country   char(2),
            dst_country   char(2),
            src_asn       integer,
            dst_asn       integer,
            extra         jsonb NOT NULL DEFAULT '{{}}'::jsonb
        )
    """)
    op.execute("SELECT create_hypertable('events', by_range('ts', INTERVAL '1 day'))")
    op.execute("CREATE UNIQUE INDEX uq_events_id_ts ON events (id, ts)")
    op.execute("CREATE INDEX ix_events_client_ts ON events (client_id, ts DESC)")
    op.execute("CREATE INDEX ix_events_device_ts ON events (device_id, ts DESC)")
    op.execute("CREATE INDEX ix_events_client_cat_ts ON events (client_id, category, ts DESC)")
    op.execute("CREATE INDEX ix_events_src_ip_ts ON events (src_ip, ts DESC) WHERE src_ip IS NOT NULL")
    op.execute("CREATE INDEX ix_events_dst_ip_ts ON events (dst_ip, ts DESC) WHERE dst_ip IS NOT NULL")
    op.execute("CREATE INDEX ix_events_user_ts ON events (user_name, ts DESC) WHERE user_name IS NOT NULL")
    op.execute("CREATE INDEX ix_events_raw ON events (raw_id, raw_ts)")
    op.execute("""
        ALTER TABLE events SET (
            timescaledb.compress,
            timescaledb.compress_segmentby = 'client_id, device_id',
            timescaledb.compress_orderby = 'ts DESC, id DESC'
        )
    """)
    op.execute("SELECT add_compression_policy('events', INTERVAL '7 days')")

    op.execute("""
        CREATE TABLE config_changes (
            id          bigserial PRIMARY KEY,
            ts          timestamptz NOT NULL,
            client_id   integer NOT NULL REFERENCES clients(id),
            device_id   integer NOT NULL REFERENCES devices(id),
            raw_id      bigint NOT NULL,
            raw_ts      timestamptz NOT NULL,
            admin_user  text,
            source_ip   inet,
            action      varchar(32) NOT NULL,
            summary     text NOT NULL DEFAULT '',
            details     jsonb NOT NULL DEFAULT '{}'::jsonb
        )
    """)
    op.execute("CREATE INDEX ix_config_changes_client_ts ON config_changes (client_id, ts DESC)")
    op.execute("CREATE INDEX ix_config_changes_raw ON config_changes (raw_id, raw_ts)")

    # One row per component per minute (FortiAnalyzer-style receive/insert/lag widgets).
    op.execute("""
        CREATE TABLE ingest_stats (
            ts            timestamptz NOT NULL,
            component     varchar(16) NOT NULL,     -- receiver | parser
            received      bigint,
            stored        bigint,
            unknown       bigint,
            rate_limited  bigint,
            dropped       bigint,
            queue_depth   bigint,
            parsed        bigint,
            failed        bigint,
            lag_avg_ms    bigint,
            lag_max_ms    bigint,
            UNIQUE (component, ts)
        )
    """)
    op.execute("SELECT create_hypertable('ingest_stats', by_range('ts', INTERVAL '7 days'))")
    op.execute("SELECT add_retention_policy('ingest_stats', INTERVAL '90 days')")

    # Continuous aggregates cannot be created inside a transaction.
    with op.get_context().autocommit_block():
        op.execute("""
            CREATE MATERIALIZED VIEW raw_logs_1m WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
            SELECT time_bucket('1 minute', ts_received) AS bucket, client_id, device_id,
                   count(*) AS lines, sum(octet_length(raw)) AS bytes
            FROM raw_logs GROUP BY 1, 2, 3 WITH NO DATA
        """)
        op.execute("""
            SELECT add_continuous_aggregate_policy('raw_logs_1m', start_offset => INTERVAL '3 hours',
                   end_offset => INTERVAL '1 minute', schedule_interval => INTERVAL '1 minute')
        """)
        op.execute("""
            CREATE MATERIALIZED VIEW events_5m WITH (timescaledb.continuous, timescaledb.materialized_only = false) AS
            SELECT time_bucket('5 minutes', ts) AS bucket, client_id, device_id, category, severity,
                   count(*) AS n
            FROM events GROUP BY 1, 2, 3, 4, 5 WITH NO DATA
        """)
        op.execute("""
            SELECT add_continuous_aggregate_policy('events_5m', start_offset => INTERVAL '1 day',
                   end_offset => INTERVAL '5 minutes', schedule_interval => INTERVAL '5 minutes')
        """)
    for view in ("raw_logs_1m", "events_5m"):
        op.execute(f'GRANT SELECT ON {view} TO "{app_role}"')


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("DROP MATERIALIZED VIEW IF EXISTS events_5m")
        op.execute("DROP MATERIALIZED VIEW IF EXISTS raw_logs_1m")
    op.execute("DROP TABLE IF EXISTS ingest_stats")
    op.execute("DROP TABLE IF EXISTS config_changes")
    op.execute("DROP TABLE IF EXISTS events")
