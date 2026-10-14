"""WAN traffic counters (per gateway WAN port, every poll) for internet throughput/packet graphs and reports.

Counters are cumulative as reported by the controller (verified on UniFi Network 10.6.106: wanN.rx_bytes,
tx_bytes, rx_packets, tx_packets, rx/tx_dropped, rx/tx_errors, speed). Rates are computed from deltas between
consecutive polls, so a counter reset (gateway reboot) is simply skipped.

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-07
"""
from alembic import op

from app.config import get_settings

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

OLD_TYPES = ("vpn_uptime", "vpn_sessions", "device_traffic", "device_uptime", "monthly_bundle")
NEW_TYPES = OLD_TYPES + ("internet_usage",)


def upgrade() -> None:
    s = get_settings()
    web = s.db_web_user
    op.execute("""
        CREATE TABLE wan_metrics (
            ts              timestamptz NOT NULL,
            client_id       integer NOT NULL REFERENCES clients(id),
            device_id       integer NOT NULL REFERENCES devices(id),
            wan_name        text NOT NULL,
            rx_bytes        bigint,       -- received from the internet (download), cumulative
            tx_bytes        bigint,       -- sent to the internet (upload), cumulative
            rx_packets      bigint,
            tx_packets      bigint,
            rx_dropped      bigint,
            tx_dropped      bigint,
            rx_errors       bigint,
            tx_errors       bigint,
            link_speed_mbps integer,
            latency_ms      real
        )
    """)
    op.execute("SELECT create_hypertable('wan_metrics', by_range('ts', INTERVAL '7 days'))")
    op.execute("CREATE INDEX ix_wan_metrics_dev_wan_ts ON wan_metrics (device_id, wan_name, ts DESC)")
    op.execute("CREATE INDEX ix_wan_metrics_client_ts ON wan_metrics (client_id, ts DESC)")
    op.execute("""ALTER TABLE wan_metrics SET (timescaledb.compress, timescaledb.compress_segmentby = 'device_id, wan_name',
                  timescaledb.compress_orderby = 'ts DESC')""")
    op.execute("SELECT add_compression_policy('wan_metrics', INTERVAL '7 days')")
    # Web role: only through the scoped view (same pattern as the other hypertables).
    op.execute("CREATE VIEW scoped.wan_metrics WITH (security_barrier = true) AS "
               "SELECT * FROM public.wan_metrics WHERE client_id = ANY ((SELECT app_client_ids())::integer[])")
    op.execute(f'GRANT SELECT ON scoped.wan_metrics TO "{web}"')
    # Retention now also covers WAN traffic.
    op.execute("""
        CREATE OR REPLACE FUNCTION apply_retention() RETURNS TABLE (client_id integer, raw_deleted bigint, events_deleted bigint)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
        DECLARE
            c record;
            r bigint;
            e bigint;
        BEGIN
            FOR c IN SELECT id, retention_days FROM clients LOOP
                DELETE FROM raw_logs WHERE raw_logs.client_id = c.id AND ts_received < now() - make_interval(days => c.retention_days);
                GET DIAGNOSTICS r = ROW_COUNT;
                DELETE FROM events WHERE events.client_id = c.id AND ts < now() - make_interval(days => c.retention_days);
                GET DIAGNOSTICS e = ROW_COUNT;
                DELETE FROM device_metrics WHERE device_metrics.client_id = c.id AND ts < now() - make_interval(days => c.retention_days);
                DELETE FROM wan_metrics WHERE wan_metrics.client_id = c.id AND ts < now() - make_interval(days => c.retention_days);
                client_id := c.id; raw_deleted := r; events_deleted := e;
                RETURN NEXT;
            END LOOP;
        END $$
    """)
    for t in ("report_runs", "report_schedules"):
        op.execute(f"ALTER TABLE {t} DROP CONSTRAINT {t}_report_type_check")
        op.execute(f"ALTER TABLE {t} ADD CONSTRAINT {t}_report_type_check CHECK (report_type IN {NEW_TYPES!r})")


def downgrade() -> None:
    for t in ("report_runs", "report_schedules"):
        op.execute(f"ALTER TABLE {t} DROP CONSTRAINT {t}_report_type_check")
        op.execute(f"ALTER TABLE {t} ADD CONSTRAINT {t}_report_type_check CHECK (report_type IN {OLD_TYPES!r})")
    op.execute("DROP VIEW IF EXISTS scoped.wan_metrics")
    op.execute("DROP TABLE IF EXISTS wan_metrics")
