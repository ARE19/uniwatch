"""UniFi Site Manager (cloud) integration: every console of the account, its internet health per 5 minutes, and an
"internet degraded" alert rule.

Revision ID: 0024
Revises: 0023
Create Date: 2026-10-08
"""
from alembic import op

from app.config import get_settings

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None

OLD_TYPES = ("device_offline", "vpn_tunnel_down", "vpn_flapping", "failed_logins", "config_change", "wan_failover",
             "outdated_firmware", "log_source_silent", "event_match", "ioc_match", "storage_quota", "wan_down", "internet_down")
NEW_TYPES = OLD_TYPES + ("isp_degraded",)


def upgrade() -> None:
    s = get_settings()
    app, web = s.db_app_user, s.db_web_user
    # One row per Site Manager console, linked to the client and device it represents.
    op.execute("""
        CREATE TABLE sitemanager_hosts (
            host_id     text PRIMARY KEY,
            site_id     text,
            client_id   integer NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            device_id   integer REFERENCES devices(id) ON DELETE SET NULL,
            name        text NOT NULL,
            model       text,
            state       text,                       -- connected / disconnected (cloud connection of the console)
            wan_ips     inet[] NOT NULL DEFAULT '{}',
            isp         text,
            counts      jsonb NOT NULL DEFAULT '{}', -- device / client counts from the site statistics
            last_sync   timestamptz NOT NULL
        )
    """)
    op.execute(f'GRANT SELECT ON sitemanager_hosts TO "{web}"')
    op.execute("ALTER TABLE sitemanager_hosts ENABLE ROW LEVEL SECURITY")
    op.execute(f'CREATE POLICY app_all ON sitemanager_hosts TO "{app}" USING (true) WITH CHECK (true)')
    op.execute(f'CREATE POLICY web_scope ON sitemanager_hosts TO "{web}" '
               f'USING (client_id = ANY ((SELECT app_client_ids())::integer[]))')

    # Internet health per site: Site Manager's 5-minute (and, for older history, 1-hour) ISP metrics.
    # download/upload_kbps are the LINE SPEED Site Manager reports (constant over weeks), not traffic.
    op.execute("""
        CREATE TABLE isp_metrics (
            ts            timestamptz NOT NULL,
            client_id     integer NOT NULL REFERENCES clients(id),
            device_id     integer NOT NULL REFERENCES devices(id),
            period_s      integer NOT NULL,
            avg_latency   real,
            max_latency   real,
            packet_loss   real,
            uptime        real,
            downtime      real,
            line_down_kbps bigint,
            line_up_kbps  bigint,
            isp_name      text,
            isp_asn       text
        )
    """)
    op.execute("SELECT create_hypertable('isp_metrics', by_range('ts', INTERVAL '7 days'))")
    op.execute("CREATE UNIQUE INDEX uq_isp_metrics ON isp_metrics (device_id, period_s, ts)")
    op.execute("CREATE INDEX ix_isp_metrics_client_ts ON isp_metrics (client_id, ts DESC)")
    op.execute("""ALTER TABLE isp_metrics SET (timescaledb.compress, timescaledb.compress_segmentby = 'device_id, period_s',
                  timescaledb.compress_orderby = 'ts DESC')""")
    op.execute("SELECT add_compression_policy('isp_metrics', INTERVAL '7 days')")
    op.execute("CREATE VIEW scoped.isp_metrics WITH (security_barrier = true) AS "
               "SELECT * FROM public.isp_metrics WHERE client_id = ANY ((SELECT app_client_ids())::integer[])")
    op.execute(f'GRANT SELECT ON scoped.isp_metrics TO "{web}"')

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
                DELETE FROM isp_metrics WHERE isp_metrics.client_id = c.id AND ts < now() - make_interval(days => c.retention_days);
                client_id := c.id; raw_deleted := r; events_deleted := e;
                RETURN NEXT;
            END LOOP;
        END $$
    """)

    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_rule_type_check")
    op.execute(f"ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_rule_type_check CHECK (rule_type IN {NEW_TYPES!r})")
    op.execute("""INSERT INTO alert_rules (name, rule_type, severity, params, throttle_minutes, notify_resolve) VALUES
        ('Internet degraded (loss / latency)', 'isp_degraded', 'medium',
         '{"loss_pct": 5, "latency_ms": 150, "periods": 3}', 60, true)""")


def downgrade() -> None:
    op.execute("""
        CREATE OR REPLACE FUNCTION apply_retention() RETURNS TABLE (client_id integer, raw_deleted bigint, events_deleted bigint)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
        DECLARE c record; r bigint; e bigint;
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
    op.execute("DELETE FROM alert_rules WHERE rule_type = 'isp_degraded'")
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_rule_type_check")
    op.execute(f"ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_rule_type_check CHECK (rule_type IN {OLD_TYPES!r})")
    op.execute("DROP VIEW IF EXISTS scoped.isp_metrics")
    op.execute("DROP TABLE IF EXISTS isp_metrics")
    op.execute("DROP TABLE IF EXISTS sitemanager_hosts")
