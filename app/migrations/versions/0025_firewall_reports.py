"""Firewall reports: hourly traffic by direction / protocol, the firewall policy configuration of each gateway (with
UniFi's own hit counters, for unused / duplicate / shadowed rule analysis), and the new report types.

Revision ID: 0025
Revises: 0024
Create Date: 2026-10-08
"""
from alembic import op

from app.config import get_settings

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None

OLD_TYPES = ("vpn_uptime", "vpn_sessions", "device_traffic", "device_uptime", "monthly_bundle", "internet_usage")
NEW_TYPES = OLD_TYPES + ("executive_summary", "traffic_bandwidth", "security_attacks", "rule_policy", "vpn_remote_access",
                         "compliance_audit", "web_app_usage", "ha_system", "firewall_bundle")

# Traffic and firewall events per hour by direction (inbound / outbound / intranet, from UniFi flows and NetFlow) and
# protocol: the volume trends and shares in the traffic report, without scanning raw flows.
TRAFFIC_BODY = """
    SELECT time_bucket('1 hour', ts) AS bucket, client_id, device_id, coalesce(extra->>'direction', 'unknown') AS direction,
           protocol, category, outcome, count(*) AS n, sum(bytes_in) AS bytes_in, sum(bytes_out) AS bytes_out
    FROM events WHERE category IN ('traffic', 'firewall')
    GROUP BY 1, 2, 3, 4, 5, 6, 7"""


def upgrade() -> None:
    s = get_settings()
    app, web = s.db_app_user, s.db_web_user
    with op.get_context().autocommit_block():
        op.execute(f"CREATE MATERIALIZED VIEW events_traffic_1h WITH (timescaledb.continuous, "
                   f"timescaledb.materialized_only = false) AS {TRAFFIC_BODY} WITH NO DATA")
        op.execute("""SELECT add_continuous_aggregate_policy('events_traffic_1h', start_offset => INTERVAL '3 days',
                      end_offset => INTERVAL '1 hour', schedule_interval => INTERVAL '15 minutes')""")
    op.execute(f'GRANT SELECT ON events_traffic_1h TO "{app}"')
    op.execute("CREATE VIEW scoped.events_traffic_1h WITH (security_barrier = true) AS "
               "SELECT * FROM public.events_traffic_1h WHERE client_id = ANY ((SELECT app_client_ids())::integer[])")
    op.execute(f'GRANT SELECT ON scoped.events_traffic_1h TO "{web}"')

    # Snapshot of each gateway's firewall policies (UniFi zone-based firewall), replaced on every fetch.
    op.execute("""
        CREATE TABLE firewall_policies (
            device_id    integer NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            policy_id    text NOT NULL,
            client_id    integer NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            name         text,
            idx          bigint,                    -- evaluation order (lower first)
            action       text,                      -- ALLOW / BLOCK / REJECT
            enabled      boolean,
            predefined   boolean,
            protocol     text,
            ip_version   text,
            logging      boolean,
            source       jsonb NOT NULL DEFAULT '{}',
            destination  jsonb NOT NULL DEFAULT '{}',
            schedule     jsonb NOT NULL DEFAULT '{}',
            hits         bigint,                    -- UniFi's own counter (since the policy was created / counters reset)
            last_hit     timestamptz,
            fetched_at   timestamptz NOT NULL,
            PRIMARY KEY (device_id, policy_id)
        )
    """)
    op.execute("""
        CREATE TABLE firewall_zones (
            device_id    integer NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            zone_id      text NOT NULL,
            client_id    integer NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            name         text,
            zone_key     text,
            fetched_at   timestamptz NOT NULL,
            PRIMARY KEY (device_id, zone_id)
        )
    """)
    for t in ("firewall_policies", "firewall_zones"):
        op.execute(f'GRANT SELECT ON {t} TO "{web}"')
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f'CREATE POLICY app_all ON {t} TO "{app}" USING (true) WITH CHECK (true)')
        op.execute(f'CREATE POLICY web_scope ON {t} TO "{web}" USING (client_id = ANY ((SELECT app_client_ids())::integer[]))')

    for t in ("report_runs", "report_schedules"):
        op.execute(f"ALTER TABLE {t} DROP CONSTRAINT {t}_report_type_check")
        op.execute(f"ALTER TABLE {t} ADD CONSTRAINT {t}_report_type_check CHECK (report_type IN {NEW_TYPES!r})")


def downgrade() -> None:
    for t in ("report_runs", "report_schedules"):
        op.execute(f"DELETE FROM {t} WHERE report_type NOT IN {OLD_TYPES!r}")
        op.execute(f"ALTER TABLE {t} DROP CONSTRAINT {t}_report_type_check")
        op.execute(f"ALTER TABLE {t} ADD CONSTRAINT {t}_report_type_check CHECK (report_type IN {OLD_TYPES!r})")
    op.execute("DROP TABLE IF EXISTS firewall_zones")
    op.execute("DROP TABLE IF EXISTS firewall_policies")
    op.execute("DROP VIEW IF EXISTS scoped.events_traffic_1h")
    with op.get_context().autocommit_block():
        op.execute("DROP MATERIALIZED VIEW IF EXISTS events_traffic_1h")
