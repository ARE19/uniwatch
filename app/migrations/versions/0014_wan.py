"""WAN interface + internet state intervals, and 'wan_down' / 'internet_down' alert rules.

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-07
"""
from alembic import op

from app.config import get_settings

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

TYPES = ("device_offline", "vpn_tunnel_down", "vpn_flapping", "failed_logins", "config_change", "wan_failover",
         "outdated_firmware", "log_source_silent", "event_match", "ioc_match", "storage_quota", "wan_down", "internet_down")


def upgrade() -> None:
    s = get_settings()
    app, web = s.db_app_user, s.db_web_user
    # One row per interval per gateway WAN port (wan_name 'WAN', 'WAN2', ...) plus wan_name 'internet' for the
    # controller's overall internet health. The open interval has ended_at NULL.
    op.execute("""
        CREATE TABLE wan_state (
            id          bigserial PRIMARY KEY,
            client_id   integer NOT NULL REFERENCES clients(id),
            device_id   integer NOT NULL REFERENCES devices(id),
            wan_name    text NOT NULL,
            label       text,
            ifname      text,
            ip          inet,
            state       varchar(8) NOT NULL CHECK (state IN ('up', 'down')),
            started_at  timestamptz NOT NULL,
            ended_at    timestamptz,
            reason      text,
            CHECK (ended_at IS NULL OR ended_at >= started_at)
        )
    """)
    op.execute("CREATE UNIQUE INDEX uq_wan_state_open ON wan_state (device_id, wan_name) WHERE ended_at IS NULL")
    op.execute("CREATE INDEX ix_wan_state_client_time ON wan_state (client_id, started_at DESC)")
    op.execute(f'GRANT SELECT ON wan_state TO "{web}"')
    op.execute("ALTER TABLE wan_state ENABLE ROW LEVEL SECURITY")
    op.execute(f'CREATE POLICY app_all ON wan_state TO "{app}" USING (true) WITH CHECK (true)')
    op.execute(f'CREATE POLICY web_scope ON wan_state TO "{web}" USING (client_id = ANY ((SELECT app_client_ids())::integer[]))')
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_rule_type_check")
    op.execute(f"ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_rule_type_check CHECK (rule_type IN {TYPES!r})")
    op.execute("""INSERT INTO alert_rules (name, rule_type, severity, params, throttle_minutes, notify_resolve) VALUES
        ('Internet down', 'internet_down', 'critical', '{"minutes": 2}', 30, true),
        ('WAN interface down', 'wan_down', 'high', '{"minutes": 2}', 30, true)""")
    # IPsec tunnels come from the poller into vpn_tunnel_state; make the existing tunnel-down rule notify on recovery too.
    op.execute("UPDATE alert_rules SET notify_resolve = true WHERE rule_type = 'vpn_tunnel_down' AND client_id IS NULL")


def downgrade() -> None:
    op.execute("DELETE FROM alert_rules WHERE rule_type IN ('wan_down', 'internet_down')")
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_rule_type_check")
    op.execute(f"ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_rule_type_check CHECK (rule_type IN {TYPES[:-2]!r})")
    op.execute("DROP TABLE IF EXISTS wan_state")
