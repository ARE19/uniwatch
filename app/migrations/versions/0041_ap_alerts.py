"""Access point and PoE alerts: AP offline, Wi-Fi quality (channel utilisation / Wi-Fi experience / weak client
signal), PoE problems (AP on limited PoE, switch PoE budget, PoE port fault). The poller keeps the controller's AP radio
and PoE details on device_inventory.extra and one row per AP per poll in ap_metrics (7 days), so "for 15 minutes" is
measured instead of reacting to a single reading.

Revision ID: 0041
Revises: 0040
Create Date: 2026-10-10
"""
from alembic import op

from app.config import get_settings

revision = "0041"
down_revision = "0040"
branch_labels = None
depends_on = None

OLD_TYPES = ("device_offline", "vpn_tunnel_down", "vpn_flapping", "failed_logins", "config_change", "wan_failover",
             "outdated_firmware", "log_source_silent", "event_match", "ioc_match", "storage_quota", "wan_down", "internet_down",
             "isp_degraded", "server_health", "unifi_event", "vpn_disconnect")
NEW_TYPES = OLD_TYPES + ("ap_offline", "wifi_quality", "poe_issue")
RULES = (("Access point offline", "ap_offline", "high", '{"minutes": 5, "ignore_after_days": 7}'),
         ("Wi-Fi quality (interference / weak signal)", "wifi_quality", "medium",
          '{"minutes": 15, "utilisation_pct": 80, "experience_pct": 60, "weak_dbm": -75, "weak_clients": 2}'),
         ("PoE problem (low power / budget / fault)", "poe_issue", "medium", '{"budget_pct": 90}'))


def upgrade() -> None:
    s = get_settings()
    app, web = s.db_app_user, s.db_web_user
    op.execute("ALTER TABLE device_inventory ADD COLUMN extra jsonb NOT NULL DEFAULT '{}'")
    op.execute("""
        CREATE TABLE ap_metrics (
            ts             timestamptz NOT NULL,
            client_id      integer NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            poll_device_id integer NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            mac            macaddr NOT NULL,
            name           text,
            cu_max         smallint,          -- highest channel utilisation of its radios (%), incl. interference
            cu_radio       text,              -- which radio (ng = 2.4 GHz, na = 5 GHz, 6e)
            exp_min        smallint,          -- lowest Wi-Fi experience (satisfaction %) of radios with clients
            clients        smallint,
            signals        smallint[] NOT NULL DEFAULT '{}',   -- Wi-Fi clients' signal (dBm) on this AP
            PRIMARY KEY (poll_device_id, mac, ts)
        )
    """)
    op.execute("CREATE INDEX ap_metrics_ts ON ap_metrics (ts)")
    op.execute(f'GRANT SELECT ON ap_metrics TO "{web}"')
    op.execute("ALTER TABLE ap_metrics ENABLE ROW LEVEL SECURITY")
    op.execute(f'CREATE POLICY app_all ON ap_metrics TO "{app}" USING (true) WITH CHECK (true)')
    op.execute(f'CREATE POLICY web_scope ON ap_metrics TO "{web}" USING (client_id = ANY ((SELECT app_client_ids())::integer[]))')

    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_rule_type_check")
    op.execute(f"ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_rule_type_check CHECK (rule_type IN {NEW_TYPES!r})")
    for name, rtype, sev, params in RULES:
        # same channels as "Device offline" (the NOC), resolved e-mails on
        op.execute(f"""INSERT INTO alert_rules (name, rule_type, severity, params, throttle_minutes, notify_resolve, channel_ids)
                       SELECT '{name}', '{rtype}', '{sev}', '{params}', 0, true,
                              coalesce((SELECT channel_ids FROM alert_rules WHERE rule_type = 'device_offline' AND client_id IS NULL
                                        ORDER BY id LIMIT 1), '{{}}')""")


def downgrade() -> None:
    op.execute("DELETE FROM alert_rules WHERE rule_type IN ('ap_offline', 'wifi_quality', 'poe_issue')")
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_rule_type_check")
    op.execute(f"ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_rule_type_check CHECK (rule_type IN {OLD_TYPES!r})")
    op.execute("DROP TABLE IF EXISTS ap_metrics")
    op.execute("ALTER TABLE device_inventory DROP COLUMN extra")
