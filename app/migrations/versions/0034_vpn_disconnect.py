"""Site-to-site VPN disconnected: alert on the gateway's disconnect event, resolve (with an e-mail) when the tunnel is back.
Alerts only when down for at least a minute (shorter blips are ignored). Replaces the 5-minute "VPN tunnel down" rule and
"VPN tunnel flapping" (both disabled, kept) and the tunnel event in "Gateway events (immediate)".

Revision ID: 0034
Revises: 0033
Create Date: 2026-10-09
"""
from alembic import op

revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None

OLD_TYPES = ("device_offline", "vpn_tunnel_down", "vpn_flapping", "failed_logins", "config_change", "wan_failover",
             "outdated_firmware", "log_source_silent", "event_match", "ioc_match", "storage_quota", "wan_down", "internet_down",
             "isp_degraded", "server_health", "unifi_event")
NEW_TYPES = OLD_TYPES + ("vpn_disconnect",)


def upgrade() -> None:
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_rule_type_check")
    op.execute(f"ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_rule_type_check CHECK (rule_type IN {NEW_TYPES!r})")
    op.execute("""INSERT INTO alert_rules (name, rule_type, severity, params, throttle_minutes, notify_resolve, channel_ids)
                  SELECT 'Site-to-site VPN disconnected', 'vpn_disconnect', 'high', '{"hours": 24, "min_seconds": 60}', 0, true,
                         coalesce((SELECT channel_ids FROM alert_rules WHERE rule_type = 'vpn_tunnel_down' AND client_id IS NULL
                                   ORDER BY id LIMIT 1), '{}')""")
    # e-mail recipients set on the old rule (a channel owned by it) move along
    op.execute("""UPDATE notification_channels SET owner_rule_id = (SELECT id FROM alert_rules WHERE rule_type = 'vpn_disconnect')
                  WHERE owner_rule_id = (SELECT id FROM alert_rules WHERE rule_type = 'vpn_tunnel_down' AND client_id IS NULL
                                         ORDER BY id LIMIT 1)""")
    op.execute("UPDATE alert_rules SET enabled = false WHERE rule_type IN ('vpn_tunnel_down', 'vpn_flapping')")
    op.execute("""UPDATE alert_rules SET params = jsonb_set(params, '{event_ids}',
                    coalesce((SELECT jsonb_agg(v) FROM jsonb_array_elements(params->'event_ids') v WHERE v::text <> '524'), '[]'))
                  WHERE rule_type = 'unifi_event'""")


def downgrade() -> None:
    op.execute("""UPDATE notification_channels SET owner_rule_id = (SELECT id FROM alert_rules WHERE rule_type = 'vpn_tunnel_down'
                  AND client_id IS NULL ORDER BY id LIMIT 1)
                  WHERE owner_rule_id = (SELECT id FROM alert_rules WHERE rule_type = 'vpn_disconnect')""")
    op.execute("DELETE FROM alert_rules WHERE rule_type = 'vpn_disconnect'")
    op.execute("UPDATE alert_rules SET enabled = true WHERE rule_type IN ('vpn_tunnel_down', 'vpn_flapping')")
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_rule_type_check")
    op.execute(f"ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_rule_type_check CHECK (rule_type IN {OLD_TYPES!r})")
