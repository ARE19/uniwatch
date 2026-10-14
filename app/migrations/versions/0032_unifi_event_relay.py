"""Event Monitor rule "UniFi alerts (relayed)": UniFi's own alert events (CEF IDs) raised as alerts the moment they arrive.

Revision ID: 0032
Revises: 0031
Create Date: 2026-10-09
"""
from alembic import op

revision = "0032"
down_revision = "0031"
branch_labels = None
depends_on = None

OLD_TYPES = ("device_offline", "vpn_tunnel_down", "vpn_flapping", "failed_logins", "config_change", "wan_failover",
             "outdated_firmware", "log_source_silent", "event_match", "ioc_match", "storage_quota", "wan_down", "internet_down",
             "isp_degraded", "server_health")
NEW_TYPES = OLD_TYPES + ("unifi_event",)


def upgrade() -> None:
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_rule_type_check")
    op.execute(f"ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_rule_type_check CHECK (rule_type IN {NEW_TYPES!r})")
    # Same e-mail recipients / channels as the existing "VPN tunnel down" rule, so it notifies the same people.
    op.execute("""INSERT INTO alert_rules (name, rule_type, severity, params, throttle_minutes, notify_resolve, channel_ids)
                  SELECT 'UniFi alerts (relayed)', 'unifi_event', 'high', '{"event_ids": [524, 105, 539, 568]}', 0, false,
                         coalesce((SELECT channel_ids FROM alert_rules WHERE rule_type = 'vpn_tunnel_down' AND client_id IS NULL
                                   ORDER BY id LIMIT 1), '{}')""")


def downgrade() -> None:
    op.execute("DELETE FROM alert_rules WHERE rule_type = 'unifi_event'")
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_rule_type_check")
    op.execute(f"ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_rule_type_check CHECK (rule_type IN {OLD_TYPES!r})")
