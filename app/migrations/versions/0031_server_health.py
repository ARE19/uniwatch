"""Event Monitor rule "Log server health": the server alerts about itself (no logs, parser stopped or behind, disk,
backups, console polling).

Revision ID: 0031
Revises: 0030
Create Date: 2026-10-09
"""
from alembic import op

revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None

OLD_TYPES = ("device_offline", "vpn_tunnel_down", "vpn_flapping", "failed_logins", "config_change", "wan_failover",
             "outdated_firmware", "log_source_silent", "event_match", "ioc_match", "storage_quota", "wan_down", "internet_down",
             "isp_degraded")
NEW_TYPES = OLD_TYPES + ("server_health",)


def upgrade() -> None:
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_rule_type_check")
    op.execute(f"ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_rule_type_check CHECK (rule_type IN {NEW_TYPES!r})")
    op.execute("""INSERT INTO alert_rules (name, rule_type, severity, params, throttle_minutes, notify_resolve) VALUES
        ('Log server health', 'server_health', 'high',
         '{"stall_minutes": 10, "backlog": 200000, "disk_pct": 85, "backup_hours": 26, "poll_fail_pct": 50}', 60, true)""")


def downgrade() -> None:
    op.execute("DELETE FROM alert_rules WHERE rule_type = 'server_health'")
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_rule_type_check")
    op.execute(f"ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_rule_type_check CHECK (rule_type IN {OLD_TYPES!r})")
