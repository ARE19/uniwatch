"""VPN handshake failures (OpenVPN TLS errors, IKE "no proposal") are internet scanners probing the VPN port, not login
attempts: the failed-login rule (high) leaves them out, and a separate "VPN port scans" rule (medium, no e-mail by
default: listed under Alerts only) keeps them visible.

Revision ID: 0040
Revises: 0039
Create Date: 2026-10-10
"""
from alembic import op

revision = "0040"
down_revision = "0039"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""UPDATE alert_rules SET params = params || '{"exclude_actions": ["vpn-tls-error", "vpn-ike-no-proposal"]}'
                  WHERE rule_type = 'failed_logins'""")
    op.execute("""INSERT INTO alert_rules (name, rule_type, severity, params, throttle_minutes, notify_resolve, channel_ids)
                  VALUES ('VPN port scans (handshake failures)', 'failed_logins', 'medium',
                          '{"count": 10, "window_minutes": 15, "actions": ["vpn-tls-error", "vpn-ike-no-proposal"]}', 0, false, '{}')""")


def downgrade() -> None:
    op.execute("DELETE FROM alert_rules WHERE name = 'VPN port scans (handshake failures)'")
    op.execute("UPDATE alert_rules SET params = params - 'exclude_actions' WHERE rule_type = 'failed_logins'")
