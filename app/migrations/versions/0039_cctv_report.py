"""CCTV access report type (also part of the executive summary report pack).

Revision ID: 0039
Revises: 0038
Create Date: 2026-10-09
"""
from alembic import op

revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None

OLD_TYPES = ("vpn_uptime", "vpn_sessions", "device_traffic", "device_uptime", "monthly_bundle", "internet_usage",
             "executive_summary", "traffic_bandwidth", "security_attacks", "rule_policy", "vpn_remote_access",
             "compliance_audit", "web_app_usage", "ha_system", "firewall_bundle")
NEW_TYPES = OLD_TYPES + ("cctv_access",)


def _set(types) -> None:
    for t in ("report_runs", "report_schedules"):
        op.execute(f"ALTER TABLE {t} DROP CONSTRAINT {t}_report_type_check")
        op.execute(f"ALTER TABLE {t} ADD CONSTRAINT {t}_report_type_check CHECK (report_type IN {types!r})")


def upgrade() -> None:
    _set(NEW_TYPES)


def downgrade() -> None:
    for t in ("report_runs", "report_schedules"):
        op.execute(f"DELETE FROM {t} WHERE report_type = 'cctv_access'")
    _set(OLD_TYPES)
