"""Per-rule e-mail recipients: a notification channel can belong to one alert rule (managed from the rule's editor).

Revision ID: 0019
Revises: 0018
Create Date: 2026-10-07
"""
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE notification_channels ADD COLUMN owner_rule_id integer REFERENCES alert_rules(id) ON DELETE CASCADE")
    op.execute("CREATE UNIQUE INDEX uq_notification_channels_owner_rule ON notification_channels (owner_rule_id) "
               "WHERE owner_rule_id IS NOT NULL")


def downgrade() -> None:
    op.execute("DELETE FROM notification_channels WHERE owner_rule_id IS NOT NULL")
    op.execute("ALTER TABLE notification_channels DROP COLUMN owner_rule_id")
