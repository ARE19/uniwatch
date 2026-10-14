"""UniFi event 105 "Temporary Internet Failover" (the gateway switched to the secondary WAN) gets its own rule, so it can be
sent to a client without the other immediate gateway events (spanning tree flapping, IP conflict). Same channels and
e-mail recipients as "Gateway events (immediate)", so nobody loses an alert.

Revision ID: 0037
Revises: 0036
Create Date: 2026-10-09
"""
from alembic import op

revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""INSERT INTO alert_rules (name, rule_type, severity, params, throttle_minutes, notify_resolve, channel_ids, enabled)
                  SELECT 'Internet failover (secondary WAN)', 'unifi_event', 'high', '{"event_ids": [105]}', 0, false,
                         coalesce((SELECT channel_ids FROM alert_rules WHERE rule_type = 'unifi_event' AND client_id IS NULL
                                   ORDER BY id LIMIT 1), '{}'),
                         coalesce((SELECT enabled FROM alert_rules WHERE rule_type = 'unifi_event' AND client_id IS NULL
                                   ORDER BY id LIMIT 1), true)""")
    # recipients typed on the gateway-events rule (its own e-mail channel) also get the failover alerts
    op.execute("""UPDATE alert_rules SET channel_ids = channel_ids || ARRAY(
                      SELECT id FROM notification_channels WHERE owner_rule_id = (
                          SELECT id FROM alert_rules WHERE rule_type = 'unifi_event' AND client_id IS NULL ORDER BY id LIMIT 1))
                  WHERE name = 'Internet failover (secondary WAN)' AND client_id IS NULL""")
    op.execute("""UPDATE alert_rules SET params = jsonb_set(params, '{event_ids}',
                    coalesce((SELECT jsonb_agg(v) FROM jsonb_array_elements(params->'event_ids') v WHERE v::text <> '105'), '[]'))
                  WHERE rule_type = 'unifi_event' AND name <> 'Internet failover (secondary WAN)'""")


def downgrade() -> None:
    op.execute("DELETE FROM alert_rules WHERE name = 'Internet failover (secondary WAN)' AND rule_type = 'unifi_event'")
    op.execute("""UPDATE alert_rules SET params = jsonb_set(params, '{event_ids}', (params->'event_ids') || '[105]')
                  WHERE rule_type = 'unifi_event'""")
