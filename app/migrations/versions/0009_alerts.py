"""Phase 9: Event Monitor — alert rules (event handlers), alerts, notification channels, notification log.

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-06
"""
import json

from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

from app.alerts.defaults import DEFAULT_RULES, RULE_TYPES  # noqa: E402


def upgrade() -> None:
    op.execute("""
        CREATE TABLE notification_channels (
            id          serial PRIMARY KEY,
            client_id   integer REFERENCES clients(id) ON DELETE CASCADE,   -- NULL = available to all clients
            name        text NOT NULL,
            type        varchar(16) NOT NULL CHECK (type IN ('email', 'teams', 'slack', 'webhook')),
            config_enc  text NOT NULL,          -- encrypted JSON: {"to": [...]} or {"url": "..."}
            enabled     boolean NOT NULL DEFAULT true,
            created_at  timestamptz NOT NULL DEFAULT now()
        )
    """)
    op.execute(f"""
        CREATE TABLE alert_rules (
            id               serial PRIMARY KEY,
            client_id        integer REFERENCES clients(id) ON DELETE CASCADE,  -- NULL = applies to every client
            name             text NOT NULL,
            rule_type        varchar(32) NOT NULL CHECK (rule_type IN {RULE_TYPES!r}),
            params           jsonb NOT NULL DEFAULT '{{}}'::jsonb,
            severity         varchar(8) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
            enabled          boolean NOT NULL DEFAULT true,
            throttle_minutes integer NOT NULL DEFAULT 60 CHECK (throttle_minutes >= 0),
            notify_resolve   boolean NOT NULL DEFAULT false,
            channel_ids      integer[] NOT NULL DEFAULT '{{}}',
            created_at       timestamptz NOT NULL DEFAULT now()
        )
    """)
    op.execute("""
        CREATE TABLE alerts (
            id               bigserial PRIMARY KEY,
            rule_id          integer NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
            client_id        integer NOT NULL REFERENCES clients(id),
            device_id        integer REFERENCES devices(id),
            dedup_key        text NOT NULL,
            severity         varchar(8) NOT NULL,
            title            text NOT NULL,
            message          text NOT NULL DEFAULT '',
            status           varchar(12) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
            first_seen       timestamptz NOT NULL,
            last_seen        timestamptz NOT NULL,
            count            integer NOT NULL DEFAULT 1,
            notified_at      timestamptz,
            acknowledged_by  text,
            acknowledged_at  timestamptz,
            resolved_at      timestamptz,
            details          jsonb NOT NULL DEFAULT '{}'::jsonb
        )
    """)
    # At most one unresolved alert per rule + entity: this IS the deduplication.
    op.execute("CREATE UNIQUE INDEX uq_alerts_active ON alerts (rule_id, client_id, dedup_key) WHERE status <> 'resolved'")
    op.execute("CREATE INDEX ix_alerts_client_status ON alerts (client_id, status, last_seen DESC)")
    op.execute("""
        CREATE TABLE notifications (
            id          bigserial PRIMARY KEY,
            alert_id    bigint NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
            channel_id  integer REFERENCES notification_channels(id) ON DELETE SET NULL,
            kind        varchar(10) NOT NULL CHECK (kind IN ('open', 'resolve')),
            sent_at     timestamptz NOT NULL DEFAULT now(),
            status      text NOT NULL
        )
    """)
    op.execute("CREATE INDEX ix_notifications_alert ON notifications (alert_id)")
    for name, rtype, sev, params in DEFAULT_RULES:
        op.execute(
            "INSERT INTO alert_rules (name, rule_type, severity, params) VALUES "
            f"('{name}', '{rtype}', '{sev}', '{json.dumps(params)}'::jsonb)")


def downgrade() -> None:
    for t in ("notifications", "alerts", "alert_rules", "notification_channels"):
        op.execute(f"DROP TABLE IF EXISTS {t}")
