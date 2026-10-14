"""Phase 12: incidents (case management) with linked alerts/events and a timeline.

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-06
"""
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE incidents (
            id           bigserial PRIMARY KEY,
            client_id    integer NOT NULL REFERENCES clients(id),
            title        text NOT NULL,
            description  text NOT NULL DEFAULT '',
            severity     varchar(8) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
            status       varchar(14) NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'investigating', 'resolved', 'closed')),
            assignee_id  integer REFERENCES users(id) ON DELETE SET NULL,
            created_by   text,
            created_at   timestamptz NOT NULL DEFAULT now(),
            updated_at   timestamptz NOT NULL DEFAULT now(),
            closed_at    timestamptz
        )
    """)
    op.execute("CREATE INDEX ix_incidents_client_status ON incidents (client_id, status, updated_at DESC)")
    op.execute("""
        CREATE TABLE incident_alerts (
            incident_id bigint NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            alert_id    bigint NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
            PRIMARY KEY (incident_id, alert_id)
        )
    """)
    op.execute("CREATE INDEX ix_incident_alerts_alert ON incident_alerts (alert_id)")
    op.execute("""
        CREATE TABLE incident_events (
            incident_id bigint NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            event_id    bigint NOT NULL,
            event_ts    timestamptz NOT NULL,
            PRIMARY KEY (incident_id, event_id)
        )
    """)
    op.execute("""
        CREATE TABLE incident_timeline (
            id          bigserial PRIMARY KEY,
            incident_id bigint NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            ts          timestamptz NOT NULL DEFAULT now(),
            author      text,
            kind        varchar(12) NOT NULL CHECK (kind IN ('created', 'note', 'status', 'assign', 'severity', 'link')),
            text        text NOT NULL
        )
    """)
    op.execute("CREATE INDEX ix_incident_timeline_incident ON incident_timeline (incident_id, ts)")
    op.execute("ALTER TABLE alert_rules ADD COLUMN auto_incident boolean NOT NULL DEFAULT false")


def downgrade() -> None:
    op.execute("ALTER TABLE alert_rules DROP COLUMN auto_incident")
    for t in ("incident_timeline", "incident_events", "incident_alerts", "incidents"):
        op.execute(f"DROP TABLE IF EXISTS {t}")
