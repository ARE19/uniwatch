"""CCTV access log: who opened UniFi Protect, when, from where, for how long, and which camera timelines (recordings) or
settings they viewed. Collected from each console's Protect event list through the Site Manager connector (event types
"access" and "adminActivity"); every console is tried, so a site that installs Protect later appears automatically.

Revision ID: 0038
Revises: 0037
Create Date: 2026-10-09
"""
from alembic import op

from app.config import get_settings

revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    s = get_settings()
    app, web = s.db_app_user, s.db_web_user
    op.execute("""
        CREATE TABLE protect_activity (
            host_id     text NOT NULL,                 -- Site Manager console id
            event_id    text NOT NULL,                 -- Protect event id
            client_id   integer NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            device_id   integer REFERENCES devices(id) ON DELETE SET NULL,
            ts          timestamptz NOT NULL,          -- start of the session / action
            ended_at    timestamptz,                   -- end of a Protect session (access events)
            kind        text NOT NULL,                 -- access | adminActivity
            action      text NOT NULL,                 -- accessed | cameraTimelineViewed | deviceListViewed | ...
            title       text,                          -- Protect's title: Full Session, Camera Timeline Viewed, ...
            user_name   text,
            user_ref    text,                          -- Protect user id
            ip          inet,
            platform    text,                          -- web | ios | android | ...
            camera_ref  text,
            camera_name text,
            duration_s  double precision,
            message     text NOT NULL,                 -- "Alice Chan viewed the timeline of CTSKL-CCTV1 - Lobby for 6m 48s."
            raw         jsonb NOT NULL,
            PRIMARY KEY (host_id, event_id)
        )
    """)
    op.execute("CREATE INDEX protect_activity_client_ts ON protect_activity (client_id, ts DESC)")
    op.execute("""
        CREATE TABLE protect_consoles (
            host_id    text PRIMARY KEY,
            client_id  integer NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            status     text NOT NULL,                  -- ok | no protect | denied | error: ...
            version    text,
            last_sync  timestamptz NOT NULL
        )
    """)
    for t in ("protect_activity", "protect_consoles"):
        op.execute(f'GRANT SELECT ON {t} TO "{web}"')
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f'CREATE POLICY app_all ON {t} TO "{app}" USING (true) WITH CHECK (true)')
        op.execute(f'CREATE POLICY web_scope ON {t} TO "{web}" USING (client_id = ANY ((SELECT app_client_ids())::integer[]))')


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS protect_activity")
    op.execute("DROP TABLE IF EXISTS protect_consoles")
