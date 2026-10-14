"""Comments on alerts (who looked at it, what was found).

Revision ID: 0023
Revises: 0022
Create Date: 2026-10-07
"""
from alembic import op

from app.config import get_settings

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    s = get_settings()
    app, web = s.db_app_user, s.db_web_user
    op.execute("""
        CREATE TABLE alert_comments (
            id        bigserial PRIMARY KEY,
            alert_id  bigint NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
            ts        timestamptz NOT NULL DEFAULT now(),
            username  text NOT NULL,
            body      text NOT NULL CHECK (length(trim(body)) BETWEEN 1 AND 4000)
        )
    """)
    op.execute("CREATE INDEX ix_alert_comments_alert ON alert_comments (alert_id, ts)")
    op.execute(f'GRANT SELECT, INSERT ON alert_comments TO "{web}"')
    op.execute(f'GRANT USAGE, SELECT ON SEQUENCE alert_comments_id_seq TO "{web}"')
    op.execute("ALTER TABLE alert_comments ENABLE ROW LEVEL SECURITY")
    op.execute(f'CREATE POLICY app_all ON alert_comments TO "{app}" USING (true) WITH CHECK (true)')
    # Visible and writable only for alerts the user can see (alerts are client-scoped).
    op.execute(f'CREATE POLICY web_scope ON alert_comments TO "{web}" '
               f'USING (EXISTS (SELECT 1 FROM alerts a WHERE a.id = alert_id)) '
               f'WITH CHECK (EXISTS (SELECT 1 FROM alerts a WHERE a.id = alert_id))')


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS alert_comments")
