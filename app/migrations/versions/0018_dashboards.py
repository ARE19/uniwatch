"""Customisable dashboards: saved widget layouts, private or shared, and each user's chosen dashboard.

Revision ID: 0018
Revises: 0017
Create Date: 2026-10-07
"""
from alembic import op

from app.config import get_settings

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    s = get_settings()
    app, web = s.db_app_user, s.db_web_user
    op.execute("""
        CREATE TABLE dashboards (
            id          serial PRIMARY KEY,
            owner_id    integer REFERENCES users(id) ON DELETE SET NULL,
            name        varchar(100) NOT NULL CHECK (length(trim(name)) > 0),
            layout      jsonb NOT NULL DEFAULT '[]',
            shared      boolean NOT NULL DEFAULT false,          -- visible to other users
            client_id   integer REFERENCES clients(id) ON DELETE CASCADE,   -- shared with this client's users only
            is_default  boolean NOT NULL DEFAULT false,          -- what users without a choice of their own see
            created_at  timestamptz NOT NULL DEFAULT now(),
            updated_at  timestamptz NOT NULL DEFAULT now(),
            CHECK (shared OR (client_id IS NULL AND NOT is_default))
        )
    """)
    # One default for everyone, and at most one per client.
    op.execute("CREATE UNIQUE INDEX uq_dashboards_default ON dashboards ((coalesce(client_id, 0))) WHERE is_default")
    op.execute("CREATE INDEX ix_dashboards_owner ON dashboards (owner_id)")
    op.execute("""
        CREATE TABLE user_dashboards (
            user_id      integer PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            dashboard_id integer NOT NULL REFERENCES dashboards(id) ON DELETE CASCADE
        )
    """)
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON dashboards, user_dashboards TO "{web}"')
    op.execute(f'GRANT USAGE, SELECT ON SEQUENCE dashboards_id_seq TO "{web}"')
    for t in ("dashboards", "user_dashboards"):
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f'CREATE POLICY app_all ON {t} TO "{app}" USING (true) WITH CHECK (true)')
    # Read: your own, plus shared ones meant for you (staff see every shared dashboard).
    op.execute(f"""CREATE POLICY web_read ON dashboards FOR SELECT TO "{web}" USING (
        owner_id = app_user_id() OR (shared AND (client_id IS NULL OR (SELECT app_is_staff())
                                              OR client_id = ANY ((SELECT app_client_ids())::integer[]))))""")
    # Write: your own private dashboards; staff also create and manage shared ones.
    op.execute(f"""CREATE POLICY web_insert ON dashboards FOR INSERT TO "{web}" WITH CHECK (
        owner_id = app_user_id() AND (NOT shared OR (SELECT app_is_staff())))""")
    op.execute(f"""CREATE POLICY web_update ON dashboards FOR UPDATE TO "{web}"
        USING (owner_id = app_user_id() OR (shared AND (SELECT app_is_staff())))
        WITH CHECK ((owner_id = app_user_id() AND NOT shared) OR (SELECT app_is_staff()))""")
    op.execute(f"""CREATE POLICY web_delete ON dashboards FOR DELETE TO "{web}"
        USING (owner_id = app_user_id() OR (shared AND (SELECT app_is_staff())))""")
    op.execute(f'CREATE POLICY web_own ON user_dashboards TO "{web}" USING (user_id = app_user_id()) '
               f'WITH CHECK (user_id = app_user_id())')


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS user_dashboards")
    op.execute("DROP TABLE IF EXISTS dashboards")
