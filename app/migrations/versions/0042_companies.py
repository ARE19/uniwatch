"""Company groups: several client sites of one customer (e.g. CTS: UK, KL, SG, HK). A company can be picked in the client
picker (all its sites at once), and alert rules and notification channels can be set for a company instead of one site.

Revision ID: 0042
Revises: 0041
Create Date: 2026-10-11
"""
from alembic import op

from app.config import get_settings

revision = "0042"
down_revision = "0041"
branch_labels = None
depends_on = None


def upgrade() -> None:
    s = get_settings()
    app, web = s.db_app_user, s.db_web_user
    op.execute("""
        CREATE TABLE companies (
            id         serial PRIMARY KEY,
            name       text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 100),
            created_at timestamptz NOT NULL DEFAULT now()
        )
    """)
    op.execute("ALTER TABLE clients ADD COLUMN company_id integer REFERENCES companies(id) ON DELETE SET NULL")
    for t in ("alert_rules", "notification_channels"):
        op.execute(f"ALTER TABLE {t} ADD COLUMN company_id integer REFERENCES companies(id) ON DELETE CASCADE")
        op.execute(f"ALTER TABLE {t} ADD CONSTRAINT {t}_one_scope CHECK (client_id IS NULL OR company_id IS NULL)")
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON companies TO "{web}"')
    op.execute(f'GRANT USAGE, SELECT ON SEQUENCE companies_id_seq TO "{web}"')
    op.execute("ALTER TABLE companies ENABLE ROW LEVEL SECURITY")
    op.execute(f'CREATE POLICY app_all ON companies TO "{app}" USING (true) WITH CHECK (true)')
    # Web: a company is visible when one of its sites is (clients' own row-level security applies inside); staff manage.
    op.execute(f"""CREATE POLICY web_scope ON companies TO "{web}"
                   USING ((SELECT app_is_staff()) OR EXISTS (SELECT 1 FROM clients c WHERE c.company_id = companies.id))
                   WITH CHECK ((SELECT app_is_staff()))""")


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS web_scope ON companies")      # it refers to clients.company_id
    for t in ("alert_rules", "notification_channels"):
        op.execute(f"DELETE FROM {t} WHERE company_id IS NOT NULL")
        op.execute(f"ALTER TABLE {t} DROP COLUMN company_id")
    op.execute("ALTER TABLE clients DROP COLUMN company_id")
    op.execute("DROP TABLE companies")
