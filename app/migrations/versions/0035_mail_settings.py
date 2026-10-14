"""Mail (SMTP) settings editable in the web UI (Admin -> Mail). One row; when present it replaces the SMTP_* values from
.env for alert and report e-mails. The password is stored encrypted (same key as the notification channel secrets).

Revision ID: 0035
Revises: 0034
Create Date: 2026-10-09
"""
from alembic import op

from app.config import get_settings

revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None


def upgrade() -> None:
    s = get_settings()
    op.execute("""
        CREATE TABLE mail_settings (
            id           smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
            host         text NOT NULL,
            port         integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
            username     text NOT NULL DEFAULT '',
            password_enc text,
            from_addr    text NOT NULL DEFAULT '',
            starttls     boolean NOT NULL DEFAULT true,
            updated_at   timestamptz NOT NULL DEFAULT now(),
            updated_by   text
        )
    """)
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON mail_settings TO "{s.db_web_user}"')
    op.execute("ALTER TABLE mail_settings ENABLE ROW LEVEL SECURITY")
    op.execute(f'CREATE POLICY app_all ON mail_settings TO "{s.db_app_user}" USING (true) WITH CHECK (true)')
    # Web: staff only in the database (the page itself is admin-only).
    op.execute(f'CREATE POLICY web_staff ON mail_settings TO "{s.db_web_user}" USING ((SELECT app_is_staff())) '
               f'WITH CHECK ((SELECT app_is_staff()))')


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS mail_settings")
