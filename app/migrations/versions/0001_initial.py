"""Phase 1: clients, roles, users, user_clients, web_sessions, audit_log.

Revision ID: 0001
Revises:
Create Date: 2026-10-06
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

from app.config import get_settings

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    app_role = get_settings().db_app_user

    bind = op.get_bind()
    if bind.execute(sa.text("SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'")).scalar() is None:
        raise RuntimeError("timescaledb extension missing — it is created by db/init/00-roles.sh")

    op.create_table(
        "clients",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("slug", sa.String(32), nullable=False),
        sa.Column("timezone", sa.String(64), nullable=False, server_default="Asia/Hong_Kong"),
        sa.Column("retention_days", sa.Integer, nullable=False, server_default="90"),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("slug", name="uq_clients_slug"),
        sa.CheckConstraint("slug ~ '^[a-z0-9][a-z0-9-]{1,30}$'", name="ck_clients_slug_format"),
        sa.CheckConstraint("retention_days BETWEEN 1 AND 3650", name="ck_clients_retention_range"),
    )

    op.create_table(
        "roles",
        sa.Column("id", sa.SmallInteger, primary_key=True),
        sa.Column("name", sa.String(32), nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.UniqueConstraint("name", name="uq_roles_name"),
    )
    op.bulk_insert(
        sa.table("roles", sa.column("id"), sa.column("name"), sa.column("description")),
        [
            {"id": 1, "name": "admin", "description": "Full access, user and client management"},
            {"id": 2, "name": "engineer", "description": "MSP engineer: all clients' logs, dashboards, reports"},
            {"id": 3, "name": "client_readonly", "description": "Client user: own client's dashboards and reports only"},
        ],
    )

    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=False, server_default=""),
        sa.Column("email", sa.String(320)),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("role_id", sa.SmallInteger, sa.ForeignKey("roles.id", name="fk_users_role_id_roles"), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("must_change_password", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("totp_secret_enc", sa.Text),
        sa.Column("totp_enabled", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("totp_last_step", sa.BigInteger),
        sa.Column("password_changed_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("last_login_at", TS),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("username ~ '^[A-Za-z0-9._@-]{2,64}$'", name="ck_users_username_format"),
    )
    op.create_index("uq_users_username_lower", "users", [sa.text("lower(username)")], unique=True)

    op.create_table(
        "user_clients",
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE", name="fk_user_clients_user_id_users"), primary_key=True),
        sa.Column("client_id", sa.Integer, sa.ForeignKey("clients.id", ondelete="CASCADE", name="fk_user_clients_client_id_clients"), primary_key=True),
    )

    op.create_table(
        "web_sessions",
        sa.Column("token_hash", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE", name="fk_web_sessions_user_id_users"), nullable=False),
        sa.Column("mfa_ok", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("mfa_failures", sa.SmallInteger, nullable=False, server_default="0"),
        sa.Column("csrf_token", sa.String(64), nullable=False),
        sa.Column("ip", sa.String(64)),
        sa.Column("user_agent", sa.String(400)),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("expires_at", TS, nullable=False),
    )
    op.create_index("ix_web_sessions_user_id", "web_sessions", ["user_id"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger, sa.Identity(), primary_key=True),
        sa.Column("ts", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL", name="fk_audit_log_user_id_users")),
        sa.Column("username", sa.String(64)),
        sa.Column("client_id", sa.Integer, sa.ForeignKey("clients.id", ondelete="SET NULL", name="fk_audit_log_client_id_clients")),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("success", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("target", sa.Text),
        sa.Column("ip", sa.String(64)),
        sa.Column("user_agent", sa.String(400)),
        sa.Column("details", JSONB),
    )
    op.create_index("ix_audit_log_ts", "audit_log", ["ts"])
    op.create_index("ix_audit_log_action_ts", "audit_log", ["action", "ts"])
    op.create_index("ix_audit_log_username_ts", "audit_log", ["username", "ts"])

    # --- Privileges for the app role -------------------------------------------------
    # Default privileges cover tables created by later migrations (run by this same owner role).
    op.execute(f'GRANT USAGE ON SCHEMA public TO "{app_role}"')
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "{app_role}"')
    op.execute(f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{app_role}"')
    op.execute(f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "{app_role}"')
    op.execute(f'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO "{app_role}"')
    # Roles are reference data; the audit log is append-only; the migration history is owner-only.
    op.execute(f'REVOKE INSERT, UPDATE, DELETE ON roles FROM "{app_role}"')
    op.execute(f'REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM "{app_role}"')
    op.execute(f'REVOKE ALL ON alembic_version FROM "{app_role}"')


def downgrade() -> None:
    for t in ("audit_log", "web_sessions", "user_clients", "users", "roles", "clients"):
        op.drop_table(t)
