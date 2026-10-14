"""Display names for VPN tunnels (e.g. the IPsec name configured on the firewall), per device and tunnel.

Revision ID: 0021
Revises: 0020
Create Date: 2026-10-07
"""
from alembic import op

from app.config import get_settings

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    s = get_settings()
    app, web = s.db_app_user, s.db_web_user
    op.execute("""
        CREATE TABLE vpn_tunnel_names (
            device_id    integer NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            tunnel_name  text NOT NULL,
            display_name text NOT NULL CHECK (length(trim(display_name)) BETWEEN 1 AND 100),
            PRIMARY KEY (device_id, tunnel_name)
        )
    """)
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON vpn_tunnel_names TO "{web}"')
    op.execute("ALTER TABLE vpn_tunnel_names ENABLE ROW LEVEL SECURITY")
    op.execute(f'CREATE POLICY app_all ON vpn_tunnel_names TO "{app}" USING (true) WITH CHECK (true)')
    # Same scoping as vpn_tunnel_aliases: visible/editable only for devices the user can see.
    op.execute(f'CREATE POLICY web_scope ON vpn_tunnel_names TO "{web}" '
               f'USING (EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id)) '
               f'WITH CHECK (EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id))')


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS vpn_tunnel_names")
