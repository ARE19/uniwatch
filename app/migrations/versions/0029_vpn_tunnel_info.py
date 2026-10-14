"""Site-to-site VPN details as the UniFi UI shows them: type, local WAN interface and IP, remote peer, established since.

Revision ID: 0029
Revises: 0028
Create Date: 2026-10-09
"""
from alembic import op

from app.config import get_settings

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    s = get_settings()
    op.execute("""
        CREATE TABLE vpn_tunnel_info (
            device_id      integer NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
            tunnel_name    text NOT NULL,                -- same key as vpn_tunnel_state ('ipsec:<name>')
            client_id      integer NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            vpn_type       text,
            interface      text,                         -- WAN port the tunnel uses: WAN, WAN2, ...
            local_ip       inet,
            peer           text,
            status         text,                         -- established / not established / disabled
            established_at timestamptz,
            updated_at     timestamptz NOT NULL,
            PRIMARY KEY (device_id, tunnel_name)
        )
    """)
    op.execute(f'GRANT SELECT ON vpn_tunnel_info TO "{s.db_web_user}"')
    op.execute("ALTER TABLE vpn_tunnel_info ENABLE ROW LEVEL SECURITY")
    op.execute(f'CREATE POLICY app_all ON vpn_tunnel_info TO "{s.db_app_user}" USING (true) WITH CHECK (true)')
    op.execute(f'CREATE POLICY web_scope ON vpn_tunnel_info TO "{s.db_web_user}" '
               f'USING (client_id = ANY ((SELECT app_client_ids())::integer[]))')


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS vpn_tunnel_info")
