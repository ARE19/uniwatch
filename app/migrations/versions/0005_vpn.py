"""Phase 5: VPN tunnel state intervals, VPN user sessions, tracker cursors.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-06
"""
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # One row per interval: up / down / unknown (log gap). The open interval has ended_at NULL.
    op.execute("""
        CREATE TABLE vpn_tunnel_state (
            id           bigserial PRIMARY KEY,
            client_id    integer NOT NULL REFERENCES clients(id),
            device_id    integer NOT NULL REFERENCES devices(id),
            tunnel_name  text NOT NULL,
            peer         text,
            state        varchar(8) NOT NULL CHECK (state IN ('up', 'down', 'unknown')),
            started_at   timestamptz NOT NULL,
            ended_at     timestamptz,
            reason       text,
            event_id     bigint,
            CHECK (ended_at IS NULL OR ended_at >= started_at)
        )
    """)
    op.execute("CREATE UNIQUE INDEX uq_vpn_tunnel_open ON vpn_tunnel_state (device_id, tunnel_name) WHERE ended_at IS NULL")
    op.execute("CREATE INDEX ix_vpn_tunnel_client_time ON vpn_tunnel_state (client_id, started_at DESC)")
    op.execute("CREATE INDEX ix_vpn_tunnel_device_name_time ON vpn_tunnel_state (device_id, tunnel_name, started_at DESC)")

    # Different log lines name the same tunnel differently (interface vs. config path); map them together.
    op.execute("""
        CREATE TABLE vpn_tunnel_aliases (
            device_id    integer NOT NULL REFERENCES devices(id),
            alias        text NOT NULL,
            tunnel_name  text NOT NULL,
            PRIMARY KEY (device_id, alias)
        )
    """)

    op.execute("""
        CREATE TABLE vpn_sessions (
            id            bigserial PRIMARY KEY,
            client_id     integer NOT NULL REFERENCES clients(id),
            device_id     integer NOT NULL REFERENCES devices(id),
            user_name     text,
            source_ip     inet,
            assigned_ip   inet,
            vpn_type      text,
            started_at    timestamptz,                -- NULL when the connect line was never seen (log gap)
            ended_at      timestamptz,
            last_seen_at  timestamptz NOT NULL,
            status        varchar(10) NOT NULL CHECK (status IN ('open', 'closed', 'orphaned')),
            close_reason  text,
            bytes_in      bigint,
            bytes_out     bigint,
            start_event_id bigint,
            end_event_id   bigint
        )
    """)
    op.execute("CREATE INDEX ix_vpn_sessions_client_time ON vpn_sessions (client_id, last_seen_at DESC)")
    op.execute("CREATE INDEX ix_vpn_sessions_open ON vpn_sessions (device_id, user_name) WHERE status = 'open'")

    op.execute("CREATE TABLE tracker_cursors (name text PRIMARY KEY, last_event_id bigint NOT NULL DEFAULT 0, updated_at timestamptz NOT NULL DEFAULT now())")


def downgrade() -> None:
    for t in ("tracker_cursors", "vpn_sessions", "vpn_tunnel_aliases", "vpn_tunnel_state"):
        op.execute(f"DROP TABLE IF EXISTS {t}")
