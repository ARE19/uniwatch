"""Phase 6: device metrics (hypertable), device state intervals, maintenance windows, network clients,
poller inventory, encrypted poller credentials.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-06
"""
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE devices
            ADD COLUMN mac macaddr,
            ADD COLUMN firmware_latest text,
            ADD COLUMN upgradable boolean,
            ADD COLUMN last_poll_at timestamptz,
            ADD COLUMN poll_status text
    """)
    op.execute("CREATE INDEX ix_devices_mac ON devices (mac) WHERE mac IS NOT NULL")

    op.execute("""
        CREATE TABLE device_metrics (
            ts            timestamptz NOT NULL,
            client_id     integer NOT NULL REFERENCES clients(id),
            device_id     integer NOT NULL REFERENCES devices(id),
            cpu_pct       real,
            mem_pct       real,
            temp_c        real,
            uptime_s      bigint,
            client_count  integer,
            wan_ip        inet,
            extra         jsonb NOT NULL DEFAULT '{}'::jsonb
        )
    """)
    op.execute("SELECT create_hypertable('device_metrics', by_range('ts', INTERVAL '7 days'))")
    op.execute("CREATE INDEX ix_device_metrics_device_ts ON device_metrics (device_id, ts DESC)")
    op.execute("""ALTER TABLE device_metrics SET (timescaledb.compress, timescaledb.compress_segmentby = 'device_id',
                  timescaledb.compress_orderby = 'ts DESC')""")
    op.execute("SELECT add_compression_policy('device_metrics', INTERVAL '7 days')")

    # Up/down/maintenance intervals per device; the open one has ended_at NULL.
    op.execute("""
        CREATE TABLE device_state (
            id          bigserial PRIMARY KEY,
            client_id   integer NOT NULL REFERENCES clients(id),
            device_id   integer NOT NULL REFERENCES devices(id),
            state       varchar(12) NOT NULL CHECK (state IN ('up', 'down', 'maintenance')),
            started_at  timestamptz NOT NULL,
            ended_at    timestamptz,
            reason      text,
            CHECK (ended_at IS NULL OR ended_at >= started_at)
        )
    """)
    op.execute("CREATE UNIQUE INDEX uq_device_state_open ON device_state (device_id) WHERE ended_at IS NULL")
    op.execute("CREATE INDEX ix_device_state_client_time ON device_state (client_id, started_at DESC)")

    op.execute("""
        CREATE TABLE maintenance_windows (
            id          serial PRIMARY KEY,
            client_id   integer NOT NULL REFERENCES clients(id),
            device_id   integer REFERENCES devices(id),        -- NULL = every device of the client
            starts_at   timestamptz NOT NULL,
            ends_at     timestamptz NOT NULL,
            reason      text NOT NULL DEFAULT '',
            created_by  text,
            created_at  timestamptz NOT NULL DEFAULT now(),
            CHECK (ends_at > starts_at)
        )
    """)
    op.execute("CREATE INDEX ix_maintenance_windows_client ON maintenance_windows (client_id, ends_at)")

    op.execute("""
        CREATE TABLE network_clients (
            client_id     integer NOT NULL REFERENCES clients(id),
            device_id     integer NOT NULL REFERENCES devices(id),   -- the controller/gateway that reported it
            mac           macaddr NOT NULL,
            ip_internal   inet,
            hostname      text,
            ssid          text,
            ap            text,
            is_wired      boolean,
            vendor        text,
            network       text,
            rssi          integer,
            first_seen    timestamptz NOT NULL,
            last_seen     timestamptz NOT NULL,
            PRIMARY KEY (device_id, mac)
        )
    """)
    op.execute("CREATE INDEX ix_network_clients_ip ON network_clients (ip_internal)")
    op.execute("CREATE INDEX ix_network_clients_client_seen ON network_clients (client_id, last_seen DESC)")

    # Everything a controller reports, including devices not registered here (shown as "discovered").
    op.execute("""
        CREATE TABLE device_inventory (
            poll_device_id integer NOT NULL REFERENCES devices(id),
            mac            macaddr NOT NULL,
            device_id      integer REFERENCES devices(id),
            name           text,
            model          text,
            type           text,
            ip             inet,
            firmware       text,
            upgradable     boolean,
            firmware_latest text,
            connected      boolean,
            seen_at        timestamptz NOT NULL,
            PRIMARY KEY (poll_device_id, mac)
        )
    """)

    # Poller secrets (API keys, SNMP communities) encrypted with SECRET_KEY; never returned to the UI.
    op.execute("""
        CREATE TABLE device_credentials (
            device_id   integer PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
            secret_enc  text NOT NULL,
            updated_at  timestamptz NOT NULL DEFAULT now()
        )
    """)


def downgrade() -> None:
    for t in ("device_credentials", "device_inventory", "network_clients", "maintenance_windows", "device_state",
              "device_metrics"):
        op.execute(f"DROP TABLE IF EXISTS {t}")
    op.execute("ALTER TABLE devices DROP COLUMN mac, DROP COLUMN firmware_latest, DROP COLUMN upgradable, "
               "DROP COLUMN last_poll_at, DROP COLUMN poll_status")
