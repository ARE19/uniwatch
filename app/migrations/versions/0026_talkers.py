"""Internet traffic per internal device per hour (MAC + IP + name), for top-talker reports that identify devices by MAC:
IP leases expire and move between devices, a MAC does not.

The internal device is the source of outgoing flows and the destination of incoming ones. UniFi API flows carry the
device's MAC and name; NetFlow from a UDM carries the MAC on outgoing records only, so incoming (download) rows keep
mac NULL here and the report attributes them by IP within the same hour.

Revision ID: 0026
Revises: 0025
Create Date: 2026-10-08
"""
from alembic import op

from app.config import get_settings

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None

BODY = """
    SELECT time_bucket('1 hour', ts) AS bucket, client_id,
           CASE WHEN extra->>'direction' = 'incoming' THEN dst_ip ELSE src_ip END AS ip,
           CASE WHEN extra->>'direction' = 'incoming' THEN dst_mac ELSE src_mac END AS mac,
           max(CASE WHEN extra->>'direction' = 'outgoing' THEN extra->>'src_name' END) AS name,
           count(*) AS n, sum(coalesce(bytes_in, 0) + coalesce(bytes_out, 0)) AS bytes
    FROM events
    WHERE category = 'traffic' AND extra->>'direction' IN ('outgoing', 'incoming')
    GROUP BY 1, 2, 3, 4"""


def upgrade() -> None:
    s = get_settings()
    with op.get_context().autocommit_block():
        op.execute(f"CREATE MATERIALIZED VIEW events_talkers_1h WITH (timescaledb.continuous, "
                   f"timescaledb.materialized_only = false) AS {BODY} WITH NO DATA")
        op.execute("""SELECT add_continuous_aggregate_policy('events_talkers_1h', start_offset => INTERVAL '3 days',
                      end_offset => INTERVAL '1 hour', schedule_interval => INTERVAL '15 minutes')""")
    op.execute(f'GRANT SELECT ON events_talkers_1h TO "{s.db_app_user}"')
    op.execute("CREATE VIEW scoped.events_talkers_1h WITH (security_barrier = true) AS "
               "SELECT * FROM public.events_talkers_1h WHERE client_id = ANY ((SELECT app_client_ids())::integer[])")
    op.execute(f'GRANT SELECT ON scoped.events_talkers_1h TO "{s.db_web_user}"')


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS scoped.events_talkers_1h")
    with op.get_context().autocommit_block():
        op.execute("DROP MATERIALIZED VIEW IF EXISTS events_talkers_1h")
