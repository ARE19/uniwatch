"""Internet usage per internal device and destination per hour, for Insights → Devices & usage: which device used which
app / website, with download and upload, over time.

device = source of outgoing flows, destination of incoming ones (MAC + IP; NetFlow downloads carry no MAC and are
attributed by IP within the hour at query time). destination = the website the gateway saw (UniFi API flows) or, where
there is none (NetFlow), the network owner from GeoIP. Byte direction per record type:
  UniFi API flow (one record per connection, from the device's view): bytes_in = download, bytes_out = upload.
  NetFlow (one record per direction): outgoing octets = upload, incoming octets = download (both in bytes_out).

Revision ID: 0027
Revises: 0026
Create Date: 2026-10-09
"""
from alembic import op

from app.config import get_settings

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None

BODY = """
    SELECT time_bucket('1 hour', ts) AS bucket, client_id,
           CASE WHEN extra->>'direction' = 'incoming' THEN dst_ip ELSE src_ip END AS ip,
           CASE WHEN extra->>'direction' = 'incoming' THEN dst_mac ELSE src_mac END AS mac,
           max(CASE WHEN extra->>'direction' = 'outgoing' THEN extra->>'src_name' END) AS name,
           rule AS app,
           coalesce(extra->>'domain',
                    CASE WHEN extra->>'direction' = 'incoming' THEN extra->>'src_as_org' ELSE extra->>'dst_as_org' END) AS site,
           count(*) AS n,
           sum(CASE WHEN action = 'netflow' THEN CASE WHEN extra->>'direction' = 'incoming' THEN coalesce(bytes_out, 0) ELSE 0 END
                    ELSE coalesce(bytes_in, 0) END) AS down,
           sum(CASE WHEN action = 'netflow' THEN CASE WHEN extra->>'direction' = 'outgoing' THEN coalesce(bytes_out, 0) ELSE 0 END
                    ELSE coalesce(bytes_out, 0) END) AS up
    FROM events
    WHERE category = 'traffic' AND extra->>'direction' IN ('outgoing', 'incoming')
    GROUP BY 1, 2, 3, 4, 6, 7"""


def upgrade() -> None:
    s = get_settings()
    with op.get_context().autocommit_block():
        op.execute(f"CREATE MATERIALIZED VIEW events_usage_1h WITH (timescaledb.continuous, "
                   f"timescaledb.materialized_only = false) AS {BODY} WITH NO DATA")
        op.execute("""SELECT add_continuous_aggregate_policy('events_usage_1h', start_offset => INTERVAL '3 days',
                      end_offset => INTERVAL '1 hour', schedule_interval => INTERVAL '15 minutes')""")
    op.execute(f'GRANT SELECT ON events_usage_1h TO "{s.db_app_user}"')
    op.execute("CREATE VIEW scoped.events_usage_1h WITH (security_barrier = true) AS "
               "SELECT * FROM public.events_usage_1h WHERE client_id = ANY ((SELECT app_client_ids())::integer[])")
    op.execute(f'GRANT SELECT ON scoped.events_usage_1h TO "{s.db_web_user}"')


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS scoped.events_usage_1h")
    with op.get_context().autocommit_block():
        op.execute("DROP MATERIALIZED VIEW IF EXISTS events_usage_1h")
