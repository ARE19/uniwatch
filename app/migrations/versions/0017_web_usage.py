"""Websites & apps per device per hour, from UniFi traffic flows and DNS forwarder lookups.

Revision ID: 0017
Revises: 0016
Create Date: 2026-10-07
"""
from alembic import op

from app.config import get_settings

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

# Outgoing flows only (incoming = internet scanners, local = LAN). `org` names the destination's network owner
# (GeoIP ASN) for flows without a domain, so unidentified traffic is still attributable.
BODY = """
    SELECT time_bucket('1 hour', ts) AS bucket, client_id, src_ip, action, rule,
           extra->>'domain' AS domain,
           CASE WHEN extra->>'domain' IS NULL THEN extra->>'dst_as_org' END AS org,
           count(*) AS n, sum(bytes_in) AS bytes_in, sum(bytes_out) AS bytes_out
    FROM events
    WHERE action = 'dns-query' OR (action = 'flow' AND extra->>'direction' = 'outgoing')
    GROUP BY 1, 2, 3, 4, 5, 6, 7"""


def upgrade() -> None:
    s = get_settings()
    with op.get_context().autocommit_block():
        op.execute(f"CREATE MATERIALIZED VIEW events_web_1h WITH (timescaledb.continuous, "
                   f"timescaledb.materialized_only = false) AS {BODY} WITH NO DATA")
        op.execute("""SELECT add_continuous_aggregate_policy('events_web_1h', start_offset => INTERVAL '3 days',
                      end_offset => INTERVAL '1 hour', schedule_interval => INTERVAL '15 minutes')""")
    op.execute(f'GRANT SELECT ON events_web_1h TO "{s.db_app_user}"')
    op.execute("CREATE VIEW scoped.events_web_1h WITH (security_barrier = true) AS "
               "SELECT * FROM public.events_web_1h WHERE client_id = ANY ((SELECT app_client_ids())::integer[])")
    op.execute(f'GRANT SELECT ON scoped.events_web_1h TO "{s.db_web_user}"')


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS scoped.events_web_1h")
    with op.get_context().autocommit_block():
        op.execute("DROP MATERIALIZED VIEW IF EXISTS events_web_1h")
