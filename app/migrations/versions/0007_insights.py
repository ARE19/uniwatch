"""Phase 7: hourly continuous aggregates behind the Insights (FortiView-style) top-N views.

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-06
"""
from alembic import op

from app.config import get_settings

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

VIEWS = {
    # Who talks / is talked to, by category and outcome (blocked/failure views filter on outcome).
    "events_src_1h": """
        SELECT time_bucket('1 hour', ts) AS bucket, client_id, src_ip, src_country, src_asn, category, outcome,
               count(*) AS n, sum(bytes_in) AS bytes_in, sum(bytes_out) AS bytes_out
        FROM events WHERE src_ip IS NOT NULL GROUP BY 1, 2, 3, 4, 5, 6, 7""",
    "events_dst_1h": """
        SELECT time_bucket('1 hour', ts) AS bucket, client_id, dst_ip, dst_country, dst_asn, dst_port, category, outcome,
               count(*) AS n, sum(bytes_in) AS bytes_in, sum(bytes_out) AS bytes_out
        FROM events WHERE dst_ip IS NOT NULL GROUP BY 1, 2, 3, 4, 5, 6, 7, 8""",
    # Rules / signatures / DNS-filter categories, plus the blocked domain for DNS events.
    "events_rule_1h": """
        SELECT time_bucket('1 hour', ts) AS bucket, client_id, category, action, outcome, rule,
               extra->>'domain' AS domain, count(*) AS n
        FROM events WHERE rule IS NOT NULL OR action IS NOT NULL GROUP BY 1, 2, 3, 4, 5, 6, 7""",
}


def upgrade() -> None:
    app_role = get_settings().db_app_user
    with op.get_context().autocommit_block():
        for name, body in VIEWS.items():
            op.execute(f"CREATE MATERIALIZED VIEW {name} WITH (timescaledb.continuous, "
                       f"timescaledb.materialized_only = false) AS {body} WITH NO DATA")
            op.execute(f"""SELECT add_continuous_aggregate_policy('{name}', start_offset => INTERVAL '3 days',
                           end_offset => INTERVAL '1 hour', schedule_interval => INTERVAL '15 minutes')""")
    for name in VIEWS:
        op.execute(f'GRANT SELECT ON {name} TO "{app_role}"')


def downgrade() -> None:
    with op.get_context().autocommit_block():
        for name in VIEWS:
            op.execute(f"DROP MATERIALIZED VIEW IF EXISTS {name}")
