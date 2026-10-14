"""Live CPU / memory / temperature / uptime / clients for every device a console reports (APs, switches, gateways), and a
faster refresh of the usage aggregate (Insights reads complete hours only, so they must be materialised promptly).

Revision ID: 0028
Revises: 0027
Create Date: 2026-10-09
"""
from alembic import op

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""ALTER TABLE device_inventory ADD COLUMN cpu_pct real, ADD COLUMN mem_pct real, ADD COLUMN temp_c real,
                  ADD COLUMN uptime_s bigint, ADD COLUMN client_count integer""")
    with op.get_context().autocommit_block():
        op.execute("SELECT remove_continuous_aggregate_policy('events_usage_1h', if_exists => true)")
        op.execute("""SELECT add_continuous_aggregate_policy('events_usage_1h', start_offset => INTERVAL '3 days',
                      end_offset => INTERVAL '5 minutes', schedule_interval => INTERVAL '10 minutes')""")


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("SELECT remove_continuous_aggregate_policy('events_usage_1h', if_exists => true)")
        op.execute("""SELECT add_continuous_aggregate_policy('events_usage_1h', start_offset => INTERVAL '3 days',
                      end_offset => INTERVAL '1 hour', schedule_interval => INTERVAL '15 minutes')""")
    op.execute("""ALTER TABLE device_inventory DROP COLUMN cpu_pct, DROP COLUMN mem_pct, DROP COLUMN temp_c,
                  DROP COLUMN uptime_s, DROP COLUMN client_count""")
