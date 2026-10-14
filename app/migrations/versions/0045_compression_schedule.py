"""Compress the two big tables once a day at a fixed time outside office hours, instead of every 12 hours at whatever
time the job happened to be created: raw_logs at 00:00 and events at 00:30, Hong Kong time.

Revision ID: 0045
Revises: 0044
Create Date: 2026-10-13
"""
from alembic import op

revision = "0045"
down_revision = "0044"
branch_labels = None
depends_on = None

TZ = "Asia/Hong_Kong"
START = {"raw_logs": "00:00", "events": "00:30"}     # half an hour apart, so the two never run together


def upgrade() -> None:
    for table, at in START.items():
        op.execute(f"""
            SELECT alter_job(job_id, schedule_interval => INTERVAL '1 day', fixed_schedule => true,
                             initial_start => TIMESTAMP '2026-01-01 {at}' AT TIME ZONE '{TZ}', timezone => '{TZ}',
                             next_start => (date_trunc('day', now() AT TIME ZONE '{TZ}') + INTERVAL '1 day' + TIME '{at}')
                                           AT TIME ZONE '{TZ}')
            FROM timescaledb_information.jobs
            WHERE proc_name = 'policy_compression' AND hypertable_name = '{table}'
        """)


def downgrade() -> None:
    for table in START:
        op.execute(f"""
            SELECT alter_job(job_id, schedule_interval => INTERVAL '12 hours', fixed_schedule => false)
            FROM timescaledb_information.jobs
            WHERE proc_name = 'policy_compression' AND hypertable_name = '{table}'
        """)
