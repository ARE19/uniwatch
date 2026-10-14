"""Phase 8: report runs and monthly report schedules.

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-06
"""
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

TYPES = ("vpn_uptime", "vpn_sessions", "device_traffic", "device_uptime", "monthly_bundle")


def upgrade() -> None:
    op.execute(f"""
        CREATE TABLE report_schedules (
            id           serial PRIMARY KEY,
            client_id    integer NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            report_type  varchar(32) NOT NULL CHECK (report_type IN {TYPES!r}),
            recipients   text[] NOT NULL DEFAULT '{{}}',
            day_of_month smallint NOT NULL DEFAULT 1 CHECK (day_of_month BETWEEN 1 AND 28),
            hour_local   smallint NOT NULL DEFAULT 6 CHECK (hour_local BETWEEN 0 AND 23),
            enabled      boolean NOT NULL DEFAULT true,
            created_by   text,
            created_at   timestamptz NOT NULL DEFAULT now(),
            UNIQUE (client_id, report_type)
        )
    """)
    op.execute(f"""
        CREATE TABLE report_runs (
            id            bigserial PRIMARY KEY,
            client_id     integer NOT NULL REFERENCES clients(id),
            report_type   varchar(32) NOT NULL CHECK (report_type IN {TYPES!r}),
            period_start  timestamptz NOT NULL,
            period_end    timestamptz NOT NULL,
            status        varchar(10) NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
            schedule_id   integer REFERENCES report_schedules(id) ON DELETE SET NULL,
            requested_by  text,
            recipients    text[] NOT NULL DEFAULT '{{}}',
            emailed_at    timestamptz,
            email_status  text,
            pdf_path      text,
            xlsx_path     text,
            summary       jsonb NOT NULL DEFAULT '{{}}'::jsonb,
            error         text,
            created_at    timestamptz NOT NULL DEFAULT now(),
            started_at    timestamptz,
            finished_at   timestamptz,
            CHECK (period_end > period_start)
        )
    """)
    op.execute("CREATE INDEX ix_report_runs_client_created ON report_runs (client_id, created_at DESC)")
    op.execute("CREATE INDEX ix_report_runs_queued ON report_runs (created_at) WHERE status = 'queued'")
    op.execute("CREATE UNIQUE INDEX uq_report_runs_schedule_period ON report_runs (schedule_id, period_start) WHERE schedule_id IS NOT NULL")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS report_runs")
    op.execute("DROP TABLE IF EXISTS report_schedules")
