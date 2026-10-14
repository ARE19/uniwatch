"""Retention drops at most 20 chunks per table per run.

Dropping hundreds of chunks in one transaction (the 756 empty chunks found on 2026-10-09) exhausted the lock table
("out of shared memory"): each chunk with its compressed chunk and indexes takes several locks, held until commit. In
normal operation only about one chunk per table per day expires; a backlog is worked off over consecutive runs.

Revision ID: 0033
Revises: 0032
Create Date: 2026-10-09
"""
from alembic import op

revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None

TABLES = (("raw_logs", "ts_received"), ("events", "ts"), ("device_metrics", "ts"), ("wan_metrics", "ts"), ("isp_metrics", "ts"))
BATCH = 20


def _function(batch: int | None) -> str:
    if batch:
        drops = "\n".join(f"""
            upto := (SELECT range_end FROM timescaledb_information.chunks WHERE hypertable_name = '{t}' AND range_end <= cutoff
                     ORDER BY range_end OFFSET {batch - 1} LIMIT 1);
            PERFORM drop_chunks('{t}', older_than => least(coalesce(upto, cutoff), cutoff));""" for t, _ in TABLES)
    else:
        drops = "\n".join(f"            PERFORM drop_chunks('{t}', older_than => cutoff);" for t, _ in TABLES)
    deletes = "\n".join(
        f"""                DELETE FROM {t} WHERE {t}.client_id = c.id AND {col} >= cutoff AND {col} < now() - make_interval(days => c.retention_days);"""
        + ("\n                GET DIAGNOSTICS r = ROW_COUNT;" if t == "raw_logs" else "\n                GET DIAGNOSTICS e = ROW_COUNT;" if t == "events" else "")
        for t, col in TABLES)
    return f"""
        CREATE OR REPLACE FUNCTION apply_retention() RETURNS TABLE (client_id integer, raw_deleted bigint, events_deleted bigint)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
        SET timescaledb.max_tuples_decompressed_per_dml_transaction = 0 AS $$
        DECLARE
            c record;
            r bigint;
            e bigint;
            maxd integer;
            cutoff timestamptz;
            upto timestamptz;
        BEGIN
            SELECT coalesce(max(retention_days), 90) INTO maxd FROM clients;
            cutoff := now() - make_interval(days => maxd);
{drops}
            FOR c IN SELECT id, retention_days FROM clients ORDER BY id LOOP
                r := 0; e := 0;
                IF c.retention_days < maxd THEN
{deletes}
                END IF;
                client_id := c.id; raw_deleted := r; events_deleted := e;
                RETURN NEXT;
            END LOOP;
        END $$
    """


def upgrade() -> None:
    op.execute(_function(BATCH))


def downgrade() -> None:
    op.execute(_function(None))
