"""Retention by dropping whole chunks, and compression after 2 days.

The old apply_retention() deleted rows client by client across every chunk: it left empty chunks behind (756 by
2026-10-09) and, with compressed chunks, failed with "out of shared memory" (one transaction locking every chunk) or the
decompression limit, so nothing expired. Now chunks entirely older than the longest client retention are dropped (fast,
no decompression, empty chunks go too); clients with a shorter retention get row deletes limited to the days between
their limit and that cutoff. Rows can outlive their retention by up to one chunk (one day).

Revision ID: 0030
Revises: 0029
Create Date: 2026-10-09
"""
from alembic import op

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None

TABLES = (("raw_logs", "ts_received"), ("events", "ts"), ("device_metrics", "ts"), ("wan_metrics", "ts"), ("isp_metrics", "ts"))


def upgrade() -> None:
    drops = "\n".join(f"    PERFORM drop_chunks('{t}', older_than => cutoff);" for t, _ in TABLES)
    deletes = "\n".join(
        f"""            DELETE FROM {t} WHERE {t}.client_id = c.id AND {col} >= cutoff AND {col} < now() - make_interval(days => c.retention_days);"""
        + ("\n            GET DIAGNOSTICS r = ROW_COUNT;" if t == "raw_logs" else "\n            GET DIAGNOSTICS e = ROW_COUNT;" if t == "events" else "")
        for t, col in TABLES)
    op.execute(f"""
        CREATE OR REPLACE FUNCTION apply_retention() RETURNS TABLE (client_id integer, raw_deleted bigint, events_deleted bigint)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
        SET timescaledb.max_tuples_decompressed_per_dml_transaction = 0 AS $$
        DECLARE
            c record;
            r bigint;
            e bigint;
            maxd integer;
            cutoff timestamptz;
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
    """)
    for t in ("raw_logs", "events"):
        op.execute(f"SELECT remove_compression_policy('{t}', if_exists => true)")
        op.execute(f"SELECT add_compression_policy('{t}', INTERVAL '2 days')")


def downgrade() -> None:
    for t in ("raw_logs", "events"):
        op.execute(f"SELECT remove_compression_policy('{t}', if_exists => true)")
        op.execute(f"SELECT add_compression_policy('{t}', INTERVAL '7 days')")
    op.execute("""
        CREATE OR REPLACE FUNCTION apply_retention() RETURNS TABLE (client_id integer, raw_deleted bigint, events_deleted bigint)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
        DECLARE c record; r bigint; e bigint;
        BEGIN
            FOR c IN SELECT id, retention_days FROM clients LOOP
                DELETE FROM raw_logs WHERE raw_logs.client_id = c.id AND ts_received < now() - make_interval(days => c.retention_days);
                GET DIAGNOSTICS r = ROW_COUNT;
                DELETE FROM events WHERE events.client_id = c.id AND ts < now() - make_interval(days => c.retention_days);
                GET DIAGNOSTICS e = ROW_COUNT;
                DELETE FROM device_metrics WHERE device_metrics.client_id = c.id AND ts < now() - make_interval(days => c.retention_days);
                DELETE FROM wan_metrics WHERE wan_metrics.client_id = c.id AND ts < now() - make_interval(days => c.retention_days);
                DELETE FROM isp_metrics WHERE isp_metrics.client_id = c.id AND ts < now() - make_interval(days => c.retention_days);
                client_id := c.id; raw_deleted := r; events_deleted := e;
                RETURN NEXT;
            END LOOP;
        END $$
    """)
