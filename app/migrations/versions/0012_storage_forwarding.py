"""Phase 14: log forwarding targets, per-client storage quota, retention enforcement, quota alert rule.

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-06
"""
from alembic import op

from app.config import get_settings

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    app_role = get_settings().db_app_user
    op.execute("ALTER TABLE clients ADD COLUMN quota_gb real CHECK (quota_gb IS NULL OR quota_gb > 0)")
    op.execute("""
        CREATE TABLE forwarding_targets (
            id            serial PRIMARY KEY,
            client_id     integer REFERENCES clients(id) ON DELETE CASCADE,   -- NULL = every client
            name          text NOT NULL,
            host          text NOT NULL,
            port          integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
            protocol      varchar(4) NOT NULL CHECK (protocol IN ('udp', 'tcp', 'tls')),
            format        varchar(6) NOT NULL CHECK (format IN ('raw', 'cef', 'json')),
            min_severity  varchar(8) NOT NULL DEFAULT 'low' CHECK (min_severity IN ('low', 'medium', 'high', 'critical')),
            enabled       boolean NOT NULL DEFAULT true,
            cursor_id     bigint NOT NULL DEFAULT 0,        -- last raw_logs.id (raw) or events.id (cef/json) sent
            sent_count    bigint NOT NULL DEFAULT 0,
            last_sent_at  timestamptz,
            last_error    text,
            created_at    timestamptz NOT NULL DEFAULT now()
        )
    """)
    # Retention runs as the schema owner (the app role may not DELETE raw logs). SECURITY DEFINER lets the
    # scheduled job call it without granting DELETE broadly.
    op.execute("""
        CREATE FUNCTION apply_retention() RETURNS TABLE (client_id integer, raw_deleted bigint, events_deleted bigint)
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
        DECLARE
            c record;
            r bigint;
            e bigint;
        BEGIN
            FOR c IN SELECT id, retention_days FROM clients LOOP
                DELETE FROM raw_logs WHERE raw_logs.client_id = c.id AND ts_received < now() - make_interval(days => c.retention_days);
                GET DIAGNOSTICS r = ROW_COUNT;
                DELETE FROM events WHERE events.client_id = c.id AND ts < now() - make_interval(days => c.retention_days);
                GET DIAGNOSTICS e = ROW_COUNT;
                DELETE FROM device_metrics WHERE device_metrics.client_id = c.id AND ts < now() - make_interval(days => c.retention_days);
                client_id := c.id; raw_deleted := r; events_deleted := e;
                RETURN NEXT;
            END LOOP;
        END $$
    """)
    op.execute("REVOKE ALL ON FUNCTION apply_retention() FROM PUBLIC")
    op.execute(f'GRANT EXECUTE ON FUNCTION apply_retention() TO "{app_role}"')
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_rule_type_check")
    op.execute("""ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_rule_type_check CHECK (rule_type IN
        ('device_offline', 'vpn_tunnel_down', 'vpn_flapping', 'failed_logins', 'config_change', 'wan_failover',
         'outdated_firmware', 'log_source_silent', 'event_match', 'ioc_match', 'storage_quota'))""")
    op.execute("""INSERT INTO alert_rules (name, rule_type, severity, params)
                  VALUES ('Storage quota', 'storage_quota', 'medium', '{"warn_pct": 80}')""")


def downgrade() -> None:
    op.execute("DELETE FROM alert_rules WHERE rule_type = 'storage_quota'")
    op.execute("ALTER TABLE alert_rules DROP CONSTRAINT alert_rules_rule_type_check")
    op.execute("""ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_rule_type_check CHECK (rule_type IN
        ('device_offline', 'vpn_tunnel_down', 'vpn_flapping', 'failed_logins', 'config_change', 'wan_failover',
         'outdated_firmware', 'log_source_silent', 'event_match', 'ioc_match'))""")
    op.execute("DROP FUNCTION IF EXISTS apply_retention()")
    op.execute("DROP TABLE IF EXISTS forwarding_targets")
    op.execute("ALTER TABLE clients DROP COLUMN quota_gb")
