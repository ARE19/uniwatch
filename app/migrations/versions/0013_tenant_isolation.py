"""Phase 10: database-enforced tenant isolation for the web role.

TimescaleDB does not allow row-level security on hypertables with columnstore (compression) enabled
(verified on 2.30: "operation not supported on hypertables that have columnstore enabled"), so:
  * hypertables + continuous aggregates: the web role has NO privileges on them; it reads them only through
    security-barrier views in schema `scoped` that carry the same names (the web role's search_path is
    "scoped, public", so existing queries resolve to the views unchanged);
  * every other client table: row-level security policies for the web role.
The visible clients are computed IN the database from app.user_id (the authenticated user): staff (active
admin/engineer) see all clients; client_readonly users see only their user_clients rows. The ingest/app role
gets an allow-all policy so background services are unaffected. The role itself is created by
scripts/upgrade-roles.sh (needs superuser); this migration only grants and defines policies.

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-06
"""
from alembic import op

from app.config import get_settings

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

HYPERTABLES = ("events", "raw_logs", "device_metrics")
CAGGS = ("raw_logs_1m", "events_5m", "events_src_1h", "events_dst_1h", "events_rule_1h")
# Regular tables with a NOT NULL client_id
CLIENT_TABLES = ("devices", "config_changes", "device_state", "maintenance_windows", "network_clients",
                 "vpn_tunnel_state", "vpn_sessions", "report_runs", "report_schedules", "alerts", "incidents")
# client_id NULL means "global" (visible to staff only)
NULLABLE_CLIENT_TABLES = ("alert_rules", "notification_channels", "forwarding_targets")
WEB_DML = ("clients", "user_clients", "devices", "maintenance_windows", "report_runs", "report_schedules", "alerts",
           "alert_rules", "notification_channels", "incidents", "incident_alerts", "incident_events", "incident_timeline",
           "forwarding_targets", "saved_searches", "users", "web_sessions", "unknown_sources",
           "ioc_feeds", "ioc_networks", "ioc_domains")
WEB_SELECT = ("roles", "config_changes", "device_state", "network_clients", "device_inventory", "vpn_tunnel_state",
              "vpn_sessions", "vpn_tunnel_aliases", "notifications")


def upgrade() -> None:
    s = get_settings()
    app, web = s.db_app_user, s.db_web_user
    exists = op.get_bind().exec_driver_sql("SELECT 1 FROM pg_roles WHERE rolname = %s", (web,)).scalar()
    if not exists:
        raise RuntimeError(f"role {web!r} missing: run scripts/upgrade-roles.sh (as the database superuser) first")

    # --- scope functions (SECURITY DEFINER: they read users/user_clients regardless of the caller's RLS)
    op.execute("""
        CREATE FUNCTION app_user_id() RETURNS integer LANGUAGE sql STABLE AS $$
            SELECT coalesce(nullif(current_setting('app.user_id', true), ''), '0')::integer $$""")
    op.execute("""
        CREATE FUNCTION app_is_staff() RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
            SELECT EXISTS (SELECT 1 FROM users u JOIN roles r ON r.id = u.role_id
                           WHERE u.id = app_user_id() AND u.is_active AND r.name IN ('admin', 'engineer')) $$""")
    op.execute("""
        CREATE FUNCTION app_client_ids() RETURNS integer[] LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
            SELECT CASE WHEN app_is_staff() THEN (SELECT coalesce(array_agg(id), '{}') FROM clients)
                        ELSE (SELECT coalesce(array_agg(uc.client_id), '{}') FROM user_clients uc
                              JOIN users u ON u.id = uc.user_id WHERE uc.user_id = app_user_id() AND u.is_active)
                   END $$""")
    op.execute("""
        CREATE FUNCTION storage_sizes() RETURNS TABLE (raw_size bigint, events_size bigint)
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
            SELECT hypertable_size('raw_logs'), hypertable_size('events') $$""")
    # Login lockout must count failures before anyone is authenticated, without the web role reading the audit log.
    op.execute("""
        CREATE FUNCTION login_failures(p_username text, p_action text, p_minutes integer) RETURNS bigint
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
            SELECT count(*) FROM audit_log WHERE action = p_action AND NOT success
              AND lower(username) = lower(p_username) AND ts >= now() - make_interval(mins => p_minutes) $$""")
    for fn in ("app_user_id()", "app_is_staff()", "app_client_ids()", "storage_sizes()", "login_failures(text, text, integer)"):
        op.execute(f"REVOKE ALL ON FUNCTION {fn} FROM PUBLIC")
        op.execute(f'GRANT EXECUTE ON FUNCTION {fn} TO "{web}", "{app}"')

    scope = "client_id = ANY ((SELECT app_client_ids())::integer[])"   # sub-select: evaluated once per query, not per row

    # --- views over hypertables and continuous aggregates
    op.execute("CREATE SCHEMA scoped")
    op.execute(f'GRANT USAGE ON SCHEMA scoped TO "{web}"')
    for t in HYPERTABLES + CAGGS:
        op.execute(f"CREATE VIEW scoped.{t} WITH (security_barrier = true) AS SELECT * FROM public.{t} WHERE {scope}")
        op.execute(f'GRANT SELECT ON scoped.{t} TO "{web}"')
    op.execute("CREATE VIEW scoped.ingest_stats WITH (security_barrier = true) AS "
               "SELECT * FROM public.ingest_stats WHERE (SELECT app_is_staff())")
    op.execute(f'GRANT SELECT ON scoped.ingest_stats TO "{web}"')

    # --- privileges for the web role (explicit; nothing on hypertables, caggs, credentials or cursors)
    op.execute(f'GRANT USAGE ON SCHEMA public TO "{web}"')
    for t in WEB_DML:
        op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON public.{t} TO "{web}"')
    for t in WEB_SELECT:
        op.execute(f'GRANT SELECT ON public.{t} TO "{web}"')
    op.execute(f'GRANT SELECT, INSERT ON public.audit_log TO "{web}"')
    op.execute(f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{web}"')

    # --- row-level security
    def rls(table: str, using: str, check: str | None = None) -> None:
        op.execute(f"ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f'CREATE POLICY app_all ON public.{table} TO "{app}" USING (true) WITH CHECK (true)')
        op.execute(f'CREATE POLICY web_scope ON public.{table} TO "{web}" USING ({using}) WITH CHECK ({check or using})')

    for t in CLIENT_TABLES:
        rls(t, scope)
    for t in NULLABLE_CLIENT_TABLES:
        rls(t, f"{scope} OR (client_id IS NULL AND (SELECT app_is_staff()))")
    # Staff see every client (also the row they are inserting, which RETURNING needs to read back).
    rls("clients", "(SELECT app_is_staff()) OR id = ANY ((SELECT app_client_ids())::integer[])", "(SELECT app_is_staff())")
    rls("user_clients", "(SELECT app_is_staff()) OR user_id = app_user_id()", "(SELECT app_is_staff())")
    rls("unknown_sources", "(SELECT app_is_staff())")
    rls("device_inventory", "EXISTS (SELECT 1 FROM devices d WHERE d.id = poll_device_id)")
    rls("vpn_tunnel_aliases", "EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id)")
    rls("notifications", "EXISTS (SELECT 1 FROM alerts a WHERE a.id = alert_id)")
    for t in ("incident_alerts", "incident_events", "incident_timeline"):
        rls(t, "EXISTS (SELECT 1 FROM incidents i WHERE i.id = incident_id)")
    rls("saved_searches", "user_id = app_user_id() OR (shared AND (SELECT app_is_staff()))", "user_id = app_user_id()")
    # Audit log: anyone may append (including before login); only staff may read; client-scoped rows stay scoped.
    op.execute("ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY")
    op.execute(f'CREATE POLICY app_all ON public.audit_log TO "{app}" USING (true) WITH CHECK (true)')
    op.execute(f'CREATE POLICY web_insert ON public.audit_log FOR INSERT TO "{web}" WITH CHECK (true)')
    op.execute(f'CREATE POLICY web_read ON public.audit_log FOR SELECT TO "{web}" USING ((SELECT app_is_staff()))')


def downgrade() -> None:
    s = get_settings()
    tables = (CLIENT_TABLES + NULLABLE_CLIENT_TABLES + ("clients", "user_clients", "unknown_sources", "device_inventory",
              "vpn_tunnel_aliases", "notifications", "incident_alerts", "incident_events", "incident_timeline",
              "saved_searches", "audit_log"))
    for t in tables:
        for p in ("app_all", "web_scope", "web_insert", "web_read"):
            op.execute(f"DROP POLICY IF EXISTS {p} ON public.{t}")
        op.execute(f"ALTER TABLE public.{t} DISABLE ROW LEVEL SECURITY")
    op.execute("DROP SCHEMA IF EXISTS scoped CASCADE")
    op.execute(f'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM "{s.db_web_user}"')
    op.execute(f'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM "{s.db_web_user}"')
    for fn in ("login_failures(text, text, integer)", "storage_sizes()", "app_client_ids()", "app_is_staff()", "app_user_id()"):
        op.execute(f"DROP FUNCTION IF EXISTS {fn}")
