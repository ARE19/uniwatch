"""Phase 10 acceptance: a client user cannot see another client's data — enforced by the DATABASE (web role:
row-level security + scoped views) and by every UI/API/export/report path.

The database tests deliberately issue UNFILTERED queries (no WHERE client_id …) as the web role: whatever
the application forgets, the database must still return only the caller's own client."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from app import db
from tests.conftest import csrf_from, full_login
from tests.test_logview import _add

NOW = datetime.now(UTC)
# Every client-scoped relation the web role can read (views shadow the hypertables/aggregates).
SCOPED = ["events", "raw_logs", "device_metrics", "raw_logs_1m", "events_5m", "events_src_1h", "events_dst_1h",
          "events_rule_1h", "devices", "config_changes", "device_state", "maintenance_windows", "network_clients",
          "vpn_tunnel_state", "vpn_sessions", "report_runs", "alerts", "incidents", "clients"]


@pytest.fixture
def two_tenants(owner_engine, make_user):
    with owner_engine.begin() as c:
        ids = {}
        for slug in ("acme", "globex"):
            cid = c.execute(text("INSERT INTO clients (name, slug) VALUES (:n, :s) RETURNING id"), {"n": slug.title(), "s": slug}).scalar()
            did = c.execute(text("INSERT INTO devices (client_id, name, vendor, last_log_at) VALUES (:c, :n, 'unifi', now()) RETURNING id"),
                            {"c": cid, "n": f"{slug}-gw"}).scalar()
            ids[slug] = (cid, did)
            eid = _add(c, cid, did, category="vpn", src="85.217.149.17", dst="192.168.1.1", action="vpn-tls-error",
                       message=f"{slug} secret")
            p = {"c": cid, "d": did}
            c.execute(text("INSERT INTO device_metrics (ts, client_id, device_id, cpu_pct) VALUES (now(), :c, :d, 50)"), p)
            c.execute(text("INSERT INTO config_changes (ts, client_id, device_id, raw_id, raw_ts, action, summary) VALUES (now(), :c, :d, 0, now(), 'modify', 'x')"), p)
            c.execute(text("INSERT INTO device_state (client_id, device_id, state, started_at) VALUES (:c, :d, 'up', now())"), p)
            c.execute(text("INSERT INTO maintenance_windows (client_id, starts_at, ends_at) VALUES (:c, now(), now() + interval '1 hour')"), p)
            c.execute(text("INSERT INTO network_clients (client_id, device_id, mac, first_seen, last_seen) VALUES (:c, :d, '00:00:00:b5:a4:31', now(), now())"), p)
            c.execute(text("INSERT INTO vpn_tunnel_state (client_id, device_id, tunnel_name, state, started_at) VALUES (:c, :d, 'tun0', 'up', now())"), p)
            c.execute(text("INSERT INTO vpn_sessions (client_id, device_id, user_name, last_seen_at, status) VALUES (:c, :d, 'u', now(), 'open')"), p)
            c.execute(text("INSERT INTO report_runs (client_id, report_type, period_start, period_end, status, pdf_path) "
                           "VALUES (:c, 'vpn_uptime', now() - interval '1 day', now(), 'done', '/tmp/reports/x.pdf')"), p)
            rule = c.execute(text("SELECT id FROM alert_rules LIMIT 1")).scalar()
            c.execute(text("INSERT INTO alerts (rule_id, client_id, dedup_key, severity, title, first_seen, last_seen) "
                           "VALUES (:r, :c, 'k', 'high', :t, now(), now())"), {"r": rule, "c": cid, "t": f"{slug} alert"})
            c.execute(text("INSERT INTO incidents (client_id, title, severity) VALUES (:c, :t, 'high')"), {"c": cid, "t": f"{slug} incident"})
            ids[slug] += (eid,)
    viewer = make_user(role="client_readonly", username="acme-viewer")
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO user_clients (user_id, client_id) VALUES (:u, :c)"), {"u": viewer["id"], "c": ids["acme"][0]})
    staff = make_user(role="engineer", username="eng")
    return ids, viewer, staff


async def _counts(user_id: int) -> dict:
    out = {}
    async with db.sessionmaker("web")() as s:
        await db.apply_scope(s, user_id, staff=False)   # the DB decides staff-ness itself, not this flag
        for t in SCOPED:
            col = "id" if t == "clients" else "client_id"
            out[t] = sorted({r[0] for r in (await s.execute(text(f"SELECT DISTINCT {col} FROM {t}"))).all()})
    return out


async def test_database_returns_only_own_client_without_any_where_clause(two_tenants):
    ids, viewer, staff = two_tenants
    acme, globex = ids["acme"][0], ids["globex"][0]
    mine = await _counts(viewer["id"])
    assert {k: v for k, v in mine.items() if v != [acme]} == {}
    everything = await _counts(staff["id"])
    assert {k: v for k, v in everything.items() if v != sorted([acme, globex])} == {}
    nobody = await _counts(0)                               # unauthenticated request
    assert {k: v for k, v in nobody.items() if v != []} == {}


async def test_staff_flag_cannot_be_forged(two_tenants):
    """Even if application code wrongly marked a client user as staff, the DB checks the real role."""
    ids, viewer, staff = two_tenants
    async with db.sessionmaker("web")() as s:
        await db.apply_scope(s, viewer["id"], staff=True)
        rows = (await s.execute(text("SELECT DISTINCT client_id FROM events"))).all()
    assert [r[0] for r in rows] == [ids["acme"][0]]


@pytest.mark.parametrize("sql", ["SELECT 1 FROM public.events", "SELECT 1 FROM public.raw_logs", "SELECT 1 FROM public.raw_logs_1m",
                                 "SELECT secret_enc FROM device_credentials", "SELECT 1 FROM tracker_cursors",
                                 "DELETE FROM scoped.events"])
async def test_web_role_has_no_direct_access(two_tenants, sql):
    ids, viewer, staff = two_tenants
    async with db.sessionmaker("web")() as s:
        await db.apply_scope(s, staff["id"], staff=True)
        with pytest.raises((ProgrammingError, DBAPIError), match="permission denied|cannot delete from view"):
            await s.execute(text(sql))


async def test_writes_into_another_client_are_rejected(two_tenants):
    ids, viewer, staff = two_tenants
    async with db.sessionmaker("web")() as s:
        await db.apply_scope(s, viewer["id"], staff=False)
        with pytest.raises((ProgrammingError, DBAPIError), match="row-level security"):
            await s.execute(text("INSERT INTO report_runs (client_id, report_type, period_start, period_end) "
                                 "VALUES (:c, 'vpn_uptime', now() - interval '1 day', now())"), {"c": ids["globex"][0]})
    async with db.sessionmaker("web")() as s:   # updates simply see no foreign rows
        await db.apply_scope(s, viewer["id"], staff=False)
        res = await s.execute(text("UPDATE incidents SET title = 'pwned' WHERE client_id = :c"), {"c": ids["globex"][0]})
        assert res.rowcount == 0


async def test_audit_log_append_only_and_staff_readable(two_tenants):
    ids, viewer, staff = two_tenants
    async with db.sessionmaker("web")() as s:
        await db.apply_scope(s, viewer["id"], staff=False)
        await s.execute(text("INSERT INTO audit_log (action, username) VALUES ('probe', 'acme-viewer')"))
        assert (await s.execute(text("SELECT count(*) FROM audit_log"))).scalar() == 0
        await s.commit()
    async with db.sessionmaker("web")() as s:
        await db.apply_scope(s, staff["id"], staff=True)
        assert (await s.execute(text("SELECT count(*) FROM audit_log WHERE action = 'probe'"))).scalar() == 1


async def test_login_lockout_still_counts_failures_through_definer_function(client, make_user, audit_rows):
    make_user(username="lockme")
    from tests.conftest import password_step
    for _ in range(10):
        await password_step(client, "lockme", "wrong-password-xx")
    assert (await password_step(client, "lockme", "Correct-Horse-Battery-9")).status_code == 429


async def test_client_user_every_path(client, owner_engine, two_tenants):
    ids, viewer, staff = two_tenants
    gcid, gdid, geid = ids["globex"]
    await full_login(client, viewer)
    for url in ("/", "/insights?view=sources&range=24h", "/vpn", "/reports"):
        r = await client.get(url)
        assert r.status_code == 200 and "globex" not in r.text.lower(), url
    d = (await client.get("/api/dashboard?range=24h")).json()
    assert "globex" not in str(d).lower()
    with owner_engine.connect() as c:
        grun = c.execute(text("SELECT id FROM report_runs WHERE client_id = :c"), {"c": gcid}).scalar()
    assert (await client.get(f"/reports/{grun}/pdf")).status_code == 404
    for url in (f"/logs/event/{geid}", "/logs/export.csv", f"/sources/raw?device_id={gdid}", "/event-monitor", "/incidents",
                "/threat-intel", "/admin/storage", f"/ip/85.217.149.17"):
        assert (await client.get(url)).status_code in (403, 404), url
    token = csrf_from((await client.get("/reports")).text)
    assert (await client.post("/reports", data={"client_id": str(gcid), "report_type": "vpn_uptime", "month": "2026-10",
                                                "csrf_token": token})).status_code == 403
    client.cookies.set("cls_scope", str(gcid))              # forged client picker
    d = (await client.get("/api/dashboard?range=24h")).json()
    assert "globex" not in str(d).lower()
