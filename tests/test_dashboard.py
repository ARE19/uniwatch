"""Dashboard page + data API, including client scoping (FortiAnalyzer ADOM equivalent)."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from tests.conftest import csrf_from, full_login


def _seed(owner_engine):
    """Two clients, one device each, a few raw lines and events each."""
    now = datetime.now(UTC)
    with owner_engine.begin() as c:
        ids = {}
        for slug, ip in (("acme", "10.0.0.1"), ("globex", "10.0.0.2")):
            cid = c.execute(text("INSERT INTO clients (name, slug) VALUES (:n, :s) RETURNING id"), {"n": slug.title(), "s": slug}).scalar()
            did = c.execute(text("INSERT INTO devices (client_id, name, vendor, syslog_source_ip, last_log_at) "
                                 "VALUES (:c, :n, 'unifi', :ip, :t) RETURNING id"),
                            {"c": cid, "n": f"{slug}-gw", "ip": ip, "t": now}).scalar()
            ids[slug] = (cid, did)
            for i in range(3):
                rid = c.execute(text("INSERT INTO raw_logs (ts_received, client_id, device_id, source_ip, transport, raw, parsed) "
                                     "VALUES (:t, :c, :d, :ip, 'udp', 'x', true) RETURNING id"),
                                {"t": now - timedelta(minutes=i), "c": cid, "d": did, "ip": ip}).scalar()
                c.execute(text("INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class, rule) "
                               "VALUES (:t, :c, :d, :r, :t, 'unifi', 'ids', :sev, 'cef:200', :rule)"),
                          {"t": now - timedelta(minutes=i), "c": cid, "d": did, "r": rid,
                           "sev": "high" if i == 0 else "low", "rule": f"{slug} signature"})
    return ids


async def test_dashboard_page_renders_for_staff(client, make_user):
    await full_login(client, make_user(role="engineer"))
    r = await client.get("/")
    assert r.status_code == 200 and "Log receive monitor" in r.text and "Insert lag time" in r.text


async def test_dashboard_api_all_clients(client, make_user, owner_engine):
    _seed(owner_engine)
    await full_login(client, make_user(role="admin", username="root-admin"))
    d = (await client.get("/api/dashboard?range=1h")).json()
    assert d["tiles"]["lines"] == 6 and d["tiles"]["events"] == 6
    assert d["tiles"]["severity"]["high"] == 2
    assert {x["name"] for x in d["devices"]} == {"acme-gw", "globex-gw"}
    assert "ingest" in d and "storage" in d["ingest"]
    assert {t["rule"] for t in d["threats"]} == {"acme signature", "globex signature"}


async def test_scope_selection_limits_data(client, make_user, owner_engine):
    ids = _seed(owner_engine)
    await full_login(client, make_user(role="admin", username="root-admin"))
    token = csrf_from((await client.get("/")).text)
    r = await client.post("/scope", data={"client": str(ids["acme"][0]), "csrf_token": token}, headers={"referer": "https://testserver/?range=1h"})
    assert r.status_code == 303 and r.headers["location"] == "/?range=1h"
    d = (await client.get("/api/dashboard?range=1h")).json()
    assert [x["name"] for x in d["devices"]] == ["acme-gw"] and d["tiles"]["events"] == 3


async def test_client_user_sees_only_own_client(client, make_user, owner_engine):
    ids = _seed(owner_engine)
    u = make_user(role="client_readonly", username="acme-viewer")
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO user_clients (user_id, client_id) VALUES (:u, :c)"), {"u": u["id"], "c": ids["acme"][0]})
    await full_login(client, u)
    d = (await client.get("/api/dashboard?range=1h")).json()
    assert [x["name"] for x in d["devices"]] == ["acme-gw"]
    assert {t["rule"] for t in d["threats"]} == {"acme signature"}
    assert "ingest" not in d  # platform internals are staff-only
    # Selecting another client's id is refused, and a forged cookie is ignored.
    token = csrf_from((await client.get("/")).text)
    assert (await client.post("/scope", data={"client": str(ids["globex"][0]), "csrf_token": token})).status_code == 403
    client.cookies.set("cls_scope", str(ids["globex"][0]))
    r = await client.get("/api/dashboard?range=1h")
    assert r.status_code == 200
    d = r.json()
    assert [x["name"] for x in d["devices"]] == ["acme-gw"]


async def test_client_user_with_no_clients_sees_nothing(client, make_user, owner_engine):
    _seed(owner_engine)
    await full_login(client, make_user(role="client_readonly", username="nobody"))
    d = (await client.get("/api/dashboard?range=24h")).json()
    assert d["devices"] == [] and d["tiles"]["events"] == 0


async def test_dashboard_api_requires_login(client):
    r = await client.get("/api/dashboard")
    assert r.status_code == 303 and r.headers["location"] == "/login"


def test_bucket_grid_is_aligned_and_complete():
    from app.web.routes_dashboard import bucket_grid
    since = datetime(2026, 10, 6, 8, 0, 30, tzinfo=UTC)
    now = datetime(2026, 10, 6, 8, 5, 10, tzinfo=UTC)
    g = bucket_grid(since, now, "1 minute")
    assert len(g) == 6 and g[0] == int(datetime(2026, 10, 6, 8, 0, tzinfo=UTC).timestamp() * 1000)
    assert all(b - a == 60000 for a, b in zip(g, g[1:]))


async def test_receive_series_zero_filled(client, make_user, owner_engine):
    _seed(owner_engine)
    await full_login(client, make_user(role="engineer"))
    d = (await client.get("/api/dashboard?range=1h")).json()
    for s in d["receive"]["series"]:
        assert len(s["points"]) >= 60 and sum(v for _, v in s["points"]) == 3


async def test_dashboard_health_and_vpn(client, make_user, owner_engine):
    ids = _seed(owner_engine)
    cid, did = ids["acme"]
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO device_metrics (ts, client_id, device_id, cpu_pct, mem_pct, temp_c, uptime_s, client_count) "
                       "VALUES (now(), :c, :d, 42.5, 67.0, 53.5, 90000, 12)"), {"c": cid, "d": did})
        c.execute(text("INSERT INTO device_state (client_id, device_id, state, started_at, ended_at) VALUES "
                       "(:c, :d, 'up', now() - interval '60 minutes', now() - interval '30 minutes'), "
                       "(:c, :d, 'down', now() - interval '30 minutes', now() - interval '20 minutes')"), {"c": cid, "d": did})
        c.execute(text("INSERT INTO device_state (client_id, device_id, state, started_at) VALUES (:c, :d, 'up', now() - interval '20 minutes')"),
                  {"c": cid, "d": did})
        c.execute(text("INSERT INTO vpn_tunnel_state (client_id, device_id, tunnel_name, state, started_at) VALUES (:c, :d, 'tun0', 'up', now())"),
                  {"c": cid, "d": did})
    await full_login(client, make_user(role="engineer"))
    d = (await client.get("/api/dashboard?range=1h")).json()
    h = next(x for x in d["health"] if x["id"] == did)
    assert (h["cpu_pct"], h["temp_c"], h["client_count"], h["state"]) == (42.5, 53.5, 12, "up")
    assert 83.0 <= h["availability"] <= 83.5  # 50 min up of 60 (10 down) -> 83.33 %
    assert d["vpn"][0]["tunnel_name"] == "tun0" and d["vpn"][0]["state"] == "up"



async def test_noc_wall_and_client_param(client, make_user, owner_engine):
    from sqlalchemy import text as _t
    with owner_engine.begin() as c:
        a = c.execute(_t("INSERT INTO clients (name, slug) VALUES ('Wall A','wall-a') RETURNING id")).scalar()
        b = c.execute(_t("INSERT INTO clients (name, slug) VALUES ('Wall B','wall-b') RETURNING id")).scalar()
    viewer = make_user(role="client_readonly", username="wall-viewer")
    with owner_engine.begin() as c:
        c.execute(_t("INSERT INTO user_clients (user_id, client_id) VALUES (:u, :c)"), {"u": viewer["id"], "c": a})
    await full_login(client, viewer)
    page = (await client.get("/wall")).text
    assert "Wall A" in page and "Wall B" not in page and "wall.js" in page
    ok = await client.get(f"/api/dashboard?range=24h&client={a}")
    assert ok.status_code == 200 and ok.json()["open_alerts"] == 0
    assert (await client.get(f"/api/dashboard?range=24h&client={b}")).status_code == 403       # never widens the scope
