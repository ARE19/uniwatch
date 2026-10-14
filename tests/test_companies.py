"""Company groups: several sites of one customer; picker scope, company rules and channels, reports per site."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import text

from app.alerts.engine import AlertEngine
from tests.conftest import csrf_from, full_login


@pytest.fixture
def sites(owner_engine):
    with owner_engine.begin() as c:
        ids = {}
        for name, slug in (("CTS KL", "cts-kl"), ("CTS SG", "cts-sg"), ("TSP-HK", "tsp-hk")):
            ids[name] = c.execute(text("INSERT INTO clients (name, slug) VALUES (:n, :s) RETURNING id"), {"n": name, "s": slug}).scalar()
            ids[name + " gw"] = c.execute(text("INSERT INTO devices (client_id, name, vendor) VALUES (:c, :n, 'unifi') RETURNING id"),
                                          {"c": ids[name], "n": name + "-UDM"}).scalar()
    return ids


async def test_admin_groups_sites_and_picker_scope(client, make_user, owner_engine, sites, audit_rows):
    await full_login(client, make_user(username="root-admin", role="admin"))
    page = (await client.get("/admin/clients")).text
    assert "CTS</strong> (CTS KL, CTS SG)" in page                              # suggestion from the names
    token = csrf_from(page)
    for name in ("CTS KL", "CTS SG"):
        r = await client.post(f"/admin/clients/{sites[name]}/company", data={"csrf_token": token, "new_company": "CTS"})
        assert r.status_code == 303
    with owner_engine.connect() as c:
        gid = c.execute(text("SELECT id FROM companies WHERE name = 'CTS'")).scalar()
        assert c.execute(text("SELECT count(*) FROM clients WHERE company_id = :g"), {"g": gid}).scalar() == 2
    assert audit_rows("client_company_set")
    page = (await client.get("/devices")).text
    assert f'value="g{gid}"' in page and "CTS (company)" in page               # in the client picker
    r = await client.post("/scope", data={"csrf_token": token, "client": f"g{gid}", "next": "/devices"})
    assert r.status_code == 303
    page = (await client.get("/devices")).text
    assert "CTS KL-UDM" in page and "CTS SG-UDM" in page and "TSP-HK-UDM" not in page and "All devices <span class=\"muted\">· CTS" in page
    assert (await client.post("/scope", data={"csrf_token": token, "client": "g999999"})).status_code == 403


async def test_company_rule_and_channel_cover_only_its_sites(client, make_user, owner_engine, sites):
    with owner_engine.begin() as c:
        gid = c.execute(text("INSERT INTO companies (name) VALUES ('CTS') RETURNING id")).scalar()
        c.execute(text("UPDATE clients SET company_id = :g WHERE name LIKE 'CTS %'"), {"g": gid})
        c.execute(text("UPDATE alert_rules SET enabled = false"))
        base = c.execute(text("SELECT id FROM alert_rules WHERE rule_type = 'failed_logins' ORDER BY id LIMIT 1")).scalar()
    await full_login(client, make_user(username="root-admin", role="admin"))
    token = csrf_from((await client.get("/event-monitor?tab=rules")).text)
    r = await client.post(f"/event-monitor/rules/{base}/copy", data={"csrf_token": token, "client_id": f"g{gid}"})
    assert r.status_code == 303
    r = await client.post("/event-monitor/channels", data={"csrf_token": token, "name": "CTS team", "type": "webhook",
                                                           "target": "https://hooks.example.test/cts", "client_id": f"g{gid}"})
    assert r.status_code == 303
    with owner_engine.begin() as c:
        rule = c.execute(text("SELECT id, client_id, company_id FROM alert_rules WHERE company_id = :g"), {"g": gid}).one()
        assert rule.client_id is None
        ch = c.execute(text("SELECT id FROM notification_channels WHERE company_id = :g"), {"g": gid}).scalar()
        c.execute(text("UPDATE alert_rules SET enabled = true, channel_ids = ARRAY[:ch]::int[], params = params - 'exclude_actions' WHERE id = :r"),
                  {"ch": ch, "r": rule.id})
        for name in ("CTS KL", "TSP-HK"):                                       # failures at an CTS site and at LEO
            for i in range(12):
                c.execute(text("""INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class,
                                      action, outcome, src_ip) VALUES (now() - make_interval(secs => :i), :c, :d, 0, now(), 'unifi', 'auth',
                                      'high', 'x', 'login-failed', 'failure', '85.217.149.17')"""),
                          {"i": i, "c": sites[name], "d": sites[name + " gw"]})
    sent = []

    async def outbox(channel, alert, kind, settings):
        sent.append((channel["name"], alert["client"]))
        return "sent"
    await AlertEngine(deliver_fn=outbox).evaluate(datetime.now(UTC))
    assert sent == [("CTS team", "CTS KL")]                                     # the company rule ignores TSP-HK


async def test_company_report_one_per_site_and_client_user_scope(client, make_user, owner_engine, sites):
    with owner_engine.begin() as c:
        gid = c.execute(text("INSERT INTO companies (name) VALUES ('CTS') RETURNING id")).scalar()
        c.execute(text("UPDATE clients SET company_id = :g WHERE name LIKE 'CTS %'"), {"g": gid})
    await full_login(client, make_user(role="engineer"))
    token = csrf_from((await client.get("/reports")).text)
    r = await client.post("/reports", data={"csrf_token": token, "client_id": f"g{gid}", "report_type": "device_uptime",
                                            "date_from": "2026-10-01", "date_to": "2026-10-10"})
    assert r.status_code == 303
    with owner_engine.connect() as c:
        names = sorted(c.execute(text("SELECT c.name FROM report_runs r JOIN clients c ON c.id = r.client_id")).scalars())
    assert names == ["CTS KL", "CTS SG"]
    leo = make_user(username="leo-viewer", role="client_readonly")
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO user_clients (user_id, client_id) VALUES (:u, :c)"), {"u": leo["id"], "c": sites["TSP-HK"]})
    client.cookies.clear()
    await full_login(client, leo)
    page = (await client.get("/cctv")).text
    assert "CTS (company)" not in page                                           # not one of this user's companies
