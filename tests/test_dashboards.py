"""Customisable dashboards: widget layouts, sharing and defaults (row-level security), saved-search widgets."""

import json
import re
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.web.widgets import DEFAULT_LAYOUT, normalise
from tests.conftest import csrf_from, full_login

W_RE = re.compile(r'<section class="card widget w-(\w+)[^"]*"\s+data-w="(\w+)"')


def widgets(html: str) -> list[tuple[str, str]]:
    return [(w, size) for size, w in W_RE.findall(html)]


@asynccontextmanager
async def session_as(user):
    from app.web.main import app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://testserver") as c:
        await full_login(c, user)
        yield c


async def save(c, body, token=None):
    token = token or csrf_from((await c.get("/")).text)
    return await c.post("/dashboards/save", content=json.dumps(body),
                        headers={"Content-Type": "application/json", "X-CSRF-Token": token})


@pytest.fixture
def two_clients(owner_engine, make_user):
    with owner_engine.begin() as c:
        acme = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Acme','acme') RETURNING id")).scalar()
        beta = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Beta','beta') RETURNING id")).scalar()
    staff = make_user(username="eng", role="engineer")
    va = make_user(username="acme-viewer", role="client_readonly")
    vb = make_user(username="beta-viewer", role="client_readonly")
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO user_clients (user_id, client_id) VALUES (:u, :c), (:v, :d)"),
                  {"u": va["id"], "c": acme, "v": vb["id"], "d": beta})
    return {"acme": acme, "beta": beta, "staff": staff, "va": va, "vb": vb}


def test_normalise_drops_unknown_duplicates_staff_only_and_bad_sizes():
    raw = [{"w": "traffic", "size": "full"}, {"w": "traffic"}, {"w": "nope"}, {"w": "rates", "size": "huge"},
           {"w": "search", "cfg": {"search_id": "7"}}, {"w": "search", "cfg": {"search_id": 8}}, {"w": "search"}, "junk"]
    assert normalise(raw, staff=True, search_ids={7}) == [
        {"w": "traffic", "size": "full"}, {"w": "rates", "size": "half"}, {"w": "search", "size": "third", "cfg": {"search_id": 7}}]
    assert normalise(raw, staff=False) == [{"w": "traffic", "size": "full"}]
    assert normalise("not a list", staff=True) == []


async def test_standard_dashboard_and_client_view(client, two_clients):
    await full_login(client, two_clients["staff"])
    page = (await client.get("/")).text
    assert [w for w, _ in widgets(page)] == [i["w"] for i in DEFAULT_LAYOUT]
    async with session_as(two_clients["va"]) as c:
        mine = [w for w, _ in widgets((await c.get("/")).text)]
    assert "rates" not in mine and "storage" not in mine and "traffic" in mine


async def test_save_private_dashboard_and_switch_back(client, two_clients, audit_rows):
    await full_login(client, two_clients["staff"])
    r = await save(client, {"name": "NOC wall", "layout": [{"w": "wan", "size": "full"}, {"w": "apps", "size": "third"},
                                                           {"w": "bogus"}, {"w": "talkers", "size": "half"}]})
    assert r.status_code == 200, r.text
    page = (await client.get("/")).text
    assert widgets(page) == [("wan", "full"), ("apps", "third"), ("talkers", "half")]
    assert "NOC wall" in page and audit_rows("dashboard_create")
    # edit in place
    r = await save(client, {"id": r.json()["id"], "name": "NOC wall", "layout": [{"w": "apps", "size": "full"}]})
    assert r.status_code == 200 and widgets((await client.get("/")).text) == [("apps", "full")]
    # back to the standard dashboard
    token = csrf_from((await client.get("/")).text)
    await client.post("/dashboards/select", data={"dashboard": "default", "csrf_token": token})
    assert len(widgets((await client.get("/")).text)) == len(DEFAULT_LAYOUT)


async def test_save_needs_csrf_and_widgets(client, two_clients):
    await full_login(client, two_clients["staff"])
    r = await client.post("/dashboards/save", content=json.dumps({"layout": [{"w": "wan"}]}),
                          headers={"Content-Type": "application/json", "X-CSRF-Token": "wrong"})
    assert r.status_code == 403
    assert (await save(client, {"layout": [{"w": "nope"}]})).status_code == 400


async def test_shared_default_per_client_and_permissions(client, two_clients, owner_engine):
    acme = two_clients["acme"]
    await full_login(client, two_clients["staff"])
    r = await save(client, {"name": "Acme view", "share": f"client:{acme}", "is_default": True,
                            "layout": [{"w": "wan", "size": "full"}, {"w": "sites", "size": "half"}]})
    assert r.status_code == 200, r.text
    board = r.json()["id"]

    async with session_as(two_clients["va"]) as c:            # Acme's user gets it by default
        page = (await c.get("/")).text
        assert widgets(page) == [("wan", "full"), ("sites", "half")] and "Acme view" in page
        token = csrf_from(page)
        # ... may not change, share or delete it
        r = await save(c, {"id": board, "name": "hijack", "layout": [{"w": "wan"}]}, token)
        assert r.status_code == 404
        assert (await save(c, {"name": "x", "share": "all", "layout": [{"w": "wan"}]}, token)).status_code == 403
        assert (await c.post(f"/dashboards/{board}/delete", data={"csrf_token": token})).status_code == 404
        # ... but may keep a private copy, which then is theirs
        r = await save(c, {"id": board, "as_new": True, "name": "My Acme", "layout": [{"w": "sites"}, {"w": "rates"}]}, token)
        assert r.status_code == 200
        assert widgets((await c.get("/")).text) == [("sites", "half")]      # staff-only widget dropped

    async with session_as(two_clients["vb"]) as c:            # Beta's user neither sees nor gets it
        page = (await c.get("/")).text
        assert "Acme view" not in page and len(widgets(page)) > 2

    with owner_engine.begin() as c:
        assert c.execute(text("SELECT name FROM dashboards WHERE id = :i"), {"i": board}).scalar() == "Acme view"


async def test_one_default_per_audience(client, two_clients, owner_engine):
    await full_login(client, two_clients["staff"])
    for name in ("First", "Second"):
        assert (await save(client, {"name": name, "share": "all", "is_default": True, "layout": [{"w": "wan"}]})).status_code == 200
    with owner_engine.begin() as c:
        assert c.execute(text("SELECT name FROM dashboards WHERE is_default")).scalars().all() == ["Second"]


async def test_saved_search_widget(client, two_clients, owner_engine):
    acme = two_clients["acme"]
    with owner_engine.begin() as c:
        dev = c.execute(text("INSERT INTO devices (client_id, name, vendor) VALUES (:c, 'GW', 'unifi') RETURNING id"),
                        {"c": acme}).scalar()
        now = datetime.now(UTC)
        for i, action in enumerate(["flow-blocked", "flow-blocked", "flow", "flow-blocked"]):
            c.execute(text("""INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class,
                              action, message) VALUES (:t, :c, :d, 0, :t, 'unifi', 'firewall', 'low', 'api:traffic-flow', :a, 'x')"""),
                      {"t": now - timedelta(minutes=10 + i), "c": acme, "d": dev, "a": action})
    await full_login(client, two_clients["staff"])
    token = csrf_from((await client.get("/logs")).text)
    await client.post("/logs/saved", data={"name": "Blocked connections", "query": "action=flow-blocked&range=1h",
                                           "csrf_token": token})
    with owner_engine.begin() as c:
        sid = c.execute(text("SELECT id FROM saved_searches")).scalar()
    r = await save(client, {"name": "Blocks", "layout": [{"w": "search", "size": "third", "cfg": {"search_id": sid}}]})
    assert r.status_code == 200, r.text
    page = (await client.get("/")).text
    assert f'data-search="{sid}"' in page and "Blocked connections" in page
    d = (await client.get(f"/api/dashboard/search/{sid}?range=24h")).json()
    assert d["count"] == 3 and d["name"] == "Blocked connections" and "action=flow-blocked" in d["link"]
    assert len(d["points"]) >= 24
    assert (await client.get("/api/dashboard/search/99999?range=24h")).status_code == 404
    async with session_as(two_clients["va"]) as c:
        assert (await c.get(f"/api/dashboard/search/{sid}")).status_code == 403
