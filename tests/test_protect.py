"""CCTV access log (UniFi Protect via Site Manager), from the real events captured 2026-10-09."""

import json
from pathlib import Path

import pytest
from sqlalchemy import text

from app.config import get_settings
from app.poller import protect
from app.poller.service import Poller
from tests.conftest import full_login

SAMPLES = json.loads((Path(__file__).resolve().parent.parent / "samples" / "unifi-protect-access-events-2026-10-09.json").read_text())
EVENTS = [v["event"] for v in SAMPLES.values()]


def by_action(action):
    return next(protect.parse(e) for e in EVENTS if protect.parse(e)["action"] == action)


def test_parse_real_events():
    acc = by_action("accessed")
    assert acc["kind"] == "access" and acc["user_name"] == "Unifi Owner" and acc["ip"] == "11.162.174.120"
    assert acc["platform"] == "web" and acc["message"] == "Unifi Owner accessed UniFi Protect using the web for 22h 1m 2s."
    assert acc["duration_s"] == pytest.approx((1791270047152 - 1791190784891) / 1000)
    tl = by_action("cameraTimelineViewed")
    assert tl["camera_name"] == "CTSKL-CCTV1 - Lobby" and tl["user_name"] == "Alice Chan"
    assert tl["message"] == "Alice Chan viewed the timeline of CTSKL-CCTV1 - Lobby for 6m 48s."
    assert tl["duration_s"] == pytest.approx(408.36, abs=0.01) and tl["ended_at"] is None
    dl = by_action("deviceListViewed")
    assert dl["camera_name"] is None and dl["message"] == "Bob Lim viewed the Device list."   # "unknown device" dropped


@pytest.fixture
def sites(owner_engine):
    with owner_engine.begin() as c:
        kl = c.execute(text("INSERT INTO clients (name, slug, timezone) VALUES ('CTS KL','cts-kl','Asia/Kuala_Lumpur') RETURNING id")).scalar()
        hk = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Northwind HK','nwhk') RETURNING id")).scalar()
        for host, cid in (("host-kl", kl), ("host-hk", hk), ("host-off", hk)):
            c.execute(text("""INSERT INTO sitemanager_hosts (host_id, client_id, name, state, last_sync)
                              VALUES (:h, :c, :h, :s, now())"""), {"h": host, "c": cid, "s": "disconnected" if host == "host-off" else "connected"})
    return {"kl": kl, "hk": hk}


async def collect(fetch):
    p = Poller(get_settings().model_copy(update={"unifi_site_manager_api_key": "test-key"}), drivers={})
    conn = await p.connect()
    try:
        return await p.protect_activity(conn, force=True, fetch=fetch)
    finally:
        await conn.close()


async def test_collect_all_consoles_skip_without_protect(owner_engine, sites):
    calls = []

    async def fetch(key, host, since_ms, until_ms):
        calls.append((host, since_ms))
        if host == "host-hk":
            raise protect.NoProtect("no protect")
        return "7.2.105", EVENTS
    assert await collect(fetch) == {"host-kl": len(EVENTS)}
    assert {h for h, _ in calls} == {"host-kl", "host-hk"}                     # disconnected console not asked
    assert await collect(fetch) == {"host-kl": len(EVENTS)}                     # idempotent (upsert)
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM protect_activity")).scalar() == len(EVENTS)
        st = dict(c.execute(text("SELECT host_id, status FROM protect_consoles")).all())
    assert st == {"host-kl": "ok", "host-hk": "no protect"}
    # second run starts 2 days before the newest stored event (sessions get their end later), first run 30 days back
    first, second = [s for h, s in calls if h == "host-kl"]
    assert second > first


async def test_cctv_page_scoped_and_filtered(client, make_user, owner_engine, sites):
    async def fetch(key, host, since_ms, until_ms):
        return "7.2.105", EVENTS if host == "host-kl" else []
    await collect(fetch)
    with owner_engine.begin() as c:                                             # sample events are older than 90 days in a test run? keep them recent
        c.execute(text("UPDATE protect_activity SET ts = now() - interval '1 hour'"))
    await full_login(client, make_user(role="engineer"))
    page = (await client.get("/cctv?range=24h")).text
    assert "Alice Chan viewed the timeline of CTSKL-CCTV1 - Lobby for 6m 48s." in page and "CTS KL" in page
    assert "collecting" in page and "Protect sign-ins" in page
    only_alice = (await client.get("/cctv?range=24h&user=Alice+Chan")).text
    assert "Alice Chan viewed" in only_alice and "Bob Lim viewed" not in only_alice
    rec = (await client.get("/cctv?range=24h&kind=recordings")).text
    assert "viewed the timeline" in rec and "accessed UniFi Protect" not in rec


async def test_cctv_client_user_sees_only_own_sites(client, make_user, owner_engine, sites):
    async def fetch(key, host, since_ms, until_ms):
        return "7.2.105", EVENTS if host == "host-kl" else []
    await collect(fetch)
    with owner_engine.begin() as c:
        c.execute(text("UPDATE protect_activity SET ts = now() - interval '1 hour'"))
    u = make_user(username="viewer-hk", role="client_readonly")
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO user_clients (user_id, client_id) VALUES (:u, :c)"), {"u": u["id"], "c": sites["hk"]})
    await full_login(client, u)
    page = (await client.get("/cctv?range=24h")).text
    assert "Alice Chan" not in page and "No CCTV access in this period." in page
