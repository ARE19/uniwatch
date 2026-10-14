"""Global search, the VPN user page and the device/IP "360" page."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from tests.conftest import full_login


@pytest.fixture
def site(owner_engine):
    now = datetime.now(UTC)
    with owner_engine.begin() as c:
        cid = c.execute(text("INSERT INTO clients (name, slug) VALUES ('CTS KL','cts-kl') RETURNING id")).scalar()
        other = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Beta','beta') RETURNING id")).scalar()
        dev = c.execute(text("INSERT INTO devices (client_id, name, vendor, syslog_source_ip) VALUES (:c,'CTS-KL','unifi','11.133.111.195') "
                             "RETURNING id"), {"c": cid}).scalar()
        bdev = c.execute(text("INSERT INTO devices (client_id, name, vendor) VALUES (:c,'beta-gw','unifi') RETURNING id"), {"c": other}).scalar()
        c.execute(text("""INSERT INTO network_clients (client_id, device_id, mac, ip_internal, hostname, vendor, network, is_wired, first_seen, last_seen)
                          VALUES (:c, :d, '8c:f8:c5:f8:32:1d', '192.168.2.184', 'CTSKL-SQL01', 'Dell', 'LAN', true, now() - interval '9 days', now())"""),
                  {"c": cid, "d": dev})
        for i, (start, end, src) in enumerate(((50, 40, "11.38.150.78"), (30, None, "192.168.2.200"))):
            c.execute(text("""INSERT INTO vpn_sessions (client_id, device_id, user_name, source_ip, assigned_ip, started_at, ended_at,
                              last_seen_at, status, bytes_in, bytes_out) VALUES (:c, :d, 'Grace Lee''s Desktop', :s, '192.168.1.99',
                              :st, :en, coalesce(:en, now()), :status, 1048576, 1024)"""),
                      {"c": cid, "d": dev, "s": src, "st": now - timedelta(minutes=start),
                       "en": now - timedelta(minutes=end) if end else None, "status": "closed" if end else "open"})
        c.execute(text("""INSERT INTO vpn_sessions (client_id, device_id, user_name, started_at, last_seen_at, status)
                          VALUES (:c, :d, 'Secret Beta''s Desktop', now(), now(), 'open')"""), {"c": other, "d": bdev})
        for i in range(3):
            c.execute(text("""INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class, action,
                              outcome, rule, src_ip, dst_ip, dst_port, message) VALUES (:t, :c, :d, 0, :t, 'unifi', 'ids', 'low', 'x',
                              'ids-detect', 'blocked', 'ET SCAN Behavioral Unusual Port 1433 traffic', '192.168.2.184', '192.168.38.20', 1433, 'scan')"""),
                      {"t": now - timedelta(hours=i), "c": cid, "d": dev})
    return cid, dev, other


async def test_search_routes(client, make_user, site):
    await full_login(client, make_user(role="engineer"))
    r = await client.get("/search?q=192.168.2.184")
    assert r.status_code == 303 and r.headers["location"] == "/ip/192.168.2.184"
    r = await client.get("/search?q=8C-F8-C5-F8-32-1D")                              # MAC, any notation
    assert r.status_code == 303 and r.headers["location"] == "/ip/192.168.2.184"
    r = await client.get("/search?q=10.0.0.0/8")
    assert r.status_code == 303 and "ip=10.0.0.0%2F8" in r.headers["location"]
    r = await client.get("/search?q=sql01")                                           # one hostname hit -> straight there
    assert r.status_code == 303 and r.headers["location"] == "/ip/192.168.2.184"
    r = await client.get("/search?q=grace")
    assert r.status_code == 303 and r.headers["location"].startswith("/vpn/user?name=Grace")
    page = (await client.get("/search?q=desktop")).text                               # several hits -> results page
    assert "Grace Lee" in page and "Secret Beta" in page                             # staff with all clients see both
    assert "Search log messages for" in (await client.get("/search?q=nothing-matches-this")).text


async def test_search_respects_client_scope(client, make_user, owner_engine, site):
    cid, _, _ = site
    viewer = make_user(role="client_readonly", username="viewer")
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO user_clients (user_id, client_id) VALUES (:u, :c)"), {"u": viewer["id"], "c": cid})
    await full_login(client, viewer)
    assert (await client.get("/search?q=desktop")).status_code == 403                 # search is staff-only
    assert (await client.get("/vpn/user?name=Secret+Beta%27s+Desktop")).status_code == 404   # other client's user
    assert (await client.get("/vpn/user?name=Grace+Lee%27s+Desktop")).status_code == 200


async def test_vpn_user_page(client, make_user, site):
    await full_login(client, make_user(role="engineer"))
    page = (await client.get("/vpn/user?name=Grace+Lee%27s+Desktop")).text
    assert "<h1>Grace Lee" in page and "connected now" in page and "2.0 MB / 2.0 KB" in page
    assert "internal network" in page and "11.38.150.78" in page and 'class="hourbar"' in page


async def test_ip_360(client, make_user, site):
    await full_login(client, make_user(role="engineer"))
    page = (await client.get("/ip/192.168.2.184")).text
    assert "<h1>CTSKL-SQL01" in page and "8c:f8:c5:f8:32:1d" in page and "Dell" in page
    assert "ET SCAN Behavioral Unusual Port 1433 traffic" in page and ">IDS/IPS alerts</span><span class=\"tile-value\">3<" in page
    vpn = (await client.get("/ip/192.168.1.99")).text
    assert "VPN address" in vpn and "Grace Lee" in vpn
