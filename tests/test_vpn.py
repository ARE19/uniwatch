"""Phase 5: VPN tunnel intervals and user sessions (state machine), plus the VPN monitor page."""

import json
import re
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from app.config import get_settings
from app.tracker.vpn import TrackerConfig, VpnTracker
from app.web.routes_vpn import availability, human, strip_class
from tests.conftest import csrf_from, full_login

T0 = datetime.now(UTC).replace(microsecond=0) - timedelta(hours=2)


@pytest.fixture
def dev(owner_engine):
    with owner_engine.begin() as c:
        cid = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Northwind HK','nwhk') RETURNING id")).scalar()
        did = c.execute(text("INSERT INTO devices (client_id, name, vendor, last_log_at) VALUES (:c,'NW-HK','unifi', now()) RETURNING id"),
                        {"c": cid}).scalar()
    return cid, did


def ev(c, cid, did, minute, action, *, iface=None, path=None, peer=None, user=None, src=None, outcome=None):
    c.execute(text("""
        INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class, action,
                            outcome, interface, dst_ip, dst_port, user_name, src_ip, extra)
        VALUES (:t, :c, :d, 0, :t, 'unifi', 'vpn', 'low', 'test', :a, :o, :i, :peer, :port, :u, :src, CAST(:x AS jsonb))"""),
        {"t": T0 + timedelta(minutes=minute), "c": cid, "d": did, "a": action, "o": outcome, "i": iface,
         "peer": peer, "port": 1194 if peer else None, "u": user, "src": src,
         "x": json.dumps({"vpn_path": path} if path else {})})


async def run(tracker, now=None):
    conn = await tracker.connect()
    try:
        while await tracker.run_once(conn, now):
            pass
        await tracker.housekeeping(conn, now)
    finally:
        await conn.close()


def intervals(owner_engine):
    with owner_engine.connect() as c:
        return [tuple(r) for r in c.execute(text(
            "SELECT tunnel_name, state, started_at, ended_at, peer FROM vpn_tunnel_state ORDER BY started_at, id"))]


async def test_tunnel_flap_with_duplicate_signals_and_aliases(owner_engine, dev):
    """Mirrors the real UDM sequence: Link DOWN + ClientDisconnected, ClientFailed (path only), Link UP + ClientConnected."""
    cid, did = dev
    P, I, PEER = "/vpn/openvpn/raws/1", "tunovpnc1", "11.124.200.216"
    with owner_engine.begin() as c:
        ev(c, cid, did, 0, "vpn-client-connected", iface=I, path=P, peer=PEER)
        ev(c, cid, did, 0, "link-up", iface=I)                       # duplicate up
        ev(c, cid, did, 50, "vpn-client-disconnected", iface=I, path=P, peer=PEER)
        ev(c, cid, did, 50, "link-down", iface=I)                    # duplicate down
        ev(c, cid, did, 51, "vpn-client-failed", path=P)             # path only -> alias -> same tunnel, still down
        ev(c, cid, did, 51, "vpn-client-connecting", path=P)
        ev(c, cid, did, 60, "link-up", iface=I)
        ev(c, cid, did, 60, "vpn-client-connected", iface=I, path=P, peer=PEER)
    await run(VpnTracker(get_settings()))
    iv = intervals(owner_engine)
    assert [(n, s) for n, s, *_ in iv] == [(I, "up"), (I, "down"), (I, "up")]
    assert iv[0][2] == T0 and iv[0][3] == T0 + timedelta(minutes=50)
    assert iv[1][3] - iv[1][2] == timedelta(minutes=10) and iv[2][3] is None
    assert iv[0][4] == "11.124.200.216:1194"


async def test_replay_and_out_of_order_events_are_ignored(owner_engine, dev):
    cid, did = dev
    with owner_engine.begin() as c:
        ev(c, cid, did, 0, "link-up", iface="tun0")
        ev(c, cid, did, 30, "link-down", iface="tun0")
    tracker = VpnTracker(get_settings())
    await run(tracker)
    with owner_engine.begin() as c:  # a parser replay re-inserts the same events with new ids
        ev(c, cid, did, 0, "link-up", iface="tun0")
        ev(c, cid, did, 30, "link-down", iface="tun0")
    await run(tracker)
    assert [s for _, s, *_ in intervals(owner_engine)] == ["up", "down"]


async def test_log_gap_makes_state_unknown(owner_engine, dev):
    cid, did = dev
    with owner_engine.begin() as c:
        ev(c, cid, did, 0, "link-up", iface="tun0")
        c.execute(text("UPDATE devices SET last_log_at = :t WHERE id = :d"), {"t": T0 + timedelta(minutes=5), "d": did})
    await run(VpnTracker(get_settings(), TrackerConfig(gap_after=timedelta(minutes=15))))
    iv = intervals(owner_engine)
    assert [s for _, s, *_ in iv] == ["up", "unknown"]
    assert iv[0][3] == T0 + timedelta(minutes=5) and iv[1][2] == T0 + timedelta(minutes=5)
    with owner_engine.begin() as c:  # logs resume with a tunnel event
        ev(c, cid, did, 90, "link-down", iface="tun0")
        c.execute(text("UPDATE devices SET last_log_at = now() WHERE id = :d"), {"d": did})
    await run(VpnTracker(get_settings()))
    assert [s for _, s, *_ in intervals(owner_engine)] == ["up", "unknown", "down"]


async def test_user_sessions_pairing(owner_engine, dev):
    cid, did = dev
    with owner_engine.begin() as c:
        ev(c, cid, did, 0, "vpn-user-connect", user="alice", src="85.217.149.17")
        ev(c, cid, did, 45, "vpn-user-disconnect", user="alice", src="85.217.149.17")
        ev(c, cid, did, 10, "vpn-user-disconnect", user="bob")                    # connect never logged
        ev(c, cid, did, 20, "vpn-user-connect", user="carol")
        ev(c, cid, did, 30, "vpn-user-connect", user="carol")                     # disconnect lost in between
        ev(c, cid, did, 5, "vpn-user-connect", user="dave")                       # never disconnects
    await run(VpnTracker(get_settings(), TrackerConfig(orphan_after=timedelta(hours=1))))
    with owner_engine.connect() as c:
        rows = {(r.user_name, r.status, r.close_reason): r for r in c.execute(text(
            "SELECT user_name, status, close_reason, started_at, ended_at FROM vpn_sessions ORDER BY id"))}
    alice = rows[("alice", "closed", "disconnect")]
    assert alice.ended_at - alice.started_at == timedelta(minutes=45)
    assert rows[("bob", "closed", "disconnect-without-connect")].started_at is None
    assert ("carol", "closed", "superseded-by-new-connect") in rows and ("carol", "orphaned", "no-disconnect-logged") in rows
    dave = rows[("dave", "orphaned", "no-disconnect-logged")]
    assert dave.ended_at == T0 + timedelta(minutes=5)


def test_helpers():
    assert availability(3000, 600) == pytest.approx(3000 / 3600) and availability(0, 0) is None
    assert strip_class(1.0) == "good" and strip_class(0.995) == "warning" and strip_class(0.5) == "critical"
    assert strip_class(None) == "unknown"
    assert human(3725) == "1h 2m" and human(45) == "45s" and human(90061) == "1d 1h"


async def test_vpn_page_numbers_match_hand_calculation(client, make_user, owner_engine, dev):
    cid, did = dev
    with owner_engine.begin() as c:
        ev(c, cid, did, 0, "link-up", iface="tun0")
        ev(c, cid, did, 50, "link-down", iface="tun0")
        ev(c, cid, did, 60, "link-up", iface="tun0")
        ev(c, cid, did, 70, "vpn-tls-error", src="85.217.149.17", outcome="failure")
    await run(VpnTracker(get_settings()))
    viewer = make_user(role="client_readonly", username="viewer")
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO user_clients (user_id, client_id) VALUES (:u, :c)"), {"u": viewer["id"], "c": cid})
    await full_login(client, viewer)
    before = datetime.now(UTC)
    r = await client.get("/vpn?range=24h&kind=all")
    after = datetime.now(UTC)
    assert r.status_code == 200
    # Up T0..T0+50m and T0+60m..now; down T0+50m..T0+60m (10 min). Hand calculation with the real clock:
    def pct_at(now):
        up = 50 * 60 + (now - (T0 + timedelta(minutes=60))).total_seconds()
        return up / (up + 600) * 100
    pct = float(re.search(r"<strong>([\d.]+) %</strong>", r.text).group(1))
    assert round(pct_at(before), 2) - 0.01 <= pct <= round(pct_at(after), 2) + 0.01
    assert "▲ up" in r.text and "85.217.149.17" in r.text and "10m" in r.text



async def test_ipsec_only_by_default_and_rename(client, make_user, owner_engine, dev):
    cid, did = dev
    with owner_engine.begin() as c:
        ev(c, cid, did, 0, "link-up", iface="tun0")
        ev(c, cid, did, 1, "vpn-tunnel-up", iface="IPsec 11.229.44.205")
    await run(VpnTracker(get_settings()))
    await full_login(client, make_user(role="engineer", username="eng"))
    page = (await client.get("/vpn?range=24h")).text
    assert "IPsec 11.229.44.205" in page and "tun0" not in page
    assert "tun0" in (await client.get("/vpn?range=24h&kind=all")).text
    token = csrf_from(page)
    r = await client.post("/vpn/tunnels/name", data={"device_id": str(did), "tunnel_name": "IPsec 11.229.44.205",
                                                      "display_name": "CTS KL <-> HQ", "csrf_token": token})
    assert r.status_code == 303
    page = (await client.get("/vpn?range=24h")).text
    assert "<strong>CTS KL &lt;-&gt; HQ</strong>" in page and "IPsec 11.229.44.205" in page   # technical name kept below
    await client.post("/vpn/tunnels/name", data={"device_id": str(did), "tunnel_name": "IPsec 11.229.44.205",
                                                 "display_name": "", "csrf_token": token})
    assert "CTS KL &lt;-&gt; HQ" not in (await client.get("/vpn?range=24h")).text


async def test_client_user_cannot_rename(client, make_user, owner_engine, dev):
    cid, did = dev
    viewer = make_user(role="client_readonly", username="viewer2")
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO user_clients (user_id, client_id) VALUES (:u, :c)"), {"u": viewer["id"], "c": cid})
    await full_login(client, viewer)
    token = csrf_from((await client.get("/vpn")).text)
    r = await client.post("/vpn/tunnels/name", data={"device_id": str(did), "tunnel_name": "x", "display_name": "y",
                                                     "csrf_token": token})
    assert r.status_code == 403


def test_person_name_without_device_suffix():
    from app.web.deps import person
    assert person("Grace Lee's Desktop") == "Grace Lee"
    assert person("Kevin Henry Tan's Desktop") == "Kevin Henry Tan"
    assert person("vt_aeva") == "vt_aeva" and person(None) == "" and person("St James's Park") == "St James's Park"



async def test_users_summary_and_per_user_sessions(client, make_user, owner_engine, dev):
    cid, did = dev
    now = datetime.now(UTC)
    with owner_engine.begin() as c:
        for user, start, end in (("Grace Lee's Desktop", 30, 20), ("Grace Lee's Desktop", 10, None), ("Jack Yeo's Desktop", 50, 45)):
            c.execute(text("""INSERT INTO vpn_sessions (client_id, device_id, user_name, source_ip, started_at, ended_at, last_seen_at,
                              status, bytes_in, bytes_out) VALUES (:c, :d, :u, '11.38.150.78', :s, :e, coalesce(:e, now()), :st, 1048576, 2048)"""),
                      {"c": cid, "d": did, "u": user, "s": now - timedelta(minutes=start),
                       "e": now - timedelta(minutes=end) if end else None, "st": "closed" if end else "open"})
    await full_login(client, make_user(role="engineer", username="eng3"))
    page = (await client.get("/vpn?range=24h")).text
    assert "Remote-access users" in page and "● 1 open" in page
    assert page.index(">Grace Lee</a>") < page.index(">Jack Yeo</a>")             # users with an open session first
    one = (await client.get("/vpn?range=24h&user=Grace+Lee%27s+Desktop")).text
    sessions = one[one.index('id="sessions"'):]
    assert "Sessions of Grace Lee" in sessions and "Jack Yeo" not in sessions and sessions.count("<tr><td") == 2
    assert "2.0 MB / 4.0 KB" in one                                                  # per-user data totals


async def test_user_traffic_during_sessions(client, make_user, owner_engine, dev):
    """Clicking a remote-access user shows the flows of the VPN address their session was given, only while connected."""
    cid, did = dev
    now = datetime.now(UTC)
    with owner_engine.begin() as c:
        c.execute(text("""INSERT INTO vpn_sessions (client_id, device_id, user_name, source_ip, assigned_ip, started_at, last_seen_at, status)
                          VALUES (:c, :d, 'Grace Lee''s Desktop', '11.38.150.78', '192.168.11.13', :s, now(), 'open')"""),
                  {"c": cid, "d": did, "s": now - timedelta(minutes=30)})
        for minutes, src, dst, name, b in ((5, "192.168.11.13", "52.97.1.1", "outlook.office365.com", 900000),
                                          (6, "192.168.11.13", "142.250.1.1", "www.google.com", 1200),
                                          (50, "192.168.11.13", "203.0.113.66", "before.example", 5),     # before she connected
                                          (4, "192.168.11.99", "198.51.100.7", "someone-else.example", 5)):
            c.execute(text("""INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class, action,
                              src_ip, src_port, dst_ip, dst_port, protocol, bytes_in, message, extra)
                              VALUES (:t, :c, :d, 0, :t, 'unifi', 'traffic', 'low', 'unifi:flow', 'flow', :s, 50000, :dst, 443, 'tcp', :b,
                                      'flow', CAST(:x AS jsonb))"""),
                      {"t": now - timedelta(minutes=minutes), "c": cid, "d": did, "s": src, "dst": dst, "b": b,
                       "x": json.dumps({"fqdn": name, "direction": "outgoing"})})
    await full_login(client, make_user(role="engineer", username="eng4"))
    page = (await client.get("/vpn?range=24h&user=Grace+Lee%27s+Desktop")).text
    traffic = page[page.index('id="traffic"'):]
    assert "connected now" in traffic and "192.168.11.13" in traffic
    assert traffic.index("outlook.office365.com") < traffic.index("www.google.com")   # top destinations by data
    assert "before.example" not in traffic and "someone-else.example" not in traffic
    assert "ip%3D192.168.11.13" in traffic                                            # live view in Log View
    other = (await client.get("/vpn?range=24h")).text
    assert 'id="traffic"' not in other                                                # only for a selected user
