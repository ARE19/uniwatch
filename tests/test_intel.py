"""Phase 13: feed parsing (real formats), refresh, IoC matching -> ids event -> alert; lookup UI."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from app.alerts.engine import AlertEngine
from app.intel import feeds as intel
from tests.conftest import full_login
from tests.test_alerts import Outbox, env, only  # noqa: F401
from tests.test_logview import _add

# Real excerpts of each feed (fetched 2026-10-06), headers included.
FEODO = """################################################################
# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (IPs only)     #
# Last updated: 2026-03-04 14:28:39 UTC                        #
162.243.103.246
178.62.3.223
"""
URLHAUS = """# abuse.ch URLhaus Host file
127.0.0.1\t123.ywxww.net
127.0.0.1\t1717.1000uc.com
127.0.0.1\tnot a domain
"""
SPAMHAUS = """{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"85.217.149.0/24","sblid":"SBLTEST","rir":"ripencc"}
{"type":"metadata","timestamp":1791200000,"size":2,"records":2,"copyright":"(c) 2026 The Spamhaus Project SLU"}
"""


def test_parse_real_formats():
    assert intel.parse("ip_list", FEODO) == (["162.243.103.246/32", "178.62.3.223/32"], [])
    assert intel.parse("hostfile", URLHAUS) == ([], ["123.ywxww.net", "1717.1000uc.com"])
    assert intel.parse("spamhaus_json", SPAMHAUS) == (["1.10.16.0/20", "85.217.149.0/24"], [])


async def fake_fetch(url):
    return {"feodo": FEODO, "urlhaus": URLHAUS, "spamhaus": SPAMHAUS}[url.split("/")[2].split(".")[0]]


async def _feeds(owner_engine):
    with owner_engine.begin() as c:
        c.execute(text("DELETE FROM ioc_feeds"))
        for name, url, fmt in (("Feodo", "https://feodo.test/x", "ip_list"), ("URLhaus", "https://urlhaus.test/x", "hostfile"),
                               ("Spamhaus DROP", "https://spamhaus.test/x", "spamhaus_json")):
            c.execute(text("INSERT INTO ioc_feeds (name, url, format) VALUES (:n, :u, :f)"), {"n": name, "u": url, "f": fmt})
    return await intel.refresh(fetch=fake_fetch)


async def test_refresh_and_failed_feed_keeps_old_indicators(owner_engine):
    res = await _feeds(owner_engine)
    assert res == {"Feodo": 2, "URLhaus": 2, "Spamhaus DROP": 2}

    async def broken(url):
        return "<html>maintenance</html>"
    await intel.refresh(fetch=broken)
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM ioc_networks")).scalar() == 4
        assert c.execute(text("SELECT count(*) FROM ioc_feeds WHERE last_error LIKE '%no indicators%'")).scalar() == 3


async def test_match_raises_ioc_event_and_single_alert(owner_engine, env):
    cid, gw = env
    await _feeds(owner_engine)
    old = datetime.now(UTC) - timedelta(minutes=5)
    with owner_engine.begin() as c:
        for _ in range(3):  # three TLS errors from an address inside a Spamhaus DROP block
            e = _add(c, cid, gw, category="vpn", src="85.217.149.17", action="vpn-tls-error")
        _add(c, cid, gw, category="dns", src="192.168.1.27", action="dns-block", extra='{"domain": "123.ywxww.net"}')
        _add(c, cid, gw, category="vpn", src="8.8.8.8", action="vpn-tcp-connect")      # not listed
        c.execute(text("UPDATE events SET raw_ts = :o"), {"o": old})                      # settled
    assert await intel.match_new_events() == 4
    assert await intel.match_new_events() == 0                                            # cursor: no double matching
    with owner_engine.connect() as c:
        rows = c.execute(text("SELECT extra->>'value', category, severity, rule FROM events WHERE action = 'ioc-match' ORDER BY id")).all()
    assert [r[0] for r in rows] == ["85.217.149.17"] * 3 + ["123.ywxww.net"]
    assert {(r[1], r[2]) for r in rows} == {("ids", "high")} and rows[0][3] == "Spamhaus DROP"
    only(owner_engine, "ioc_match")
    with owner_engine.begin() as c:   # the alert cursor starts at the latest match of the last day on first run
        c.execute(text("INSERT INTO tracker_cursors (name, last_event_id) SELECT 'alerts:ioc:' || id, 1 FROM alert_rules WHERE rule_type = 'ioc_match'"))
    out = Outbox()
    await AlertEngine(deliver_fn=out).evaluate()
    await AlertEngine(deliver_fn=out).evaluate()
    assert sorted(t for _, t in out.sent) == ["Traffic with known-bad address 123.ywxww.net",
                                             "Traffic with known-bad address 85.217.149.17"]


async def test_unsettled_events_wait(owner_engine, env):
    cid, gw = env
    await _feeds(owner_engine)
    with owner_engine.begin() as c:
        _add(c, cid, gw, category="vpn", src="85.217.149.17", action="vpn-tls-error")
        c.execute(text("UPDATE events SET raw_ts = now()"))
    assert await intel.match_new_events() == 0   # too fresh: retried on the next run


async def test_threat_intel_page_lookup(client, make_user, owner_engine, env):
    await _feeds(owner_engine)
    await full_login(client, make_user(role="engineer"))
    r = await client.get("/threat-intel?q=85.217.149.17")
    assert r.status_code == 200 and "Listed by 1 feed" in r.text and "85.217.149.0/24" in r.text
    assert "Not on any loaded threat list" in (await client.get("/threat-intel?q=example.com")).text
    assert "Spamhaus DROP" in r.text


async def test_old_matches_do_not_alert(owner_engine, env):
    """Hits older than the rule's max age (default 24 h, e.g. from an imported history) stay out of the alerts."""
    cid, gw = env
    only(owner_engine, "ioc_match")
    with owner_engine.begin() as c:
        _add(c, cid, gw, category="system", src="192.168.1.1", action="filler")       # id 1: the cursor starts after it
        c.execute(text("INSERT INTO tracker_cursors (name, last_event_id) SELECT 'alerts:ioc:' || id, 1 FROM alert_rules WHERE rule_type = 'ioc_match' "
                       "ON CONFLICT (name) DO UPDATE SET last_event_id = 1"))
        for ago, ip in ((timedelta(days=3), "203.0.113.9"), (timedelta(hours=1), "203.0.113.10")):
            c.execute(text("""INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class, action,
                              message, extra) VALUES (:t, :c, :d, 0, :t, 'unifi', 'ids', 'high', 'intel', 'ioc-match', 'hit',
                              CAST(:x AS jsonb))"""),
                      {"t": datetime.now(UTC) - ago, "c": cid, "d": gw, "x": '{"value": "%s", "feeds": ["CINS"]}' % ip})
    out = Outbox()
    await AlertEngine(deliver_fn=out).evaluate()
    assert [t for _, t in out.sent] == ["Traffic with known-bad address 203.0.113.10"]


async def test_inbound_scanner_probes_do_not_alert(owner_engine, env):
    """A listed address probing the WAN (an inbound flow with no data) is recorded but not alerted; an inbound session that
    moved data, or an internal host talking to a listed address, is."""
    cid, gw = env
    await _feeds(owner_engine)
    with owner_engine.begin() as c:
        _add(c, cid, gw, category="system", src="192.168.1.1", action="filler")
        c.execute(text("INSERT INTO tracker_cursors (name, last_event_id) SELECT 'alerts:ioc:' || id, 1 FROM alert_rules WHERE rule_type = 'ioc_match' "
                       "ON CONFLICT (name) DO UPDATE SET last_event_id = 1"))
        for src, dst, direction, b in (("85.217.149.17", "203.0.113.1", "incoming", 120),           # scanner probe
                                       ("85.217.149.18", "192.168.1.20", "incoming", 900000),       # real inbound session
                                       ("192.168.1.27", "85.217.149.19", "outgoing", 300)):         # internal host -> bad IP
            c.execute(text("""INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class, action,
                              src_ip, dst_ip, bytes_in, message, extra)
                              VALUES (now() - interval '5 minutes', :c, :d, 0, now() - interval '5 minutes', 'unifi', 'traffic', 'low',
                                      'unifi:flow', 'flow', :s, :t, :b, 'flow', CAST(:x AS jsonb))"""),
                      {"c": cid, "d": gw, "s": src, "t": dst, "b": b, "x": '{"direction": "%s"}' % direction})
    only(owner_engine, "ioc_match")
    assert await intel.match_new_events() == 3
    out = Outbox()
    await AlertEngine(deliver_fn=out).evaluate()
    assert sorted(t for _, t in out.sent) == ["Traffic with known-bad address 85.217.149.18",
                                             "Traffic with known-bad address 85.217.149.19"]
