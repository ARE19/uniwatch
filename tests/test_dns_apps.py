"""DNS-based website/app visibility: classification, forwarder parser (real lines), Insights/IP/dashboard views."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from app.intel.apps import classify
from app.parsers.vendors import module_for
from tests.conftest import full_login

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "coredns-forwarder-2026-10-07.log"
NOW = datetime(2026, 10, 6, 16, 0, tzinfo=UTC)
fwd = module_for("dns")


@pytest.mark.parametrize("name,expected", [
    ("www.youtube.com.", ("youtube.com", "YouTube", "Video streaming")),
    ("rr3---sn-i3belney.googlevideo.com", ("googlevideo.com", "YouTube", "Video streaming")),
    ("teams.microsoft.com", ("microsoft.com", "Microsoft Teams", "Collaboration")),
    ("mail.google.com", ("google.com", "Gmail", "Google Workspace")),
    ("www.google.com", ("google.com", "Google Search", "Search")),
    ("mmx-ds.cdn.whatsapp.net", ("whatsapp.net", "WhatsApp", "Messaging")),
    ("abc.sharepoint.com", ("sharepoint.com", "SharePoint / OneDrive", "Microsoft 365")),
    ("news.bbc.co.uk", ("bbc.co.uk", "BBC", "News")),
    ("shop.example.com.hk", ("example.com.hk", None, None)),
    ("nw-hk.localdomain", (None, None, None)),
    ("8.8.8.8.in-addr.arpa", (None, None, None)),
    ("printer", (None, None, None)),
])
def test_classify(name, expected):
    assert classify(name) == expected


def lines():
    return [l for l in SAMPLE.read_text(encoding="utf-8").splitlines() if l.strip()]


def test_every_forwarder_sample_parses():
    evs = [fwd.parse(l, "Asia/Hong_Kong", NOW) for l in lines()]
    queries = [e for e in evs if e.action == "dns-query"]
    assert len(queries) == 10 and all(e.ts.tzinfo for e in evs)
    assert {e.category for e in evs if e.action != "dns-query"} == {"system"}   # startup lines


def test_query_fields_from_real_line():
    line = next(l for l in lines() if "udp A www.youtube.com." in l)
    ev = fwd.parse(line, "Asia/Hong_Kong", NOW)
    assert (ev.category, ev.action, ev.src_ip, ev.src_port, ev.protocol, ev.rule, ev.outcome) == (
        "dns", "dns-query", "192.168.1.50", 46158, "udp", "YouTube", "success")
    assert ev.ts == datetime(2026, 10, 6, 15, 38, 18, 693202, tzinfo=UTC)          # RFC 5424 UTC timestamp, not shifted
    assert ev.extra["domain"] == "youtube.com" and ev.extra["app_category"] == "Video streaming" and ev.extra["qtype"] == "A"
    assert ev.message == "www.youtube.com (YouTube) A NOERROR"
    nx = fwd.parse(next(l for l in lines() if "NXDOMAIN" in l), "UTC", NOW)
    assert nx.outcome is None and nx.extra["rcode"] == "NXDOMAIN"
    local = fwd.parse(next(l for l in lines() if "nw-hk.localdomain" in l), "UTC", NOW)
    assert local.rule is None and local.extra["local"] is True and "domain" not in local.extra


@pytest.fixture
def lookups(owner_engine):
    with owner_engine.begin() as c:
        cid = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Northwind HK','nwhk') RETURNING id")).scalar()
        did = c.execute(text("INSERT INTO devices (client_id, name, vendor, syslog_source_ip) VALUES (:c, 'DNS forwarder', 'dns', '127.0.0.1') RETURNING id"),
                        {"c": cid}).scalar()
        now = datetime.now(UTC)
        for ip, app, domain, n in (("192.168.1.27", "YouTube", "googlevideo.com", 5), ("192.168.1.27", "Microsoft Teams", "microsoft.com", 2),
                                   ("192.168.1.54", "YouTube", "youtube.com", 1), ("192.168.1.54", None, "example.org", 3)):
            for i in range(n):
                c.execute(text("""INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class,
                                  action, rule, src_ip, message, extra) VALUES (:t, :c, :d, 0, :t, 'dns', 'dns', 'low', 'syslog:coredns',
                                  'dns-query', :app, :ip, :m, CAST(:x AS jsonb))"""),
                          {"t": now - timedelta(minutes=5 + i), "c": cid, "d": did, "app": app, "ip": ip, "m": f"q {domain}",
                           "x": '{"domain": "%s"}' % domain})
        c.execute(text("INSERT INTO network_clients (client_id, device_id, mac, ip_internal, hostname, first_seen, last_seen) "
                       "VALUES (:c, :d, '00:00:00:f9:a6:2b', '192.168.1.27', 'Alex-Laptop', now(), now())"), {"c": cid, "d": did})
    return cid


async def test_insights_websites_and_apps(client, make_user, lookups):
    await full_login(client, make_user(role="engineer"))
    page = (await client.get("/insights?view=web&range=24h")).text
    assert page.index("YouTube") < page.index("Microsoft Teams")              # 6 lookups beat 2
    assert "Video streaming" in page and "example.org" in page and "Alex-Laptop" in page
    dev = (await client.get("/insights?view=web&range=24h&ip=192.168.1.54")).text
    assert "example.org" in dev and "Microsoft Teams" not in dev and "device 192.168.1.54" in dev
    ip_page = (await client.get("/ip/192.168.1.27")).text
    assert "Websites &amp; apps" in ip_page and "YouTube" in ip_page
    d = (await client.get("/api/dashboard?range=24h")).json()
    assert d["apps"][0] == {"app": "YouTube", "n": 6, "bytes": 0, "flow": False, "category": "Video streaming"}
