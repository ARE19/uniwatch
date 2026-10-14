"""Phase 4: Log View search, drill-down, export, saved searches, live tail, config changes, IP details."""

import asyncio
import csv
import io
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from starlette.datastructures import MultiDict

from app.web import routes_logs
from app.web.logquery import LogQuery
from tests.conftest import csrf_from, full_login

NOW = datetime.now(UTC)


def _add(c, cid, did, *, minutes_ago=1, category="system", severity="low", src=None, dst=None, user=None,
         message="hello", action=None, raw="<13>raw line", extra="{}"):
    ts = NOW - timedelta(minutes=minutes_ago)
    rid = c.execute(text("INSERT INTO raw_logs (ts_received, client_id, device_id, source_ip, transport, raw, parsed) "
                         "VALUES (:t, :c, :d, '10.0.0.1', 'udp', :raw, true) RETURNING id"),
                    {"t": ts, "c": cid, "d": did, "raw": raw}).scalar()
    return c.execute(text("""
        INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class, action,
                            src_ip, dst_ip, user_name, message, extra)
        VALUES (:t, :c, :d, :r, :t, 'unifi', :cat, :sev, 'syslog:x', :act, :src, :dst, :u, :m, CAST(:extra AS jsonb))
        RETURNING id"""), {"t": ts, "c": cid, "d": did, "r": rid, "cat": category, "sev": severity, "act": action,
                           "src": src, "dst": dst, "u": user, "m": message, "extra": extra}).scalar()


@pytest.fixture
def two_clients(owner_engine):
    with owner_engine.begin() as c:
        out = {}
        for slug, ip in (("acme", "10.0.0.1"), ("globex", "10.0.0.2")):
            cid = c.execute(text("INSERT INTO clients (name, slug) VALUES (:n, :s) RETURNING id"), {"n": slug.title(), "s": slug}).scalar()
            did = c.execute(text("INSERT INTO devices (client_id, name, vendor, syslog_source_ip) VALUES (:c, :n, 'unifi', :ip) RETURNING id"),
                            {"c": cid, "n": f"{slug}-gw", "ip": ip}).scalar()
            out[slug] = (cid, did)
        a, g = out["acme"], out["globex"]
        _add(c, *a, category="vpn", severity="high", src="85.217.149.17", action="vpn-tls-error", message="TLS Error: cannot locate HMAC",
             raw="<27>Oct  6 13:35:18 NW-HK NW-HK openvpn[3586]: TLS Error")
        _add(c, *a, category="dhcp", src="192.168.1.60", action="dhcp-ack", message="DHCPACK(br0) 192.168.1.60",
             extra='{"hostname": "SIP-T55A"}')
        _add(c, *a, category="auth", user="Unifi Owner", message="=cmd|' /C calc'!A0", action="admin-access")
        _add(c, *g, category="vpn", severity="high", src="85.217.149.17", message="globex secret event")
        c.execute(text("INSERT INTO config_changes (ts, client_id, device_id, raw_id, raw_ts, admin_user, source_ip, action, summary) "
                       "VALUES (now(), :c, :d, 1, now(), 'Unifi Owner', '11.26.85.18', 'modify', 'System / rsyslogd: port: 514')"),
                  {"c": a[0], "d": a[1]})
    return out


async def _staff(client, make_user, role="engineer"):
    await full_login(client, make_user(role=role, username=f"{role}-user"))


async def test_search_and_filters(client, make_user, two_clients):
    await _staff(client, make_user)
    r = await client.get("/logs?range=1h")
    assert r.status_code == 200 and "TLS Error: cannot locate HMAC" in r.text and "globex secret event" in r.text
    assert "SIP-T55A" not in r.text  # extra fields only in the details pane
    r = await client.get("/logs?range=1h&category=vpn&severity=high")
    assert "TLS Error" in r.text and "DHCPACK" not in r.text
    r = await client.get("/logs?range=1h&ip=85.217.149.0/24")
    assert "TLS Error" in r.text and "DHCPACK" not in r.text
    r = await client.get("/logs?range=1h&user=owner")
    assert "admin-access" in r.text and "TLS Error" not in r.text
    r = await client.get("/logs?range=1h&q=hmac")
    assert "TLS Error" in r.text and "DHCPACK" not in r.text
    r = await client.get(f"/logs?range=1h&device={two_clients['globex'][1]}")
    assert "globex secret event" in r.text and "TLS Error" not in r.text
    r = await client.get("/logs?range=1h&ip=not-an-ip")
    assert "is not an IP address" in r.text


async def test_raw_view_and_details_pane(client, make_user, two_clients):
    await _staff(client, make_user)
    r = await client.get("/logs?range=1h&view=raw&action=vpn-tls-error")
    assert "openvpn[3586]: TLS Error" in r.text
    event_id = r.text.split('hx-get="/logs/event/')[1].split("?")[0]
    d = await client.get(f"/logs/event/{event_id}")
    assert d.status_code == 200 and "Original log line" in d.text and "openvpn[3586]" in d.text


async def test_scope_isolation_in_search_and_details(client, make_user, owner_engine, two_clients):
    await _staff(client, make_user)
    token = csrf_from((await client.get("/")).text)
    await client.post("/scope", data={"client": str(two_clients["acme"][0]), "csrf_token": token})
    r = await client.get("/logs?range=1h")
    assert "globex secret event" not in r.text and "TLS Error" in r.text
    with owner_engine.connect() as c:
        gid = c.execute(text("SELECT id FROM events WHERE message = 'globex secret event'")).scalar()
    assert (await client.get(f"/logs/event/{gid}")).status_code == 404
    assert "globex secret event" not in (await client.get("/logs/export.csv?range=1h")).text


async def test_paging(client, make_user, owner_engine, two_clients):
    cid, did = two_clients["acme"]
    with owner_engine.begin() as c:
        for i in range(130):
            _add(c, cid, did, minutes_ago=2 + i * 0.1, message=f"bulk {i:03d}")
    await _staff(client, make_user)
    r = await client.get("/logs?range=1h&q=bulk")
    assert r.text.count('class="logrow"') == 100 and "Load older events" in r.text
    more_url = r.text.split('hx-get="/logs/rows?')[1].split('"')[0].replace("&amp;", "&")
    r2 = await client.get("/logs/rows?" + more_url)
    assert r2.text.count('class="logrow"') == 30 and "Load older events" not in r2.text
    assert "bulk 129" in r2.text and "bulk 000" not in r2.text


async def test_csv_export(client, make_user, two_clients, audit_rows):
    await _staff(client, make_user)
    r = await client.get("/logs/export.csv?range=1h")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == 4
    risky = next(x for x in rows if x["category"] == "auth")
    assert risky["message"].startswith("'=")  # formula injection neutralised
    assert audit_rows("log_export")


async def test_saved_searches(client, make_user, two_clients):
    await _staff(client, make_user)
    token = csrf_from((await client.get("/logs")).text)
    r = await client.post("/logs/saved", data={"name": "VPN failures", "query": "range=24h&category=vpn&bogus=1",
                                               "shared": "true", "csrf_token": token})
    assert r.status_code == 303 and "bogus" not in r.headers["location"]
    page = (await client.get("/logs")).text
    assert "VPN failures" in page and "category=vpn" in page
    sid = page.split('action="/logs/saved/')[1].split("/")[0]
    assert (await client.post(f"/logs/saved/{sid}/delete", data={"csrf_token": token})).status_code == 303
    assert "VPN failures" not in (await client.get("/logs")).text


async def test_live_tail_streams_new_events(client, make_user, owner_engine, two_clients, monkeypatch):
    monkeypatch.setattr(routes_logs, "TAIL_SECONDS", 3)
    await _staff(client, make_user)
    cid, did = two_clients["acme"]

    async def add_later():
        await asyncio.sleep(1)
        with owner_engine.begin() as c:
            _add(c, cid, did, minutes_ago=0, message="brand new live event")

    task = asyncio.create_task(add_later())
    r = await client.get("/logs/tail?range=1h")
    await task
    assert r.headers["content-type"].startswith("text/event-stream")
    assert "event: rows" in r.text and "brand new live event" in r.text
    assert "TLS Error" not in r.text  # only events newer than the tail start


async def test_config_change_view(client, make_user, two_clients):
    await _staff(client, make_user)
    r = await client.get("/logs/config-changes")
    assert r.status_code == 200 and "System / rsyslogd: port: 514" in r.text and "Unifi Owner" in r.text


async def test_ip_details(client, make_user, two_clients):
    await _staff(client, make_user)
    r = await client.get("/ip/192.168.1.60")
    assert r.status_code == 200 and "Internal" in r.text and "SIP-T55A" in r.text
    r = await client.get("/ip/85.217.149.17")
    assert "External" in r.text and "TLS Error" in r.text
    assert (await client.get("/ip/nope")).status_code == 400


async def test_client_readonly_has_no_log_view(client, make_user, two_clients):
    await full_login(client, make_user(role="client_readonly", username="viewer"))
    for url in ("/logs", "/logs/export.csv", "/logs/config-changes", "/ip/192.168.1.60", "/logs/tail"):
        assert (await client.get(url)).status_code == 403, url


def test_logquery_custom_range_uses_client_timezone():
    lq = LogQuery.from_params(MultiDict([("from", "2026-10-06T16:00:00"), ("to", "2026-10-06T17:00:00")]), "Asia/Hong_Kong")
    assert lq.range == "custom" and lq.since == datetime(2026, 10, 6, 8, 0, tzinfo=UTC)
    assert lq.until == datetime(2026, 10, 6, 9, 0, tzinfo=UTC)
    assert "from=2026-10-06T16%3A00%3A00" in lq.qs()


def test_logquery_ignores_unknown_values():
    lq = LogQuery.from_params(MultiDict([("category", "vpn"), ("category", "evil'); drop"), ("severity", "nope"),
                                         ("device", "x1"), ("range", "99y")]), "UTC")
    assert lq.categories == ["vpn"] and lq.severities == [] and lq.devices == [] and lq.range == "1h"
