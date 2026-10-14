"""Phase 14: forwarding (CEF/JSON/raw over real UDP and TCP sockets), retention enforcement, quota usage + alert."""

import asyncio
import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from app import forwarder as fw
from app.alerts.engine import AlertEngine
from app.parsers.cef import parse_cef
from tests.conftest import csrf_from, full_login
from tests.test_alerts import Outbox, env, only  # noqa: F401
from tests.test_logview import _add


def test_cef_output_escaping_roundtrips_through_our_own_parser():
    ev = {"ts": datetime(2026, 10, 6, 8, 0, tzinfo=UTC), "severity": "high", "event_class": "cef:200",
          "event_name": "Threat | Detected", "action": "ids-detect", "category": "ids", "outcome": "allowed",
          "src_ip": "85.217.149.17", "src_port": 4444, "dst_ip": "192.168.1.50", "dst_port": 22, "protocol": "tcp",
          "user_name": None, "rule": "ET SCAN a=b", "message": "line1\nline2 with = sign", "device": "NW-HK",
          "client": "nwhk", "src_country": "BG", "dst_country": None, "interface": None}
    rec = parse_cef(fw.to_cef(ev))
    assert rec.vendor == "Example MSP" and rec.name == "Threat | Detected" and rec.severity == "8"
    assert rec.ext["src"] == "85.217.149.17" and rec.ext["dpt"] == "22" and rec.ext["cs2"] == "ET SCAN a=b"
    assert rec.ext["msg"] == "line1\nline2 with = sign" and rec.ext["cs3"] == "BG" and "cs4" not in rec.ext
    assert rec.ext["rt"] == str(int(ev["ts"].timestamp() * 1000))


def test_syslog_wrap():
    line = fw.syslog_wrap("hello", datetime(2026, 10, 6, 8, 0, 0, 123000, tzinfo=UTC), "NW HK", "critical")
    assert line == "<130>1 2026-10-06T08:00:00.123Z NW_HK uniwatch - - - hello"


class Listener:
    def __init__(self):
        self.lines = []

    async def start(self, proto):
        loop = asyncio.get_running_loop()
        if proto == "udp":
            outer = self

            class P(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    outer.lines.append(data.decode())
            self.t, _ = await loop.create_datagram_endpoint(P, local_addr=("127.0.0.1", 0))
            return self.t.get_extra_info("sockname")[1]

        async def handle(reader, writer):
            while line := await reader.readline():
                self.lines.append(line.decode().rstrip("\n"))
        self.srv = await asyncio.start_server(handle, "127.0.0.1", 0)
        return self.srv.sockets[0].getsockname()[1]

    async def wait(self, n, timeout=5):
        for _ in range(int(timeout * 20)):
            if len(self.lines) >= n:
                return
            await asyncio.sleep(0.05)


@pytest.mark.parametrize("proto,fmt", [("udp", "cef"), ("tcp", "json"), ("tcp", "raw")])
async def test_forwarding_end_to_end(owner_engine, env, proto, fmt):
    cid, gw = env
    lis = Listener()
    port = await lis.start(proto)
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO forwarding_targets (name, host, port, protocol, format, min_severity) VALUES ('t', '127.0.0.1', :p, :pr, :f, 'medium')"),
                  {"p": port, "pr": proto, "f": fmt})
        _add(c, cid, gw, severity="high", message="before the target existed")
    f = fw.Forwarder()
    assert await f.run_once() == {"t": 0}          # first run only positions the cursor at "now"
    with owner_engine.begin() as c:
        _add(c, cid, gw, severity="high", category="vpn", src="85.217.149.17", message="forward me", raw="<27>Oct  6 13:35:18 NW-HK NW-HK openvpn[3586]: forward me raw")
        _add(c, cid, gw, severity="low", message="too low for the filter", raw="<14>low raw line")
    res = await f.run_once()
    await lis.wait(1 if fmt != "raw" else 2)
    joined = "\n".join(lis.lines)
    assert "before the target existed" not in joined
    if fmt == "cef":
        assert res == {"t": 1} and "CEF:0|Example MSP|Uniwatch|1.0|syslog:x|" in joined and "msg=forward me" in joined
        assert "too low" not in joined
    elif fmt == "json":
        body = json.loads(lis.lines[0].split(" - - - ", 1)[1])
        assert res == {"t": 1} and body["message"] == "forward me" and body["src_ip"] == "85.217.149.17" and body["client"] == "nwhk"
    else:  # raw ignores the severity filter and sends the original line verbatim
        assert res == {"t": 2} and "openvpn[3586]: forward me raw" in joined and "<14>low raw line" in joined
    assert await f.run_once() == {"t": 0}          # cursor advanced: nothing resent


async def test_forwarding_failure_keeps_cursor(owner_engine, env):
    cid, gw = env
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO forwarding_targets (name, host, port, protocol, format, cursor_id) VALUES ('down', '127.0.0.1', 1, 'tcp', 'cef', 1)"))
        _add(c, cid, gw, severity="high")   # id 1 (== cursor)
        _add(c, cid, gw, severity="high")   # id 2: pending
    res = await fw.Forwarder().run_once()
    assert "ConnectionRefused" in res["down"] or "Errno" in res["down"]
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT cursor_id, last_error IS NOT NULL FROM forwarding_targets")).one() == (1, True)


async def test_retention_deletes_per_client(owner_engine, env):
    cid, gw = env
    with owner_engine.begin() as c:
        other = c.execute(text("INSERT INTO clients (name, slug, retention_days) VALUES ('Other','other', 365) RETURNING id")).scalar()
        od = c.execute(text("INSERT INTO devices (client_id, name, vendor) VALUES (:c,'og','unifi') RETURNING id"), {"c": other}).scalar()
        c.execute(text("UPDATE clients SET retention_days = 30 WHERE id = :c"), {"c": cid})
        for client, dev in ((cid, gw), (other, od)):
            for age in (40, 10):
                rid = c.execute(text("INSERT INTO raw_logs (ts_received, client_id, device_id, source_ip, transport, raw) "
                                     "VALUES (now() - make_interval(days => :a), :c, :d, '10.0.0.1', 'udp', 'x') RETURNING id"),
                                {"a": age, "c": client, "d": dev}).scalar()
                c.execute(text("INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class) "
                               "VALUES (now() - make_interval(days => :a), :c, :d, :r, now(), 'unifi', 'system', 'low', 'x')"),
                          {"a": age, "c": client, "d": dev, "r": rid})
    res = {r["client_id"]: r for r in await fw.apply_retention()}
    assert (res[cid]["raw_deleted"], res[cid]["events_deleted"]) == (1, 1)
    assert (res[other]["raw_deleted"], res[other]["events_deleted"]) == (0, 0)   # 365-day retention keeps its 40-day-old data
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM raw_logs")).scalar() == 3


async def test_quota_usage_and_alert(owner_engine, env):
    cid, gw = env
    with owner_engine.begin() as c:
        for i in range(50):
            _add(c, cid, gw, raw="x" * 2000)
        c.execute(text("UPDATE clients SET quota_gb = 0.0000001 WHERE id = :c"), {"c": cid})   # ~107 bytes: far exceeded
    from app import db
    async with db.sessionmaker()() as s:
        usage = await fw.storage_usage(s)
    assert usage[0]["lines"] == 50 and usage[0]["used_pct"] > 100
    only(owner_engine, "storage_quota")
    out = Outbox()
    await AlertEngine(deliver_fn=out).evaluate()
    await AlertEngine(deliver_fn=out).evaluate()
    assert len(out.sent) == 1 and "storage quota" in out.sent[0][1]


async def test_storage_page_admin_only(client, make_user, owner_engine, env):
    cid, gw = env
    await full_login(client, make_user(role="admin", username="root-admin"))
    page = await client.get("/admin/storage")
    assert page.status_code == 200 and "Northwind HK" in page.text
    token = csrf_from(page.text)
    r = await client.post(f"/admin/storage/clients/{cid}", data={"retention_days": "180", "quota_gb": "50", "csrf_token": token})
    assert r.status_code == 303
    assert (await client.post("/admin/storage/forwarding", data={"name": "x", "host": "bad host!", "port": "514", "csrf_token": token})).status_code == 400
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT retention_days, quota_gb FROM clients WHERE id = :c"), {"c": cid}).one() == (180, 50.0)
    await full_login(client, make_user(role="engineer", username="eng"))
    assert (await client.get("/admin/storage")).status_code == 403


async def test_retention_drops_whole_old_chunks(owner_engine, env):
    """Data older than the longest retention goes by dropping whole chunks (also empty ones); nothing newer is touched."""
    cid, gw = env
    with owner_engine.begin() as c:
        c.execute(text("UPDATE clients SET retention_days = 90"))
        for age in (400, 200, 95, 10):
            c.execute(text("INSERT INTO raw_logs (ts_received, client_id, device_id, source_ip, transport, raw) "
                           "VALUES (now() - make_interval(days => :a), :c, :d, '10.0.0.1', 'udp', 'x')"), {"a": age, "c": cid, "d": gw})
        c.execute(text("DELETE FROM raw_logs WHERE ts_received < now() - interval '300 days'"))     # leaves an empty chunk behind
        before = c.execute(text("SELECT count(*) FROM timescaledb_information.chunks WHERE hypertable_name = 'raw_logs'")).scalar()
    await fw.apply_retention()
    with owner_engine.connect() as c:
        ages = sorted(round(x) for x in c.execute(text("SELECT extract(epoch FROM now() - ts_received) / 86400 FROM raw_logs")).scalars())
        after = c.execute(text("SELECT count(*) FROM timescaledb_information.chunks WHERE hypertable_name = 'raw_logs'")).scalar()
    assert ages == [10] and after == before - 3                                # the 400 (empty), 200 and 95-day chunks


async def test_retention_works_off_a_chunk_backlog_in_batches(owner_engine, env):
    """At most 20 chunks per table per run (one transaction holding hundreds of chunk locks failed in production)."""
    cid, gw = env
    with owner_engine.begin() as c:
        c.execute(text("UPDATE clients SET retention_days = 90"))
        for age in range(100, 125):                    # 25 daily chunks past the retention
            c.execute(text("INSERT INTO raw_logs (ts_received, client_id, device_id, source_ip, transport, raw) "
                           "VALUES (now() - make_interval(days => :a), :c, :d, '10.0.0.1', 'udp', 'x')"), {"a": age, "c": cid, "d": gw})

    def old_chunks():
        with owner_engine.connect() as c:
            return c.execute(text("SELECT count(*) FROM timescaledb_information.chunks WHERE hypertable_name = 'raw_logs' "
                                  "AND range_end <= now() - interval '90 days'")).scalar()
    assert old_chunks() >= 25
    await fw.apply_retention()
    assert 1 <= old_chunks() <= 6
    await fw.apply_retention()
    assert old_chunks() == 0
