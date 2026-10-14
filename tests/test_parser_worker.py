"""Parser worker against the test database: raw_logs -> events, failures, config changes, replay, stats."""

import argparse
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from app.config import get_settings
from app.enrich.geoip import GeoResult
from app.parserd.__main__ import replay
from app.parserd.worker import ParserWorker
from tests.test_parsers_unifi import find

NOW = datetime(2026, 10, 6, 9, 0, tzinfo=UTC)


class FakeGeo:
    available = True

    def lookup(self, ip):
        return GeoResult("US", 64500, "Example Net") if ip == "11.26.85.18" else None


@pytest.fixture
def seeded(owner_engine):
    """Client nwhk + UniFi device + a few real raw lines and one garbage line."""
    lines = [
        find("|546|Config Modified|"),
        find("|544|Network Accessed|4|UNIFIcategory=Audit UNIFIhost=NW HK UNIFIaccessMethod=web UNIFIadmin=Unifi Owner src=11.26.85.18"),
        find("DHCPACK(br0) 192.168.1.60 80:5e:c0:f1:35:d5 SIP-T55A"),
        "complete garbage, not syslog",
    ]
    with owner_engine.begin() as c:
        cid = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Northwind HK','nwhk') RETURNING id")).scalar()
        did = c.execute(text("INSERT INTO devices (client_id, name, vendor, syslog_source_ip) "
                             "VALUES (:c,'NW-HK','unifi','192.168.1.1') RETURNING id"), {"c": cid}).scalar()
        for i, line in enumerate(lines):
            c.execute(text("INSERT INTO raw_logs (ts_received, client_id, device_id, source_ip, transport, raw) "
                           "VALUES (:ts, :c, :d, '192.168.1.1', 'udp', :raw)"),
                      {"ts": NOW - timedelta(seconds=10 - i), "c": cid, "d": did, "raw": line})
    return cid, did


async def test_worker_parses_batch(owner_engine, seeded):
    w = ParserWorker(get_settings(), FakeGeo())
    assert await w.run_once(NOW) == 4
    assert await w.run_once(NOW) == 0  # nothing left
    with owner_engine.connect() as c:
        events = c.execute(text("SELECT category, action, src_country, src_asn, extra->>'src_as_org' org FROM events ORDER BY raw_id")).all()
        raws = c.execute(text("SELECT parsed, parse_error FROM raw_logs ORDER BY id")).all()
        cfg = c.execute(text("SELECT admin_user, host(source_ip), summary FROM config_changes")).all()
    assert [(e.category, e.action) for e in events] == [("config", "config-change"), ("auth", "admin-access"), ("dhcp", "dhcp-ack")]
    assert (events[1].src_country, events[1].src_asn, events[1].org) == ("US", 64500, "Example Net")
    assert all(r.parsed for r in raws)
    assert [r.parse_error for r in raws][:3] == [None, None, None] and "unrecognised" in raws[3].parse_error
    assert cfg == [("Unifi Owner", "11.26.85.18", "System / rsyslogd: port: 514")]
    assert w.stats["parsed"] == 3 and w.stats["failed"] == 1


async def test_worker_records_stats(owner_engine, seeded):
    w = ParserWorker(get_settings())
    await w.run_once(NOW)
    await w.flush_stats()
    with owner_engine.connect() as c:
        row = c.execute(text("SELECT parsed, failed, lag_max_ms FROM ingest_stats WHERE component='parser'")).one()
    assert (row.parsed, row.failed) == (3, 1) and row.lag_max_ms >= 7000


async def test_replay_requeues_and_reparses(owner_engine, seeded):
    w = ParserWorker(get_settings())
    await w.run_once(NOW)
    args = argparse.Namespace(client="nwhk", since=(NOW - timedelta(hours=1)).isoformat(), until=(NOW + timedelta(hours=1)).isoformat(),
                              device=None, failed_only=False)
    assert await replay(args) == 0
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM events")).scalar() == 0
        assert c.execute(text("SELECT count(*) FROM config_changes")).scalar() == 0
        assert c.execute(text("SELECT count(*) FROM raw_logs WHERE NOT parsed")).scalar() == 4
        assert c.execute(text("SELECT count(*) FROM audit_log WHERE action='parser_replay'")).scalar() == 1
    assert await w.run_once(NOW) == 4
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM events")).scalar() == 3


async def test_replay_failed_only_leaves_good_events(owner_engine, seeded):
    w = ParserWorker(get_settings())
    await w.run_once(NOW)
    args = argparse.Namespace(client="nwhk", since=(NOW - timedelta(hours=1)).isoformat(), until=(NOW + timedelta(hours=1)).isoformat(),
                              device=None, failed_only=True)
    await replay(args)
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM events")).scalar() == 3
        assert c.execute(text("SELECT count(*) FROM raw_logs WHERE NOT parsed")).scalar() == 1


async def test_device_clock_far_off_uses_receive_time(owner_engine, seeded):
    cid, did = seeded
    with owner_engine.begin() as c:
        c.execute(text("UPDATE raw_logs SET parsed = true"))
        c.execute(text("INSERT INTO raw_logs (ts_received, client_id, device_id, source_ip, transport, raw) "
                       "VALUES (:ts, :c, :d, '192.168.1.1', 'udp', '<13>Jan  1 00:00:00 NW-HK NW-HK x[1]: old clock')"),
                  {"ts": NOW, "c": cid, "d": did})
    await ParserWorker(get_settings()).run_once(NOW)
    with owner_engine.connect() as c:
        ts, dev_ts = c.execute(text("SELECT ts, extra->>'ts_device' FROM events")).one()
    assert ts == NOW and dev_ts.startswith("2025-12-31T16:00")  # Jan 1 00:00 HKT


async def test_two_workers_never_double_process(owner_engine, seeded):
    import asyncio
    a, b = ParserWorker(get_settings(), batch_size=2), ParserWorker(get_settings(), batch_size=2)
    counts = await asyncio.gather(a.run_once(NOW), b.run_once(NOW))
    assert sorted(counts) == [2, 2]
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*), count(DISTINCT raw_id) FROM events")).one() == (3, 3)


async def test_compressed_history_does_not_stall_parsing(owner_engine, seeded, monkeypatch):
    """Regression (2026-10-07): with an imported history compressed, marking a batch parsed touched every chunk and hit
    TimescaleDB's decompression limit, so parsing stopped. The update is now bounded to the batch's time range."""
    cid, did = seeded
    old = NOW - timedelta(days=20)
    with owner_engine.begin() as c:
        for i in range(5):
            c.execute(text("INSERT INTO raw_logs (ts_received, client_id, device_id, source_ip, transport, raw, parsed) "
                           "VALUES (:ts, :c, :d, '192.168.1.1', 'file', 'history', true)"),
                      {"ts": old + timedelta(seconds=i), "c": cid, "d": did})
        c.execute(text("SELECT compress_chunk(ch) FROM show_chunks('raw_logs', older_than => CAST(:t AS timestamptz)) ch"),
                  {"t": NOW - timedelta(days=10)})
        assert c.execute(text("SELECT count(*) FROM timescaledb_information.chunks WHERE hypertable_name = 'raw_logs' "
                              "AND is_compressed")).scalar() == 1
    monkeypatch.setenv("PGOPTIONS", "-c timescaledb.max_tuples_decompressed_per_dml_transaction=1")
    w = ParserWorker(get_settings(), FakeGeo())
    for _ in range(7):           # past psycopg's prepare threshold: the bounds must stay effective
        with owner_engine.begin() as c:
            c.execute(text("UPDATE raw_logs SET parsed = false WHERE ts_received > :t"), {"t": NOW - timedelta(days=1)})
        assert await w.run_once(NOW) == 4
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM raw_logs WHERE NOT parsed")).scalar() == 0


async def test_recent_claim_leaves_old_chunks_alone(owner_engine, seeded):
    """The normal claim only looks at recent lines (so it never locks old chunks that are being compressed); older
    unparsed lines are picked up by the separate, occasional pass."""
    cid, did = seeded
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO raw_logs (ts_received, client_id, device_id, source_ip, transport, raw) "
                       "VALUES (now(), :c, :d, '192.168.1.1', 'udp', 'complete garbage, not syslog')"), {"c": cid, "d": did})
    w = ParserWorker(get_settings(), old_backlog_every=3600.0)
    w._old_last = __import__("time").monotonic()                 # the occasional pass is not due
    assert await w.run_once() == 1                               # only the line received just now
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM raw_logs WHERE NOT parsed")).scalar() == 4   # the 6 Oct lines untouched
    assert await ParserWorker(get_settings()).run_once(NOW) == 4  # default: older lines are taken as well
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM raw_logs WHERE NOT parsed")).scalar() == 0
