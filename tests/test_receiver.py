"""Receiver: framing and cleaning units, then real UDP/TCP sockets into the test database."""

import asyncio
import socket
import time

import pytest
from sqlalchemy import text

from app.config import get_settings
from app.receiver.framing import OCTET_HARD_MAX, FramingError, TcpFramer, clean
from app.receiver.ratelimit import TokenBuckets
from app.receiver.server import Receiver

LINE = b"<14>Oct 06 15:05:16 NW-HK CEF:0|Ubiquiti|UniFi Network|10.6.106|400|WiFi Client Connected|1|UNIFIcategory=Client Devices"


# ---------------------------------------------------------------- units
def test_clean_strips_terminators_and_nul():
    assert clean(b"hello\r\n\x00", 100) == ("hello", False)
    assert clean(b"a\x00b", 100) == ("a�b", False)
    assert clean(b"\xff\xfeok", 100)[0].endswith("ok")


def test_clean_truncates():
    text_, truncated = clean(b"x" * 50, 10)
    assert text_ == "x" * 10 and truncated


def test_framer_lf_and_crlf_across_chunks():
    f = TcpFramer(1000)
    assert f.feed(b"<1>first\r\n<1>sec") == [(b"<1>first\r", False)]
    assert f.feed(b"ond\n\n") == [(b"<1>second", False)]


def test_framer_octet_counting_split_prefix():
    f = TcpFramer(1000)
    msg = b"<14>hello world"
    assert f.feed(b"1") == []
    assert f.feed(b"5 <14>hello") == []
    assert f.feed(b" world" + b"5 <1>") == [(msg, False)]  # next frame still incomplete
    assert f.feed(b"") == []


def test_framer_mixed_and_message_containing_newline():
    f = TcpFramer(1000)
    out = f.feed(b"10 <1>a\nb\nc!!<2>lf-framed\n")
    assert out == [(b"<1>a\nb\nc!!", False), (b"<2>lf-framed", False)]


def test_framer_oversize_lf_message_is_truncated_then_resyncs():
    f = TcpFramer(10)
    assert f.feed(b"<1>" + b"z" * 30) == [(b"<1>" + b"z" * 7, True)]
    assert f.feed(b"zzzz\n<2>next\n") == [(b"<2>next", False)]


def test_framer_oversize_octet_frame_truncated():
    f = TcpFramer(5)
    assert f.feed(b"8 <1>abcde") == [(b"<1>ab", True)]


def test_framer_rejects_absurd_octet_count():
    with pytest.raises(FramingError):
        TcpFramer(100).feed(str(OCTET_HARD_MAX + 1).encode() + b" <1>x")


def test_framer_remainder_without_trailing_newline():
    f = TcpFramer(100)
    f.feed(b"<1>no newline")
    assert f.remainder() == b"<1>no newline"


def test_token_bucket():
    tb = TokenBuckets(rate=1.0, burst=3)
    assert [tb.allow("a", 0.0) for _ in range(4)] == [True, True, True, False]
    assert tb.allow("a", 1.0)  # one token refilled after a second
    assert tb.allow("b", 1.0)  # independent per source
    tb.prune(10_000.0)
    assert len(tb) == 0


# ---------------------------------------------------------------- integration
@pytest.fixture
def mapped_device(owner_engine):
    """Client 'acme' with a device whose syslog source is 127.0.0.1 (the test container talking to itself)."""
    def _make(ip="127.0.0.1"):
        with owner_engine.begin() as c:
            cid = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Acme', 'acme') RETURNING id")).scalar()
            did = c.execute(text(
                "INSERT INTO devices (client_id, name, vendor, syslog_source_ip) VALUES (:c, 'udm', 'unifi', :ip) RETURNING id"
            ), {"c": cid, "ip": ip}).scalar()
        return cid, did
    return _make


@pytest.fixture
async def receiver():
    started: list[Receiver] = []

    async def _start(**overrides):
        s = get_settings().model_copy(update={
            "receiver_bind": "127.0.0.1", "receiver_udp_port": 0, "receiver_tcp_port": 0, "receiver_extra_ports": "",
            "receiver_netflow_port": 0, "receiver_flush_seconds": 0.05, "receiver_heartbeat_file": "/tmp/test-heartbeat", **overrides,
        })
        r = Receiver(s)
        await r.start()
        started.append(r)
        return r

    yield _start
    for r in started:
        await r.stop()


async def wait_for(owner_engine, sql, expected, timeout=5.0):
    deadline = time.monotonic() + timeout
    while True:
        with owner_engine.connect() as c:
            value = c.execute(text(sql)).scalar()
        if value == expected or time.monotonic() > deadline:
            return value
        await asyncio.sleep(0.05)


def send_udp(port, *payloads):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for p in payloads:
            s.sendto(p, ("127.0.0.1", port))


async def send_tcp(port, data: bytes):
    _, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(data)
    await w.drain()
    w.close()
    await w.wait_closed()


async def test_udp_and_tcp_lines_land_in_raw_logs(owner_engine, mapped_device, receiver):
    cid, did = mapped_device()
    r = await receiver()
    send_udp(r.udp_port, LINE, b"<13>plain syslog line\n")
    await send_tcp(r.tcp_port, b"<13>tcp lf framed\n" + b"17 <13>octet counted" + b"<13>no trailing newline")
    assert await wait_for(owner_engine, "SELECT count(*) FROM raw_logs", 5) == 5
    with owner_engine.connect() as c:
        rows = c.execute(text("SELECT transport, raw, client_id, device_id, host(source_ip) FROM raw_logs ORDER BY id")).all()
        last_log = c.execute(text("SELECT last_log_at FROM devices WHERE id = :d"), {"d": did}).scalar()
    raws = {row.raw for row in rows}
    assert LINE.decode() in raws and "<13>plain syslog line" in raws
    assert {"<13>tcp lf framed", "<13>octet counted", "<13>no trailing newline"} <= raws
    assert {(row.client_id, row.device_id, row[4]) for row in rows} == {(cid, did, "127.0.0.1")}
    assert sorted(row.transport for row in rows) == ["tcp", "tcp", "tcp", "udp", "udp"]
    assert last_log is not None


async def test_unknown_sender_is_counted_not_stored(owner_engine, receiver):
    r = await receiver()
    send_udp(r.udp_port, b"<13>who am i 1", b"<13>who am i 2", b"<13>who am i 3")
    assert await wait_for(owner_engine, "SELECT coalesce(sum(count),0) FROM unknown_sources", 3, timeout=10) == 3
    with owner_engine.connect() as c:
        row = c.execute(text("SELECT host(source_ip), sample, last_transport FROM unknown_sources")).one()
        assert c.execute(text("SELECT count(*) FROM raw_logs")).scalar() == 0
    assert row[0] == "127.0.0.1" and row[1].startswith("<13>who am i") and row[2] == "udp"


async def test_rate_limit_per_source(owner_engine, mapped_device, receiver):
    mapped_device()
    r = await receiver(receiver_rate_per_source=0.001, receiver_burst_per_source=5)
    send_udp(r.udp_port, *[b"<13>burst %d" % i for i in range(20)])
    assert await wait_for(owner_engine, "SELECT count(*) FROM raw_logs", 5) == 5
    await asyncio.sleep(0.3)
    assert r.pipeline.stats["rate_limited"] == 15


async def test_oversize_udp_is_truncated_and_flagged(owner_engine, mapped_device, receiver):
    mapped_device()
    r = await receiver(receiver_max_message_bytes=100)
    send_udp(r.udp_port, b"<13>" + b"y" * 5000)
    assert await wait_for(owner_engine, "SELECT count(*) FROM raw_logs WHERE truncated", 1) == 1
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT length(raw) FROM raw_logs")).scalar() == 100


async def test_queue_survives_db_outage(owner_engine, mapped_device, receiver):
    """Rows submitted while the DB is unreachable are kept and written once it is back."""
    mapped_device()
    r = await receiver()
    good = r.s.db_host
    r.pipeline.s = r.s.model_copy(update={"db_host": "127.0.0.1", "db_port": 1})  # nothing listens there
    await r.pipeline._drop_conn()
    send_udp(r.udp_port, b"<13>during outage 1", b"<13>during outage 2")
    await asyncio.sleep(0.5)
    assert len(r.pipeline.queue) == 2 and r.pipeline.stats["db_errors"] >= 1
    r.pipeline.s = r.s.model_copy(update={"db_host": good})
    assert await wait_for(owner_engine, "SELECT count(*) FROM raw_logs", 2, timeout=40) == 2


async def test_device_disabled_becomes_unknown(owner_engine, mapped_device, receiver):
    _, did = mapped_device()
    with owner_engine.begin() as c:
        c.execute(text("UPDATE devices SET is_active = false WHERE id = :d"), {"d": did})
    r = await receiver()
    send_udp(r.udp_port, b"<13>from disabled device")
    assert await wait_for(owner_engine, "SELECT coalesce(sum(count),0) FROM unknown_sources", 1, timeout=10) == 1


async def test_app_role_cannot_delete_raw_logs():
    from sqlalchemy.exc import ProgrammingError

    from app import db
    async with db.engine().connect() as c:
        with pytest.raises(ProgrammingError, match="permission denied"):
            await c.execute(text("DELETE FROM raw_logs"))
        await c.rollback()


def test_raw_logs_is_a_compressed_hypertable(owner_engine):
    with owner_engine.connect() as c:
        ht = c.execute(text(
            "SELECT compression_enabled FROM timescaledb_information.hypertables WHERE hypertable_name = 'raw_logs'"
        )).scalar()
        jobs = c.execute(text(
            "SELECT count(*) FROM timescaledb_information.jobs WHERE hypertable_name = 'raw_logs' AND proc_name = 'policy_compression'"
        )).scalar()
    assert ht is True and jobs == 1


async def test_unknown_sender_registered_meanwhile_is_not_recorded(owner_engine, mapped_device, receiver):
    r = await receiver()
    send_udp(r.udp_port, b"<13>before registration")
    await asyncio.sleep(0.2)
    assert "127.0.0.1" in r.pipeline.unknown or await wait_for(
        owner_engine, "SELECT count(*) FROM unknown_sources", 1) == 1
    with owner_engine.begin() as c:
        c.execute(text("DELETE FROM unknown_sources"))
    mapped_device()
    await r.pipeline.refresh_devices()
    r.pipeline.unknown["127.0.0.1"] = [1, None, None, "late", "udp"]
    await r.pipeline.flush_unknown()
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM unknown_sources")).scalar() == 0


def test_netflow_capture_keeps_first_datagrams_per_sender(tmp_path):
    from app.receiver.server import NetflowCapture
    cap = NetflowCapture(str(tmp_path), max_per_source=2)
    for i in range(3):
        cap.datagram_received(bytes([0, 10, i]), ("192.0.2.7", 40000))
    cap.datagram_received(bytes([0, 9]), ("192.0.2.8", 40000))
    lines = (tmp_path / "192.0.2.7.hex").read_text().splitlines()
    assert [l.split()[1] for l in lines] == ["000a00", "000a01"]          # third one only counted
    assert cap.counts == {"192.0.2.7": 3, "192.0.2.8": 1}
    assert (tmp_path / "192.0.2.8.hex").read_text().split()[1] == "0009"
