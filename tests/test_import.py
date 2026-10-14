"""Importing a UniFi console's own log files (CTS KL /var/log): file-format parsing from real lines, the importer,
and rebuilding one client's VPN history in time order."""

import gzip
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import zstandard
from sqlalchemy import text

from app.config import get_settings
from app.parserd.importer import import_files
from app.parserd.worker import ParserWorker
from app.parsers.vendors import module_for
from app.tracker.vpn import VpnTracker

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
RECENT = [l for l in (SAMPLES / "udm-cts-kl-files-2026-10-07.log").read_text(encoding="utf-8").splitlines() if l.strip()]
HISTORY = [l for l in (SAMPLES / "udm-cts-kl-files-history.txt").read_text(encoding="utf-8").splitlines() if l.strip()]
unifi = module_for("unifi")


def line(fragment: str) -> str:
    return next(l for l in RECENT + HISTORY if fragment in l)


def p(fragment: str):
    return unifi.parse(line(fragment), "Asia/Kuala_Lumpur")


def test_file_header_keeps_explicit_offset():
    ev = p("Grace Lee's Desktop) connected")
    assert ev.ts == datetime(2026, 10, 6, 9, 38, 33, tzinfo=UTC) and ev.host == "CTS-KL" and ev.process == "ubios-udapi-server"


def test_wireguard_server_peer_is_a_user_session():
    c, d = p("Grace Lee's Desktop) connected"), p("Grace Lee's Desktop) disconnected")
    assert (c.category, c.action, c.user_name, c.src_ip, c.src_port) == ("vpn", "vpn-user-connect", "Grace Lee's Desktop",
                                                                        "192.168.2.200", 54443)
    assert c.extra["assigned_ip"] == "192.168.1.99" and c.interface == "wgsrv1" and d.action == "vpn-user-disconnect"
    # the EVT_VPN line for the same peer must not look like a site-to-site tunnel
    e = p("EVT_VPN_ClientConnected nADg")
    assert e.action == "vpn-peer-connected" and e.interface is None


def test_ipsec_lines():
    up = p("established between 11.133.111.195")
    assert (up.action, up.dst_ip, up.interface) == ("vpn-tunnel-up", "11.229.44.205", "IPsec 11.229.44.205")
    assert p("to 11.145.11.27").action == "vpn-tunnel-connecting" and p("to 11.145.11.27").interface == "IPsec 11.145.11.27"
    assert p("reauthenticating IKE_SA").action == "vpn-ipsec-rekey"
    closed = p("closing CHILD_SA")
    assert closed.action == "vpn-ipsec-sa-closed" and closed.bytes_in > 6_000_000_000
    assert p("N(NO_PROP)").action == "vpn-ike-no-proposal"
    assert p("DPD check timed out").action == "vpn-ipsec-dpd-timeout"
    inbound = p("is initiating a Main Mode IKE_SA")
    assert inbound.action == "vpn-ike-inbound" and inbound.src_ip == "11.145.11.27"


def test_ids_json_from_threat_log():
    ev = p("ubnt-idsips-daemon")
    assert (ev.category, ev.action, ev.outcome, ev.severity) == ("ids", "ids-detect", "blocked", "low")
    assert ev.rule.startswith("ET SCAN") and ev.src_ip == "192.168.2.184" and ev.dst_port == 1433
    assert ev.extra["signature_id"] == 2001583 and ev.extra["ubnt_category"] == "SCAN"


def test_dhcp_and_sudo_from_files():
    assert p("DHCPACK(br0)").action == "dhcp-ack"
    assert p("sudo[").action == "sudo"


# ---- importer --------------------------------------------------------------------------------------------
@pytest.fixture
def kl(owner_engine):
    with owner_engine.begin() as c:
        cid = c.execute(text("INSERT INTO clients (name, slug, timezone) VALUES ('CTS KL','cts-kl','Asia/Kuala_Lumpur') RETURNING id")).scalar()
        dev = c.execute(text("INSERT INTO devices (client_id, name, vendor, syslog_source_ip) VALUES (:c,'CTS-KL','unifi','11.133.111.195') "
                             "RETURNING id"), {"c": cid}).scalar()
    return cid, dev


def _files(tmp_path):
    noise = "2026-10-06T00:00:02+08:00 CTS-KL kernel: [123.4] al_mod_eth_mac_stats_get: MAC statistics not supported"
    plain = tmp_path / "messages"
    nul = RECENT[12].replace("process:", "process:\x00")     # binary garbage, as found in real rotated logs
    plain.write_text("\n".join(RECENT[:6] + [noise, RECENT[0], nul]) + "\n", encoding="utf-8")   # one duplicate
    zst = tmp_path / "daemon.log.1.zst"
    zst.write_bytes(zstandard.ZstdCompressor().compress(("\n".join(RECENT[6:12] + HISTORY[:2] + [RECENT[1]]) + "\n").encode()))
    gz = tmp_path / "threat.log.gz"
    gz.write_bytes(gzip.compress(("\n".join(HISTORY[2:]) + "\n").encode()))
    return [str(plain), str(zst), str(gz)]


async def test_import_rebuild_end_to_end(owner_engine, kl, tmp_path):
    cid, dev = kl
    files = _files(tmp_path)
    st = await import_files(get_settings().db_conninfo(), "cts-kl", "CTS-KL", files, ["al_mod_eth_mac_stats_get"])
    assert st["stored"] == len(RECENT) + len(HISTORY) and st["duplicates"] == 2 and st["skipped_noise"] == 1
    again = await import_files(get_settings().db_conninfo(), "cts-kl", "CTS-KL", files, [])
    assert again["stored"] == 0 and len(again["skipped_files"]) == 3                       # safe to re-run
    with owner_engine.begin() as c:
        rows = c.execute(text("SELECT ts_received, transport, raw FROM raw_logs WHERE device_id = :d"), {"d": dev}).all()
        assert {r.transport for r in rows} == {"import"}
        dpd = next(r for r in rows if "DPD check" in r.raw)
        assert dpd.ts_received == datetime(2026, 9, 18, 22, 41, 43, tzinfo=UTC)          # the line's own time
    while await ParserWorker(get_settings()).run_once():
        pass
    with owner_engine.begin() as c:
        assert c.execute(text("SELECT count(*) FROM raw_logs WHERE device_id = :d AND parse_error IS NOT NULL"), {"d": dev}).scalar() == 0
        # events keep their original timestamps even when weeks old
        assert c.execute(text("SELECT min(ts) FROM events WHERE device_id = :d"), {"d": dev}).scalar() < datetime(2026, 9, 20, tzinfo=UTC)

    tracker = VpnTracker(get_settings())
    conn = await tracker.connect()
    try:
        n = await tracker.rebuild_client(conn, cid)
        await conn.commit()
    finally:
        await conn.close()
    assert n > 0
    with owner_engine.begin() as c:
        tunnels = {r.tunnel_name: r.state for r in c.execute(text(
            "SELECT tunnel_name, state FROM vpn_tunnel_state WHERE client_id = :c AND ended_at IS NULL"), {"c": cid})}
        sessions = c.execute(text("SELECT user_name, host(source_ip) AS src, started_at, ended_at FROM vpn_sessions "
                                  "WHERE client_id = :c ORDER BY started_at NULLS FIRST"), {"c": cid}).all()
    assert tunnels == {"IPsec 11.229.44.205": "up", "IPsec 11.145.11.27": "down"}
    # Grace: disconnected 17:37:58, connected again 17:38:33 (local) -> one closed (no connect seen) + one open session
    grace = [s for s in sessions if s.user_name == "Grace Lee's Desktop"]
    assert len(grace) == 2 and grace[0].ended_at is not None and grace[1].ended_at is None and grace[1].src == "192.168.2.200"


async def test_duplicate_session_signal_is_ignored(owner_engine, kl):
    """CEF 520 and the daemon's WireGuard line for the same connect create one session, not two."""
    cid, dev = kl
    with owner_engine.begin() as c:
        for i, (cls, extra) in enumerate((("cef:520", {"vpn_type": "WIREGUARD_SERVER"}),
                                          ("syslog:ubios-udapi-server", {"assigned_ip": "192.168.1.99"}))):
            c.execute(text("""INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class,
                              action, user_name, src_ip, extra) VALUES (:t, :c, :d, :i, :t, 'unifi', 'vpn', 'low', :cls,
                              'vpn-user-connect', 'Grace', '192.168.2.200', CAST(:x AS jsonb))"""),
                      {"t": datetime(2026, 10, 7, 3, 0, i, tzinfo=UTC), "c": cid, "d": dev, "i": i, "cls": cls, "x": json.dumps(extra)})
    tracker = VpnTracker(get_settings())
    conn = await tracker.connect()
    try:
        await tracker.rebuild_client(conn, cid)
        await conn.commit()
    finally:
        await conn.close()
    with owner_engine.begin() as c:
        assert c.execute(text("SELECT count(*) FROM vpn_sessions WHERE client_id = :c"), {"c": cid}).scalar() == 1


async def test_import_refreshes_insight_summaries(owner_engine, kl, tmp_path, monkeypatch):
    """After an import the aggregates are recomputed from the oldest imported line. (The refresh itself is not run here:
    materialising aggregates in the shared test database would leave rows behind for other tests.)"""
    import app.parserd.__main__ as cli
    calls = []

    async def fake_refresh(since):
        calls.append(since)
    monkeypatch.setattr(cli, "refresh_aggregates", fake_refresh)
    await import_files(get_settings().db_conninfo(), "cts-kl", "CTS-KL", _files(tmp_path), [])
    while await ParserWorker(get_settings()).run_once():
        pass
    await cli.refresh_insights_after_import("cts-kl", wait_minutes=0)
    assert calls == [datetime(2026, 9, 18, 22, 41, 43, tzinfo=UTC)]          # the DPD line, the oldest imported
