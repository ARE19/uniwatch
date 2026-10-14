"""Log forwarding to other syslog receivers / SIEMs.

Formats (each wrapped in an RFC 5424 syslog header):
  raw   the original received line, verbatim (from raw_logs)
  cef   normalised event as ArcSight CEF (header '|' and '\\' escaped; extension '=' '\\' and newlines escaped)
  json  normalised event as one JSON object
Transports: UDP (one datagram per message), TCP and TLS (LF-terminated; TLS verifies the server certificate).
A new target starts at "now" (no history flood). A failed send keeps the cursor, so nothing is skipped."""

import asyncio
import json
import logging
import ssl
from datetime import UTC, datetime

from sqlalchemy import text

from app import db

log = logging.getLogger("forwarder")
SEV_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
CEF_SEV = {"low": 3, "medium": 5, "high": 8, "critical": 10}
SYSLOG_SEV = {"low": 6, "medium": 4, "high": 3, "critical": 2}   # info, warning, err, crit
FACILITY_LOCAL0 = 16
MAX_UDP = 8000
BATCH = 2000


def cef_header(v) -> str:
    return str(v if v is not None else "").replace("\\", "\\\\").replace("|", "\\|")


def cef_value(v) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\r", "\\r").replace("\n", "\\n")


def to_cef(ev: dict) -> str:
    name = ev.get("event_name") or ev.get("action") or ev.get("category")
    ext = {
        "rt": int(ev["ts"].timestamp() * 1000), "cat": ev.get("category"), "act": ev.get("action"),
        "outcome": ev.get("outcome"), "src": ev.get("src_ip"), "spt": ev.get("src_port"), "dst": ev.get("dst_ip"),
        "dpt": ev.get("dst_port"), "proto": ev.get("protocol"), "suser": ev.get("user_name"),
        "smac": ev.get("src_mac"), "dmac": ev.get("dst_mac"), "in": ev.get("bytes_in"), "out": ev.get("bytes_out"),
        "deviceInboundInterface": ev.get("interface"), "dvchost": ev.get("device"),
        "cs1Label": "client", "cs1": ev.get("client"), "cs2Label": "rule", "cs2": ev.get("rule"),
        "cs3Label": "sourceCountry", "cs3": ev.get("src_country"), "cs4Label": "destinationCountry", "cs4": ev.get("dst_country"),
        "msg": ev.get("message"),
    }
    # A label without its value is noise: drop pairs whose value is empty.
    for i in range(1, 5):
        if ext.get(f"cs{i}") in (None, ""):
            ext.pop(f"cs{i}", None)
            ext.pop(f"cs{i}Label", None)
    tail = " ".join(f"{k}={cef_value(v)}" for k, v in ext.items() if v not in (None, ""))
    return "CEF:0|{}|{}|{}|{}|{}|{}|{}".format(
        cef_header("Example MSP"), cef_header("Uniwatch"), cef_header("1.0"),
        cef_header(ev.get("event_class")), cef_header(name), CEF_SEV[ev["severity"]], tail)


def to_json(ev: dict) -> str:
    return json.dumps({k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in ev.items()}, default=str,
                      ensure_ascii=False)


def syslog_wrap(msg: str, ts: datetime, host: str, severity: str = "low", app: str = "uniwatch") -> str:
    pri = FACILITY_LOCAL0 * 8 + SYSLOG_SEV.get(severity, 6)
    host = (host or "-").replace(" ", "_")[:255]
    return f"<{pri}>1 {ts.astimezone(UTC).isoformat(timespec='milliseconds').replace('+00:00', 'Z')} {host} {app} - - - {msg}"


async def send(target: dict, lines: list[str]) -> None:
    if target["protocol"] == "udp":
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(asyncio.DatagramProtocol, remote_addr=(target["host"], target["port"]))
        try:
            for line in lines:
                transport.sendto(line.encode("utf-8", "replace")[:MAX_UDP])
            await asyncio.sleep(0)
        finally:
            transport.close()
        return
    ctx = ssl.create_default_context() if target["protocol"] == "tls" else None
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(target["host"], target["port"], ssl=ctx,
                                server_hostname=target["host"] if ctx else None), timeout=10)
    try:
        writer.write("".join(line.replace("\n", " ") + "\n" for line in lines).encode("utf-8", "replace"))
        await asyncio.wait_for(writer.drain(), timeout=30)
    finally:
        writer.close()


EVENT_SQL = """
    SELECT e.id, e.ts, e.category, e.severity, e.event_class, e.event_name, e.action, e.outcome, host(e.src_ip) AS src_ip,
           e.src_port, host(e.dst_ip) AS dst_ip, e.dst_port, e.protocol, e.user_name, e.rule, e.interface,
           e.src_mac::text AS src_mac, e.dst_mac::text AS dst_mac, e.bytes_in, e.bytes_out, e.src_country, e.dst_country,
           e.message, d.name AS device, c.slug AS client
    FROM events e JOIN devices d ON d.id = e.device_id JOIN clients c ON c.id = e.client_id
    WHERE e.id > :cur AND e.ts > now() - interval '1 day' AND (CAST(:client AS integer) IS NULL OR e.client_id = :client)
      AND (CASE e.severity WHEN 'low' THEN 0 WHEN 'medium' THEN 1 WHEN 'high' THEN 2 ELSE 3 END) >= :minsev
    ORDER BY e.id LIMIT :lim
"""
RAW_SQL = """
    SELECT r.id, r.ts_received AS ts, r.raw, d.name AS device
    FROM raw_logs r JOIN devices d ON d.id = r.device_id
    WHERE r.id > :cur AND r.ts_received > now() - interval '1 day' AND (CAST(:client AS integer) IS NULL OR r.client_id = :client)
    ORDER BY r.id LIMIT :lim
"""


class Forwarder:
    def __init__(self, sender=send):
        self.send = sender

    async def run_once(self) -> dict:
        out = {}
        async with db.sessionmaker()() as s:
            targets = [dict(r._mapping) for r in (await s.execute(text("SELECT * FROM forwarding_targets WHERE enabled ORDER BY id"))).all()]
        for t in targets:
            try:
                out[t["name"]] = await self._one(t)
            except Exception as e:  # noqa: BLE001 — keep the cursor; retry next run
                msg = f"{type(e).__name__}: {e}"[:300]
                log.warning("forwarding to %s failed: %s", t["name"], msg)
                async with db.sessionmaker()() as s:
                    await s.execute(text("UPDATE forwarding_targets SET last_error = :e WHERE id = :i"), {"e": msg, "i": t["id"]})
                    await s.commit()
                out[t["name"]] = msg
        return out

    async def _one(self, t: dict) -> int:
        raw = t["format"] == "raw"
        async with db.sessionmaker()() as s:
            if t["cursor_id"] == 0:  # new target: start from now
                top = (await s.execute(text("SELECT coalesce(max(id), 0) FROM raw_logs" if raw else "SELECT coalesce(max(id), 0) FROM events"))).scalar()
                await s.execute(text("UPDATE forwarding_targets SET cursor_id = :c WHERE id = :i"), {"c": max(top, 1), "i": t["id"]})
                await s.commit()
                return 0
            rows = [dict(r._mapping) for r in (await s.execute(text(RAW_SQL if raw else EVENT_SQL),
                    {"cur": t["cursor_id"], "client": t["client_id"], "lim": BATCH,
                     "minsev": SEV_ORDER[t["min_severity"]]})).all()]
            if not rows:
                return 0
            if raw:
                lines = [syslog_wrap(r["raw"], r["ts"], r["device"]) for r in rows]
            elif t["format"] == "cef":
                lines = [syslog_wrap(to_cef(r), r["ts"], r["device"], r["severity"]) for r in rows]
            else:
                lines = [syslog_wrap(to_json(r), r["ts"], r["device"], r["severity"]) for r in rows]
            await self.send(t, lines)
            await s.execute(text("""UPDATE forwarding_targets SET cursor_id = :c, sent_count = sent_count + :n,
                                    last_sent_at = now(), last_error = NULL WHERE id = :i"""),
                            {"c": rows[-1]["id"], "n": len(rows), "i": t["id"]})
            await s.commit()
            return len(rows)


async def storage_usage(s) -> list[dict]:
    """Per-client estimated on-disk usage: each client's share of raw bytes and of event rows, applied to the
    real (compressed) size of the raw_logs and events hypertables."""
    rows = [dict(r._mapping) for r in (await s.execute(text("""
        WITH raw AS (SELECT client_id, sum(bytes) AS b, sum(lines) AS lines FROM raw_logs_1m GROUP BY 1),
             ev AS (SELECT client_id, sum(n) AS n FROM events_5m GROUP BY 1),
             sz AS (SELECT * FROM storage_sizes()),
             tot AS (SELECT (SELECT sum(b) FROM raw) AS raw_b, (SELECT sum(n) FROM ev) AS ev_n,
                            sz.raw_size, sz.events_size AS ev_size FROM sz)
        SELECT c.id, c.name, c.slug, c.retention_days, c.quota_gb, coalesce(raw.lines, 0) AS lines, coalesce(ev.n, 0) AS events,
               coalesce(raw.b / NULLIF(tot.raw_b, 0) * tot.raw_size, 0) + coalesce(ev.n / NULLIF(tot.ev_n, 0) * tot.ev_size, 0) AS est_bytes
        FROM clients c LEFT JOIN raw ON raw.client_id = c.id LEFT JOIN ev ON ev.client_id = c.id CROSS JOIN tot
        ORDER BY c.name""" ))).all()]
    for r in rows:
        r["est_bytes"] = float(r["est_bytes"] or 0)
        r["used_pct"] = (r["est_bytes"] / (r["quota_gb"] * 1024 ** 3) * 100) if r["quota_gb"] else None
    return rows


async def apply_retention() -> list[dict]:
    async with db.sessionmaker()() as s:
        rows = [dict(r._mapping) for r in (await s.execute(text("SELECT * FROM apply_retention()"))).all()]
        await s.commit()
    deleted = [r for r in rows if r["raw_deleted"] or r["events_deleted"]]
    if deleted:
        log.info("retention: %s", deleted)
    return rows
