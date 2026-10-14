"""Report data. Every function takes (session, client_id, start, end) in UTC and returns plain dicts used by
both the PDF and the Excel renderer, so both outputs always show identical numbers."""

from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.reports.intervals import summarize

TITLES = {
    "vpn_uptime": "VPN tunnel availability",
    "vpn_sessions": "VPN client sessions",
    "device_traffic": "Device sources and destinations",
    "device_uptime": "Device uptime and downtime",
    "internet_usage": "Internet usage",
}
BUNDLE = ("internet_usage", "device_uptime", "vpn_uptime", "vpn_sessions", "device_traffic")

# Per-poll counter deltas. A negative delta (counter reset after a reboot) or a gap over 15 minutes is not
# used for rates; non-negative deltas always count towards totals.
WAN_DELTAS = """
    WITH m AS (
        SELECT w.device_id, w.wan_name, w.ts,
               w.rx_bytes - lag(w.rx_bytes) OVER win AS drx, w.tx_bytes - lag(w.tx_bytes) OVER win AS dtx,
               w.rx_packets - lag(w.rx_packets) OVER win AS dprx, w.tx_packets - lag(w.tx_packets) OVER win AS dptx,
               (w.rx_dropped + w.tx_dropped) - lag(w.rx_dropped + w.tx_dropped) OVER win AS ddrop,
               (w.rx_errors + w.tx_errors) - lag(w.rx_errors + w.tx_errors) OVER win AS derr,
               extract(epoch FROM w.ts - lag(w.ts) OVER win) AS secs
        FROM wan_metrics w
        WHERE w.client_id = ANY(:ids) AND w.ts >= CAST(:s AS timestamptz) - interval '15 minutes' AND w.ts < :e
        WINDOW win AS (PARTITION BY w.device_id, w.wan_name ORDER BY w.ts)
    )
"""


def _mbps(nbytes: float, secs: float) -> float:
    return nbytes * 8 / secs / 1e6 if secs > 0 else 0.0


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    v = sorted(values)
    return v[min(len(v) - 1, int(round(0.95 * (len(v) - 1))))]


async def internet_usage(db, client_id, start, end, now=None) -> dict:
    now = now or datetime.now(UTC)
    tz = ZoneInfo((await _rows(db, "SELECT timezone FROM clients WHERE id = :c", c=client_id))[0]["timezone"])
    rows = await _rows(db, WAN_DELTAS + """
        SELECT m.device_id, d.name AS device, m.wan_name, m.ts, m.drx, m.dtx, m.dprx, m.dptx, m.ddrop, m.derr, m.secs
        FROM m JOIN devices d ON d.id = m.device_id
        WHERE m.ts >= :s AND m.secs > 0 ORDER BY m.device_id, m.wan_name, m.ts""", ids=[client_id], s=start, e=end)
    labels = {(r["device_id"], r["wan_name"]): r["label"] for r in await _rows(db, """
        SELECT DISTINCT ON (device_id, wan_name) device_id, wan_name, label FROM wan_state
        WHERE client_id = :c ORDER BY device_id, wan_name, started_at DESC""", c=client_id)}
    states = await _rows(db, """SELECT device_id, wan_name, state, started_at, ended_at FROM wan_state
                                WHERE client_id = :c AND coalesce(ended_at, :now) > :s AND started_at < :e""",
                         c=client_id, s=start, e=end, now=now)
    wans: dict = {}
    for r in rows:
        k = (r["device_id"], r["wan_name"])
        w = wans.setdefault(k, {"device": r["device"], "wan": r["wan_name"], "label": labels.get(k), "rx": 0, "tx": 0,
                                "prx": 0, "ptx": 0, "drops": 0, "errors": 0, "rate_secs": 0.0, "rx_rates": [], "tx_rates": [],
                                "days": {}})
        if r["drx"] is None or r["drx"] < 0 or r["dtx"] is None or r["dtx"] < 0:
            continue  # counter reset (reboot): skip this interval
        w["rx"] += r["drx"]
        w["tx"] += r["dtx"]
        w["prx"] += max(0, r["dprx"] or 0)
        w["ptx"] += max(0, r["dptx"] or 0)
        w["drops"] += max(0, r["ddrop"] or 0)
        w["errors"] += max(0, r["derr"] or 0)
        day = w["days"].setdefault(r["ts"].astimezone(tz).date(), {"rx": 0, "tx": 0, "peak_rx": 0.0, "peak_tx": 0.0})
        day["rx"] += r["drx"]
        day["tx"] += r["dtx"]
        secs = float(r["secs"])
        if secs <= 900:
            rx_rate, tx_rate = _mbps(r["drx"], secs), _mbps(r["dtx"], secs)
            w["rx_rates"].append(rx_rate)
            w["tx_rates"].append(tx_rate)
            w["rate_secs"] += secs
            day["peak_rx"], day["peak_tx"] = max(day["peak_rx"], rx_rate), max(day["peak_tx"], tx_rate)
    out = []
    for (device_id, name), w in wans.items():
        if w["rx"] == 0 and w["tx"] == 0:
            continue  # an unused port
        iv = [(x["state"], x["started_at"], x["ended_at"]) for x in states if x["device_id"] == device_id and x["wan_name"] == name]
        sm = summarize(iv, start, end, None, now)
        rxr, txr = w.pop("rx_rates"), w.pop("tx_rates")
        out.append({**w, "avg_rx_mbps": _mbps(w["rx"], w["rate_secs"]), "avg_tx_mbps": _mbps(w["tx"], w["rate_secs"]),
                    "peak_rx_mbps": max(rxr, default=0.0), "peak_tx_mbps": max(txr, default=0.0),
                    "p95_rx_mbps": _p95(rxr), "p95_tx_mbps": _p95(txr),
                    "availability": sm.availability, "outages": sm.outages, "down_s": sm.seconds.get("down", 0.0),
                    "days": [{"date": d, **v} for d, v in sorted(w["days"].items())]})
    return {"wans": out}


def month_bounds(year: int, month: int, tz: str) -> tuple[datetime, datetime]:
    """A calendar month in the client's time zone, returned as UTC instants."""
    z = ZoneInfo(tz)
    start = datetime(year, month, 1, tzinfo=z)
    end = datetime(year + (month == 12), month % 12 + 1, 1, tzinfo=z)
    return start.astimezone(UTC), end.astimezone(UTC)


def previous_month(now: datetime, tz: str) -> tuple[datetime, datetime]:
    local = now.astimezone(ZoneInfo(tz))
    y, m = (local.year, local.month - 1) if local.month > 1 else (local.year - 1, 12)
    return month_bounds(y, m, tz)


async def _rows(db: AsyncSession, sql: str, **p) -> list[dict]:
    return [dict(r._mapping) for r in (await db.execute(text(sql), p)).all()]


async def _maintenance(db, client_id, start, end) -> dict:
    """device_id (or None = whole client) -> [(start, end)]"""
    out: dict = {}
    for r in await _rows(db, """SELECT device_id, starts_at, ends_at FROM maintenance_windows
                                WHERE client_id = :c AND ends_at > :s AND starts_at < :e""", c=client_id, s=start, e=end):
        out.setdefault(r["device_id"], []).append((r["starts_at"], r["ends_at"]))
    return out


def _windows_for(mw: dict, device_id: int) -> list:
    return mw.get(None, []) + mw.get(device_id, [])


async def device_uptime(db, client_id, start, end, now=None) -> dict:
    now = now or datetime.now(UTC)
    mw = await _maintenance(db, client_id, start, end)
    devices = await _rows(db, "SELECT id, name, model, firmware FROM devices WHERE client_id = :c ORDER BY name", c=client_id)
    states = await _rows(db, """SELECT device_id, state, started_at, ended_at FROM device_state
                                WHERE client_id = :c AND coalesce(ended_at, :now) > :s AND started_at < :e
                                ORDER BY started_at""", c=client_id, s=start, e=end, now=now)
    rows = []
    for d in devices:
        iv = [(r["state"], r["started_at"], r["ended_at"]) for r in states if r["device_id"] == d["id"]]
        sm = summarize(iv, start, end, _windows_for(mw, d["id"]), now)
        rows.append({**d, "availability": sm.availability, "up_s": sm.seconds.get("up", 0.0),
                     "down_s": sm.seconds.get("down", 0.0), "maintenance_s": sm.seconds.get("maintenance", 0.0),
                     "no_data_s": max(0.0, (min(end, now) - start).total_seconds() - sum(sm.seconds.values())),
                     "outages": sm.outages, "drops": sm.drops})
    return {"devices": rows}


async def vpn_uptime(db, client_id, start, end, now=None) -> dict:
    now = now or datetime.now(UTC)
    mw = await _maintenance(db, client_id, start, end)
    rows = await _rows(db, """
        SELECT t.device_id, d.name AS device, t.tunnel_name, t.peer, t.state, t.started_at, t.ended_at
        FROM vpn_tunnel_state t JOIN devices d ON d.id = t.device_id
        WHERE t.client_id = :c AND coalesce(t.ended_at, :now) > :s AND t.started_at < :e
        ORDER BY d.name, t.tunnel_name, t.started_at""", c=client_id, s=start, e=end, now=now)
    tunnels: dict = {}
    for r in rows:
        key = (r["device_id"], r["device"], r["tunnel_name"])
        t = tunnels.setdefault(key, {"device": r["device"], "tunnel": r["tunnel_name"], "peer": r["peer"], "iv": []})
        t["peer"] = r["peer"] or t["peer"]
        t["iv"].append((r["state"], r["started_at"], r["ended_at"]))
    out = []
    for (device_id, _, _), t in tunnels.items():
        sm = summarize(t.pop("iv"), start, end, _windows_for(mw, device_id), now)
        out.append({**t, "availability": sm.availability, "up_s": sm.seconds.get("up", 0.0),
                    "down_s": sm.seconds.get("down", 0.0), "unknown_s": sm.seconds.get("unknown", 0.0),
                    "maintenance_s": sm.seconds.get("maintenance", 0.0), "drops": sm.drops, "outages": sm.outages,
                    "longest": sorted(sm.outages, key=lambda ab: ab[1] - ab[0], reverse=True)[:25]})
    return {"tunnels": out}


async def vpn_sessions(db, client_id, start, end, now=None) -> dict:
    rows = await _rows(db, """
        SELECT s.user_name, host(s.source_ip) AS source_ip, host(s.assigned_ip) AS assigned_ip, s.vpn_type,
               s.started_at, s.ended_at, s.status, s.close_reason, d.name AS device
        FROM vpn_sessions s JOIN devices d ON d.id = s.device_id
        WHERE s.client_id = :c AND coalesce(s.started_at, s.last_seen_at) < :e AND coalesce(s.ended_at, s.last_seen_at) >= :s
        ORDER BY coalesce(s.started_at, s.last_seen_at)""", c=client_id, s=start, e=end)
    users: dict = {}
    for r in rows:
        r["duration_s"] = (r["ended_at"] - r["started_at"]).total_seconds() if r["started_at"] and r["ended_at"] else None
        u = users.setdefault(r["user_name"] or "(unknown)", {"user": r["user_name"] or "(unknown)", "sessions": 0, "total_s": 0.0})
        u["sessions"] += 1
        u["total_s"] += r["duration_s"] or 0.0
    failed = await _rows(db, """
        SELECT host(src_ip) AS ip, src_country AS country, extra->>'src_as_org' AS org, count(*) AS n
        FROM events WHERE client_id = :c AND ts >= :s AND ts < :e AND category = 'vpn' AND outcome = 'failure'
          AND src_ip IS NOT NULL GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT 50""", c=client_id, s=start, e=end)
    return {"sessions": rows, "users": sorted(users.values(), key=lambda u: -u["total_s"]), "failed_sources": failed}


async def device_traffic(db, client_id, start, end, now=None, top: int = 20) -> dict:
    devices = await _rows(db, "SELECT id, name FROM devices WHERE client_id = :c ORDER BY name", c=client_id)
    out = []
    for d in devices:
        p = {"d": d["id"], "s": start, "e": end, "top": top}
        srcs = await _rows(db, """
            SELECT host(src_ip) AS ip, src_country AS country, count(*) AS events,
                   count(*) FILTER (WHERE outcome IN ('blocked', 'failure')) AS blocked,
                   coalesce(sum(bytes_in), 0) + coalesce(sum(bytes_out), 0) AS bytes
            FROM events WHERE device_id = :d AND ts >= :s AND ts < :e AND src_ip IS NOT NULL
            GROUP BY 1, 2 ORDER BY 3 DESC LIMIT :top""", **p)
        dsts = await _rows(db, """
            SELECT host(dst_ip) AS ip, dst_port AS port, dst_country AS country, count(*) AS events,
                   count(*) FILTER (WHERE outcome IN ('blocked', 'failure')) AS blocked,
                   coalesce(sum(bytes_in), 0) + coalesce(sum(bytes_out), 0) AS bytes
            FROM events WHERE device_id = :d AND ts >= :s AND ts < :e AND dst_ip IS NOT NULL
            GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT :top""", **p)
        total = (await db.execute(text("SELECT count(*) FROM events WHERE device_id = :d AND ts >= :s AND ts < :e"),
                                  {"d": d["id"], "s": start, "e": end})).scalar()
        out.append({"device": d["name"], "events": total, "sources": srcs, "destinations": dsts})
    return {"devices": out}


BUILDERS = {"vpn_uptime": vpn_uptime, "vpn_sessions": vpn_sessions, "device_traffic": device_traffic,
            "device_uptime": device_uptime, "internet_usage": internet_usage}


async def build(db, report_type: str, client_id: int, start: datetime, end: datetime, now=None) -> dict:
    client = (await _rows(db, "SELECT id, name, slug, timezone FROM clients WHERE id = :c", c=client_id))[0]
    from app import packs
    packs.refresh()
    types = BUNDLES.get(report_type, (report_type,))
    if any(t not in BUILDERS for t in types):
        raise LookupError("This report type needs a report pack that is not installed, or whose licence has expired "
                          "(Admin -> Report packs).")
    sections = [{"type": t, "title": TITLES[t], **(await BUILDERS[t](db, client_id, start, end, now))} for t in types]
    return {"client": client, "type": report_type, "start": start, "end": end, "sections": sections,
            "generated": now or datetime.now(UTC), "period_s": (end - start).total_seconds()}


def human(seconds: float | None) -> str:
    if seconds is None:
        return ""
    td = timedelta(seconds=round(seconds))
    d, rem = td.days, td.seconds
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    return f"{d}d {h:02d}:{m:02d}:{s:02d}" if d else f"{h:02d}:{m:02d}:{s:02d}"


BUNDLES = {"monthly_bundle": BUNDLE}
BUNDLE_TITLES = {"monthly_bundle": "Monthly network report"}
TYPE_LABELS = {"monthly_bundle": "Monthly bundle (network reports)"}     # names in the "report type" lists


def report_types() -> dict:
    """Every report type that can be requested now: the built-in ones plus those of the installed report packs
    (app/packs.py), bundles first."""
    from app import packs
    packs.refresh()
    return {**TYPE_LABELS, **{t: title for t, title in TITLES.items() if t in BUILDERS}}
