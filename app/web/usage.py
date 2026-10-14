"""Insights → Devices & usage: internet bandwidth per device (by MAC, with hostname), per app and per website / service,
over time. Data: the events_usage_1h aggregate (hourly; download and upload separated).

A device is its MAC. NetFlow download records carry no MAC: they take the MAC their IP used for outgoing traffic in the
same hour (leases do not move within an hour); what still has no MAC is shown as "IP x.x.x.x (no MAC)"."""

from datetime import datetime, timedelta

from sqlalchemy import text

from app.intel.apps import APP_CATEGORY

# A MAC seen with more than this many IPs in one hour is a router in front of the users (its MAC is on their traffic),
# not a device: its traffic is attributed per IP instead.
ROUTER_IPS = 4
PRIVATE = "(u.ip << '10.0.0.0/8' OR u.ip << '172.16.0.0/12' OR u.ip << '192.168.0.0/16')"
# Complete hours only (bucket < the current hour): reading the open hour would aggregate raw events on the fly (millions of
# rows at busy times). {pre} narrows the scan to one device or one service before the MAC resolution.
RESOLVED = f"""
    WITH u0 AS (
        SELECT u.bucket, u.client_id, u.ip, u.mac, u.name, u.app, u.site, u.n, u.down, u.up FROM events_usage_1h u
        WHERE u.client_id = ANY(:ids) AND u.bucket >= :since AND u.bucket < :upto AND u.ip IS NOT NULL AND {PRIVATE}
          {{pre}}),
    routers AS (SELECT client_id, bucket, mac FROM u0 WHERE mac IS NOT NULL GROUP BY 1, 2, 3 HAVING count(DISTINCT ip) > {ROUTER_IPS}),
    u AS (SELECT u0.bucket, u0.client_id, u0.ip, CASE WHEN rt.mac IS NULL THEN u0.mac END AS mac, u0.name, u0.app, u0.site,
                 u0.n, u0.down, u0.up
          FROM u0 LEFT JOIN routers rt ON rt.client_id = u0.client_id AND rt.bucket = u0.bucket AND rt.mac = u0.mac),
    m AS (SELECT DISTINCT ON (client_id, bucket, ip) client_id, bucket, ip, mac FROM u WHERE mac IS NOT NULL
          ORDER BY client_id, bucket, ip, n DESC),
    r AS (SELECT u.bucket, u.client_id, u.ip, coalesce(u.mac, m.mac) AS mac, u.name, u.app, u.site, u.n, u.down, u.up,
                 coalesce(coalesce(u.mac, m.mac)::text, 'ip:' || host(u.ip)) AS dev
          FROM u LEFT JOIN m ON u.mac IS NULL AND m.client_id = u.client_id AND m.bucket = u.bucket AND m.ip = u.ip)
"""
KEEP = 6


async def _q(db, sql: str, **p) -> list[dict]:
    return [dict(r._mapping) for r in (await db.execute(text(sql), p)).all()]


def _prefilter(dev: str, item: str, kind: str) -> str:
    out = []
    if dev.startswith("ip:"):
        out.append("AND u.ip = CAST(:dev_ip AS inet)")
    elif dev:
        out.append("""AND (u.mac = CAST(:dev_mac AS macaddr) OR (u.mac IS NULL AND (u.client_id, u.bucket, u.ip) IN (
                         SELECT x.client_id, x.bucket, x.ip FROM events_usage_1h x WHERE x.mac = CAST(:dev_mac AS macaddr)
                         AND x.client_id = ANY(:ids) AND x.bucket >= :since AND x.bucket < :upto)))""")
    if item:
        out.append("AND u.app = :item" if kind == "app" else "AND u.site = :item")
    return " ".join(out)


def _filter(dev: str, item: str, kind: str) -> tuple[str, dict]:
    where, p = [], {}
    if dev:
        where.append("r.dev = :dev")
        p["dev"] = dev
    if item:
        where.append("r.app = :item" if kind == "app" else "r.site = :item")
        p["item"] = item
    return (" AND ".join(where) or "TRUE"), p


async def _names(db, ids, macs: list[str]) -> dict[str, str]:
    """MAC -> name: the UniFi client list (the admin's alias, else the device's hostname), else the latest DHCP hostname."""
    if not macs:
        return {}
    out = {r["mac"]: r["hostname"] for r in await _q(db, """SELECT DISTINCT ON (mac) mac::text AS mac, hostname FROM network_clients
                             WHERE client_id = ANY(:ids) AND mac = ANY(CAST(:macs AS macaddr[])) AND hostname IS NOT NULL
                             ORDER BY mac, last_seen DESC""", ids=ids, macs=macs)}
    for r in await _q(db, """
        SELECT DISTINCT ON (src_mac) src_mac::text AS mac, extra->>'hostname' AS host FROM events
        WHERE client_id = ANY(:ids) AND category = 'dhcp' AND extra ? 'hostname' AND src_mac = ANY(CAST(:macs AS macaddr[]))
          AND ts > now() - interval '90 days'
        ORDER BY src_mac, ts DESC""", ids=ids, macs=macs):
        out.setdefault(r["mac"], r["host"])
    return out


def _label(d: dict) -> str:
    if d.get("hostname") and d.get("mac"):
        return d["hostname"]
    return d.get("hostname") or d.get("mac") or f"IP {d['ips'][0]} (no MAC)"


async def build(db, ids: list[int], since: datetime, now: datetime, rng: str, dev: str = "", item: str = "",
                kind: str = "") -> dict:
    kind = kind if kind in ("app", "site") else "site"
    cond, extra = _filter(dev, item, kind)
    upto = now.replace(minute=0, second=0, microsecond=0)                 # complete hours only
    since = min(since.replace(minute=0, second=0, microsecond=0), upto - timedelta(hours=1))
    p = {"ids": ids, "since": since, "upto": upto, **extra}
    if dev.startswith("ip:"):
        p["dev_ip"] = dev[3:]
    elif dev:
        p["dev_mac"] = dev
    global_pre = _prefilter(dev, item, kind)
    step = timedelta(hours=1) if now - since <= timedelta(days=7) else timedelta(days=1)
    now = upto - timedelta(seconds=1)                                      # the chart axis ends with the last complete hour

    devices = await _q(db, RESOLVED.replace("{pre}", global_pre) + f"""
        SELECT r.dev, max(r.mac::text) AS mac, array_agg(DISTINCT host(r.ip)) AS ips, max(r.name) AS name,
               sum(r.down) AS down, sum(r.up) AS up, sum(r.n) AS n,
               count(DISTINCT coalesce(r.site, r.app)) AS dests
        FROM r WHERE {cond} GROUP BY r.dev ORDER BY sum(r.down) + sum(r.up) DESC LIMIT 50""", **p)
    names = await _names(db, ids, [d["mac"] for d in devices if d["mac"]])
    for d in devices:
        d["hostname"] = names.get(d["mac"]) or d["name"]
        d["ips"] = sorted(d["ips"] or [])
        d["label"] = _label(d)
        d["bytes"] = int(d["down"] or 0) + int(d["up"] or 0)

    apps = await _q(db, RESOLVED.replace("{pre}", global_pre) + f"""
        SELECT r.app AS k, sum(r.down) AS down, sum(r.up) AS up, sum(r.n) AS n, count(DISTINCT r.dev) AS devices
        FROM r WHERE {cond} AND r.app IS NOT NULL GROUP BY 1 ORDER BY sum(r.down) + sum(r.up) DESC LIMIT 30""", **p)
    sites = await _q(db, RESOLVED.replace("{pre}", global_pre) + f"""
        SELECT r.site AS k, max(r.app) AS app, sum(r.down) AS down, sum(r.up) AS up, sum(r.n) AS n,
               count(DISTINCT r.dev) AS devices
        FROM r WHERE {cond} AND r.site IS NOT NULL GROUP BY 1 ORDER BY sum(r.down) + sum(r.up) DESC LIMIT 40""", **p)
    for x in apps + sites:
        x["bytes"] = int(x["down"] or 0) + int(x["up"] or 0)
        x["category"] = APP_CATEGORY.get(x.get("app") or x["k"], "") if (x.get("app") or x["k"]) else ""

    # Bandwidth over time: one series per top destination (the selected item: download / upload instead).
    p["step"] = step
    if item:
        rows = await _q(db, RESOLVED.replace("{pre}", global_pre) + f"""
            SELECT time_bucket(CAST(:step AS interval), r.bucket) AS t, sum(r.down) AS down, sum(r.up) AS up
            FROM r WHERE {cond} GROUP BY 1 ORDER BY 1""", **p)
        x, series = _axis(since, now, step), {"Download": {}, "Upload": {}}
        for r in rows:
            series["Download"][r["t"]] = int(r["down"] or 0)
            series["Upload"][r["t"]] = int(r["up"] or 0)
    else:
        rows = await _q(db, RESOLVED.replace("{pre}", global_pre) + f"""
            SELECT time_bucket(CAST(:step AS interval), r.bucket) AS t, coalesce(r.site, r.app, 'unknown') AS k,
                   sum(r.down) + sum(r.up) AS b
            FROM r WHERE {cond} GROUP BY 1, 2""", **p)
        totals: dict = {}
        for r in rows:
            totals[r["k"]] = totals.get(r["k"], 0) + int(r["b"] or 0)
        top = [k for k, _ in sorted(totals.items(), key=lambda kv: -kv[1])[:KEEP]]
        x, series = _axis(since, now, step), {k: {} for k in top}
        if len(totals) > KEEP:
            series["Other"] = {}
        for r in rows:
            k = r["k"] if r["k"] in top else "Other"
            series[k][r["t"]] = series[k].get(r["t"], 0) + int(r["b"] or 0)
    chart = {"x": [t.isoformat() for t in x], "step_s": int(step.total_seconds()),
             "series": [{"name": k, "data": [v.get(t, 0) for t in x]} for k, v in series.items()]}

    focus, history = None, []
    if dev:
        focus = next((d for d in devices if d["dev"] == dev), None) or {"dev": dev, "label": dev, "ips": [], "mac": None}
        history = await _history(db, ids, focus, since, item, kind)
    return {"devices": devices, "apps": apps, "sites": sites, "chart": chart, "dev": dev, "item": item, "kind": kind,
            "history": history, "history_limit": HISTORY,
            "focus": focus, "empty": not devices,
            "total_down": sum(int(d["down"] or 0) for d in devices), "total_up": sum(int(d["up"] or 0) for d in devices)}


HISTORY = 200


async def _history(db, ids, focus: dict, since: datetime, item: str, kind: str) -> list[dict]:
    """The device's latest connections (newest first), up to now (not only complete hours). Looked up by the device's
    IPs (indexed) and then checked against its MAC, so a reused IP does not mix devices."""
    ips = focus.get("ips") or ([focus["dev"][3:]] if focus["dev"].startswith("ip:") else [])
    if not ips:
        return []
    item_cond = ""
    p = {"ids": ids, "since": since, "ips": ips, "mac": focus.get("mac"), "lim": HISTORY}
    if item:
        item_cond = ("AND e.rule = :item" if kind == "app"
                     else "AND coalesce(e.extra->>'domain', e.extra->>'dst_as_org') = :item")
        p["item"] = item
    rows = await _q(db, f"""
        SELECT e.id, e.ts, e.action, e.outcome, host(e.src_ip) AS src, host(e.dst_ip) AS dst, e.dst_port, e.protocol,
               coalesce(e.extra->>'fqdn', e.extra->>'domain') AS site, e.extra->>'dst_as_org' AS org, e.rule AS app,
               e.dst_country, e.bytes_in, e.bytes_out
        FROM events e
        WHERE e.src_ip = ANY(CAST(:ips AS inet[])) AND e.ts >= :since AND e.client_id = ANY(:ids) AND e.category IN ('traffic', 'firewall')
          AND (CAST(:mac AS macaddr) IS NULL OR e.src_mac IS NULL OR e.src_mac = CAST(:mac AS macaddr))
          AND coalesce(e.extra->>'direction', 'outgoing') = 'outgoing' {item_cond}
        ORDER BY e.ts DESC LIMIT :lim""", **p)
    for r in rows:
        netflow = r["action"] == "netflow"
        r["down"] = None if netflow else r["bytes_in"]          # NetFlow: one record per direction (this one = upload)
        r["up"] = r["bytes_out"]
        r["blocked"] = r["outcome"] == "blocked" or r["action"] == "flow-blocked"
    return rows


def _axis(since: datetime, now: datetime, step: timedelta) -> list[datetime]:
    s = step.total_seconds()
    t = datetime.fromtimestamp((since.timestamp() // s) * s, since.tzinfo)
    out = []
    while t <= now:
        out.append(t)
        t += step
    return out
