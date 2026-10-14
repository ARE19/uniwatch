"""Insights (FortiView equivalent): top-N views over hourly continuous aggregates, each row drilling
into Log View with the matching filter. Every role may view (dashboards); always client-scoped."""

import ipaddress
from datetime import timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text

from app.web.deps import Ctx, current
from app.intel.apps import APP_CATEGORY
from app.web.routes_logs import geo

router = APIRouter()
RANGES = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
VIEWS = [("usage", "Devices & usage"), ("web", "Websites & apps"), ("sources", "Top sources"), ("destinations", "Top destinations"), ("countries", "Countries & map"),
         ("threats", "Threats"), ("blocked", "Blocked & failed"), ("dns", "DNS filtering"), ("wifi", "WiFi"),
         ("admin", "Admin activity"), ("system", "System events")]
FAIL_OUTCOMES = ("blocked", "failure")


def _external(ip: str | None) -> bool:
    try:
        return bool(ip) and ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _org(ip: str | None) -> str | None:
    if not _external(ip):
        return None
    g = geo().lookup(ip)
    return g.as_org if g else None


async def _q(ctx: Ctx, sql: str, **p) -> list[dict]:
    return [dict(r._mapping) for r in (await ctx.db.execute(text(sql), p)).all()]


def _logs(rng: str, **filters) -> str:
    return "/logs?" + urlencode({"range": rng, **{k: v for k, v in filters.items() if v is not None}})


@router.get("/insights")
async def insights(ctx: Ctx = Depends(current), view: str = "web", rng: str = Query("24h", alias="range"), ip: str = "",
                   web_src: str = Query("", alias="src"), map_mode: str = Query("attacks", alias="map"),
                   dev: str = "", item: str = "", kind: str = ""):
    if rng not in RANGES:
        rng = "24h"
    if view not in dict(VIEWS):
        view = "sources"
    (now,) = (await ctx.db.execute(text("SELECT now()"))).one()
    p = {"ids": ctx.scope_ids, "since": now - RANGES[rng]}
    staff = ctx.is_staff
    tables: list[dict] = []
    web_meta: dict = {}

    usage = None
    if view == "usage":
        from app.web import usage as usage_mod
        usage = await usage_mod.build(ctx.db, ctx.scope_ids, p["since"], now, rng, dev[:64], item[:255], kind)
    elif view == "web":
        dev = ""
        if ip:
            try:
                ip = str(ipaddress.ip_address(ip))
                dev, p["ip"] = "AND src_ip = CAST(:ip AS inet)", ip
            except ValueError:
                ip = ""
        # Source: UniFi traffic flows (connections with data volume) when the scope has them, else DNS lookups.
        have = {r["action"] for r in await _q(ctx, """SELECT DISTINCT action FROM events_web_1h
                                                      WHERE client_id = ANY(:ids) AND bucket >= :since""", **p)}
        src = web_src if web_src in have else ("flow" if "flow" in have else "dns-query")
        p["act"] = src
        flows = src == "flow"
        vol = "sum(coalesce(bytes_in, 0) + coalesce(bytes_out, 0)) AS bytes, sum(bytes_in) AS down, sum(bytes_out) AS up"
        order = "ORDER BY bytes DESC, n DESC" if flows else "ORDER BY n DESC"
        base = f"FROM events_web_1h WHERE client_id = ANY(:ids) AND bucket >= :since AND action = :act {dev}"
        apps = await _q(ctx, f"SELECT rule AS app, sum(n) AS n, {vol}, count(DISTINCT src_ip) AS devices {base} "
                             f"AND rule IS NOT NULL GROUP BY 1 {order} LIMIT 40", **p)
        sites = await _q(ctx, f"SELECT domain, max(rule) AS app, sum(n) AS n, {vol}, count(DISTINCT src_ip) AS devices {base} "
                              f"AND domain IS NOT NULL GROUP BY 1 {order} LIMIT 50", **p)
        cats: dict = {}
        for a in apps:
            a["category"] = APP_CATEGORY.get(a["app"], "")
            a["link"] = _logs(rng, action=src, q=a["app"], ip=ip or None)
            c = cats.setdefault(a["category"], {"category": a["category"], "n": 0, "bytes": 0})
            c["n"] += int(a["n"])
            c["bytes"] += int(a["bytes"] or 0)
        for site in sites:
            site["category"] = APP_CATEGORY.get(site["app"], "") if site["app"] else ""
            site["link"] = _logs(rng, action=src, q=site["domain"], ip=ip or None)
        who = f" — device {ip}" if ip else ""
        count_label = "Connections" if flows else "DNS lookups"
        measure = ([("Data", "bytes", "bytesbar"), ("Download", "down", "bytes"), ("Upload", "up", "bytes"), (count_label, "n", "num")]
                   if flows else [(count_label, "n", "bar")])
        many = [] if ip else [("Devices", "devices", "num")]
        tables.append({"title": f"Applications{who}", "rows": apps,
                       "cols": [("Application", "app", "link"), ("Category", "category", "text")] + measure + many})
        tables.append({"title": f"Categories{who}", "rows": sorted(cats.values(), key=lambda c: (-c["bytes"], -c["n"])),
                       "cols": [("Category", "category", "text"), measure[0]] + ([(count_label, "n", "num")] if flows else [])})
        tables.append({"title": f"Websites (all domains){who}", "rows": sites,
                       "cols": [("Website", "domain", "link"), ("Application", "app", "text"), ("Category", "category", "text")]
                       + measure + many})
        if flows:
            orgs = await _q(ctx, f"SELECT org, sum(n) AS n, {vol}, count(DISTINCT src_ip) AS devices {base} "
                                 f"AND domain IS NULL AND org IS NOT NULL GROUP BY 1 {order} LIMIT 25", **p)
            tables.append({"title": f"Traffic without a website name, by network owner{who}", "rows": orgs,
                           "cols": [("Network owner (ASN)", "org", "text")] + measure + many})
        if not ip:
            top = await _q(ctx, f"SELECT host(src_ip) AS ip, sum(n) AS n, {vol}, count(DISTINCT rule) AS apps {base} "
                                f"GROUP BY 1 {order} LIMIT 25", **p)
            names = {r["ip"]: r["hostname"] for r in await _q(ctx, """
                SELECT DISTINCT ON (host(ip_internal)) host(ip_internal) AS ip, hostname FROM network_clients
                WHERE client_id = ANY(:ids) AND ip_internal IS NOT NULL ORDER BY host(ip_internal), last_seen DESC""", **p)}
            for t in top:
                t["hostname"] = names.get(t["ip"], "")
                t["link"] = f"/insights?view=web&range={rng}&ip={t['ip']}&src={src}"
            tables.append({"title": "Devices (click for that device's websites & apps)", "rows": top, "cols": [
                ("Device", "ip", "devlink"), ("Name", "hostname", "text")] + measure + [("Apps", "apps", "num")]})
        web_meta = {"src": src, "have": sorted(have), "ip": ip, "empty": not have}

    elif view == "sources":
        rows = await _q(ctx, """
            SELECT host(src_ip) AS ip, src_country AS country, src_asn AS asn, sum(n) AS n,
                   sum(n) FILTER (WHERE outcome = ANY(:fail)) AS failed, count(DISTINCT category) AS cats
            FROM events_src_1h WHERE client_id = ANY(:ids) AND bucket >= :since
            GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT 25""", fail=list(FAIL_OUTCOMES), **p)
        for r in rows:
            r["org"], r["where"] = _org(r["ip"]), "external" if _external(r["ip"]) else "internal"
            r["link"] = _logs(rng, ip=r["ip"])
        tables.append({"title": "Sources by event count", "rows": rows, "cols": [
            ("Source", "ip", "ip"), ("Where", "where", "text"), ("Country", "country", "text"), ("Network", "org", "text"),
            ("Events", "n", "bar"), ("Blocked / failed", "failed", "num")]})

    elif view == "destinations":
        rows = await _q(ctx, """
            SELECT host(dst_ip) AS ip, dst_port AS port, dst_country AS country, sum(n) AS n,
                   sum(n) FILTER (WHERE outcome = ANY(:fail)) AS failed
            FROM events_dst_1h WHERE client_id = ANY(:ids) AND bucket >= :since
            GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT 25""", fail=list(FAIL_OUTCOMES), **p)
        for r in rows:
            r["org"], r["link"] = _org(r["ip"]), _logs(rng, ip=r["ip"])
        tables.append({"title": "Destinations by event count", "rows": rows, "cols": [
            ("Destination", "ip", "ip"), ("Port", "port", "text"), ("Country", "country", "text"), ("Network", "org", "text"),
            ("Events", "n", "bar"), ("Blocked / failed", "failed", "num")]})

    elif view == "countries":
        map_mode = map_mode if map_mode in ("attacks", "destinations") else "attacks"
        if map_mode == "attacks":   # external sources that were blocked, failed or flagged by IDS
            rows = await _q(ctx, """
                SELECT src_country AS cc, sum(n) AS v FROM events_src_1h
                WHERE client_id = ANY(:ids) AND bucket >= :since AND src_country IS NOT NULL
                  AND (outcome = ANY(:fail) OR category = 'ids') GROUP BY 1""", fail=list(FAIL_OUTCOMES), **p)
            unit, link = "blocked / failed / IDS events", _logs(rng, q="srccountry=__CC__")
        else:                       # where internal devices connected to, by data volume (MB)
            rows = await _q(ctx, """
                SELECT dst_country AS cc, round(sum(coalesce(bytes_in, 0) + coalesce(bytes_out, 0)) / 1048576.0, 1) AS v
                FROM events_dst_1h WHERE client_id = ANY(:ids) AND bucket >= :since AND dst_country IS NOT NULL
                GROUP BY 1 HAVING sum(coalesce(bytes_in, 0) + coalesce(bytes_out, 0)) > 0""", **p)
            unit, link = "MB of traffic", _logs(rng, type="traffic", q="dstcountry=__CC__")
        web_meta = {"map": {"mode": map_mode, "unit": unit, "staff": staff, "link": link,
                            "data": [{"name": r["cc"], "value": float(r["v"])} for r in rows]}}
        for side, title in (("src", "Countries connecting in (source)"), ("dst", "Countries connected to (destination)")):
            rows = await _q(ctx, f"""
                SELECT {side}_country AS country, sum(n) AS n, count(DISTINCT {side}_ip) AS ips,
                       sum(n) FILTER (WHERE outcome = ANY(:fail)) AS failed
                FROM events_{side}_1h WHERE client_id = ANY(:ids) AND bucket >= :since AND {side}_country IS NOT NULL
                GROUP BY 1 ORDER BY 2 DESC LIMIT 25""", fail=list(FAIL_OUTCOMES), **p)
            tables.append({"title": title, "rows": rows, "cols": [
                ("Country", "country", "text"), ("Events", "n", "bar"), ("Distinct IPs", "ips", "num"),
                ("Blocked / failed", "failed", "num")]})

    elif view == "threats":
        rows = await _q(ctx, """
            SELECT rule, sum(n) AS n FROM events_rule_1h
            WHERE client_id = ANY(:ids) AND bucket >= :since AND category = 'ids' GROUP BY 1 ORDER BY 2 DESC LIMIT 25""", **p)
        for r in rows:
            r["link"] = _logs(rng, category="ids", q=r["rule"])
        tables.append({"title": "IDS/IPS signatures", "rows": rows, "cols": [("Signature / policy", "rule", "link"), ("Hits", "n", "bar")]})
        rows = await _q(ctx, """
            SELECT host(src_ip) AS ip, src_country AS country, sum(n) AS n FROM events_src_1h
            WHERE client_id = ANY(:ids) AND bucket >= :since AND category = 'ids' GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15""", **p)
        for r in rows:
            r["link"] = _logs(rng, category="ids", ip=r["ip"])
        tables.append({"title": "Threat sources", "rows": rows, "cols": [("Source", "ip", "ip"), ("Country", "country", "text"), ("Hits", "n", "bar")]})

    elif view == "blocked":
        rows = await _q(ctx, """
            SELECT category, action, rule, sum(n) AS n FROM events_rule_1h
            WHERE client_id = ANY(:ids) AND bucket >= :since AND outcome = ANY(:fail)
            GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT 25""", fail=list(FAIL_OUTCOMES), **p)
        for r in rows:
            r["link"] = _logs(rng, category=r["category"], action=r["action"])
        tables.append({"title": "Blocked / failed by type", "rows": rows, "cols": [
            ("Category", "category", "text"), ("Action", "action", "link"), ("Rule", "rule", "text"), ("Events", "n", "bar")]})
        rows = await _q(ctx, """
            SELECT host(src_ip) AS ip, src_country AS country, sum(n) AS n FROM events_src_1h
            WHERE client_id = ANY(:ids) AND bucket >= :since AND outcome = ANY(:fail)
            GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 20""", fail=list(FAIL_OUTCOMES), **p)
        for r in rows:
            r["org"], r["link"] = _org(r["ip"]), _logs(rng, ip=r["ip"])
        tables.append({"title": "Blocked / failed sources", "rows": rows, "cols": [
            ("Source", "ip", "ip"), ("Country", "country", "text"), ("Network", "org", "text"), ("Events", "n", "bar")]})

    elif view == "dns":
        rows = await _q(ctx, """
            SELECT domain, rule, sum(n) AS n FROM events_rule_1h
            WHERE client_id = ANY(:ids) AND bucket >= :since AND category = 'dns' AND domain IS NOT NULL
            GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 30""", **p)
        for r in rows:
            r["link"] = _logs(rng, category="dns", q=r["domain"])
        tables.append({"title": "Blocked domains", "rows": rows, "cols": [("Domain", "domain", "link"), ("Filter category", "rule", "text"), ("Blocks", "n", "bar")]})
        rows = await _q(ctx, """
            SELECT host(src_ip) AS ip, sum(n) AS n FROM events_src_1h
            WHERE client_id = ANY(:ids) AND bucket >= :since AND category = 'dns' GROUP BY 1 ORDER BY 2 DESC LIMIT 15""", **p)
        for r in rows:
            r["link"] = _logs(rng, category="dns", ip=r["ip"])
        tables.append({"title": "Clients with most blocked lookups", "rows": rows, "cols": [("Client IP", "ip", "ip"), ("Blocks", "n", "bar")]})

    elif view == "wifi":
        rows = await _q(ctx, """
            SELECT coalesce(ap, '(wired)') AS ap, count(*) AS n, count(*) FILTER (WHERE last_seen > now() - interval '10 minutes') AS online
            FROM network_clients WHERE client_id = ANY(:ids) AND last_seen >= :since GROUP BY 1 ORDER BY 2 DESC""", **p)
        tables.append({"title": "Clients by access point", "rows": rows, "cols": [("Access point", "ap", "text"), ("Clients seen", "n", "bar"), ("Online now", "online", "num")]})
        rows = await _q(ctx, """
            SELECT ssid, count(*) AS n, round(avg(rssi)) AS rssi FROM network_clients
            WHERE client_id = ANY(:ids) AND last_seen >= :since AND ssid IS NOT NULL GROUP BY 1 ORDER BY 2 DESC""", **p)
        tables.append({"title": "Clients by SSID", "rows": rows, "cols": [("SSID", "ssid", "text"), ("Clients", "n", "bar"), ("Avg signal (dBm)", "rssi", "num")]})
        rows = await _q(ctx, """
            SELECT action, sum(n) AS n FROM events_rule_1h
            WHERE client_id = ANY(:ids) AND bucket >= :since AND category = 'wifi' AND action IS NOT NULL GROUP BY 1 ORDER BY 2 DESC""", **p)
        for r in rows:
            r["link"] = _logs(rng, category="wifi", action=r["action"])
        tables.append({"title": "WiFi events", "rows": rows, "cols": [("Event", "action", "link"), ("Count", "n", "bar")]})

    elif view == "admin":
        rows = await _q(ctx, """
            SELECT coalesce(user_name, '(unknown)') AS user_name, action, count(*) AS n, max(ts) AS last
            FROM events WHERE client_id = ANY(:ids) AND ts >= :since AND category IN ('auth', 'config')
            GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 25""", **p)
        for r in rows:
            r["link"] = _logs(rng, user=r["user_name"] if r["user_name"] != "(unknown)" else None, action=r["action"])
        tables.append({"title": "Admin and privileged activity", "rows": rows, "cols": [
            ("User", "user_name", "text"), ("Action", "action", "link"), ("Count", "n", "bar"), ("Last", "last", "time")]})

    elif view == "system":
        rows = await _q(ctx, """
            SELECT coalesce(process, '(none)') AS process, severity, count(*) AS n FROM events
            WHERE client_id = ANY(:ids) AND ts >= :since AND category = 'system'
            GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 30""", **p)
        for r in rows:
            r["link"] = _logs(rng, category="system", q=r["process"] if r["process"] != "(none)" else None)
        tables.append({"title": "System events by process", "rows": rows, "cols": [
            ("Process", "process", "link"), ("Severity", "severity", "sev"), ("Events", "n", "bar")]})

    for t in tables:
        bar = next((key for _, key, kind in t["cols"] if kind in ("bar", "bytesbar")), "n")
        t["max"] = max([int(r.get(bar) or 0) for r in t["rows"]] or [0])
        if not staff:  # Log View is staff-only; client users see the numbers without drill-down
            for r in t["rows"]:
                r.pop("link", None)
    return ctx.render("insights.html", view=view, views=VIEWS, range=rng, ranges=list(RANGES), tables=tables, staff=staff,
                      web=web_meta, usage=usage)
