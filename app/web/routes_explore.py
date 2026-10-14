"""Global search (top bar) and the "360" page of a remote-access VPN user. The device/IP 360 is /ip/<ip> (routes_logs).

Search understands an IP or CIDR, a MAC address, and free text matched against device names, network-client hostnames,
VPN user names and website domains. Everything is client-scoped like the rest of the app."""

import ipaddress
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import text

from app.models.auth import ROLE_ADMIN, ROLE_ENGINEER
from app.web.deps import Ctx, current, require_role
from app.web.logquery import quote_value
from app.web.routes_logs import geo
from app.web.routes_vpn import human

router = APIRouter()
staff = require_role(ROLE_ADMIN, ROLE_ENGINEER)
_MAC = re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")


def _like(s: str) -> str:
    return "%" + s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


async def _rows(ctx: Ctx, sql: str, **p) -> list[dict]:
    return [dict(r._mapping) for r in (await ctx.db.execute(text(sql), p)).all()]


@router.get("/search")
async def search(ctx: Ctx = Depends(staff), q: str = ""):
    q = q.strip()[:200]
    if not q:
        return ctx.render("search.html", q=q, sections=[])
    try:                                                  # an address: straight to its page
        if "/" in q:
            net = ipaddress.ip_network(q, strict=False)
            return RedirectResponse("/logs?" + urlencode({"range": "24h", "ip": str(net)}), status_code=303)
        return RedirectResponse(f"/ip/{ipaddress.ip_address(q)}", status_code=303)
    except ValueError:
        pass
    p = {"ids": ctx.scope_ids, "like": _like(q), "since": datetime.now(UTC) - timedelta(days=7)}
    sections = []
    if _MAC.match(q):
        p["mac"] = q.lower().replace("-", ":")
        macs = await _rows(ctx, """
            SELECT host(nc.ip_internal) AS ip, nc.hostname, nc.vendor, nc.network, nc.last_seen, c.name AS client
            FROM network_clients nc JOIN clients c ON c.id = nc.client_id
            WHERE nc.client_id = ANY(:ids) AND nc.mac = CAST(:mac AS macaddr) ORDER BY nc.last_seen DESC""", **p)
        if len(macs) == 1 and macs[0]["ip"]:
            return RedirectResponse(f"/ip/{macs[0]['ip']}", status_code=303)
        sections.append(("Network clients with this MAC", "clients", macs))
    devices = await _rows(ctx, """
        SELECT d.id, d.name, d.model, host(d.syslog_source_ip) AS ip, c.name AS client FROM devices d
        JOIN clients c ON c.id = d.client_id WHERE d.client_id = ANY(:ids) AND (d.name ILIKE :like OR d.model ILIKE :like)
        ORDER BY d.name LIMIT 20""", **p)
    hosts = await _rows(ctx, """
        SELECT DISTINCT ON (nc.mac) host(nc.ip_internal) AS ip, nc.hostname, nc.mac::text AS mac, nc.vendor, nc.network,
               nc.last_seen, c.name AS client
        FROM network_clients nc JOIN clients c ON c.id = nc.client_id
        WHERE nc.client_id = ANY(:ids) AND (nc.hostname ILIKE :like OR nc.vendor ILIKE :like)
        ORDER BY nc.mac, nc.last_seen DESC LIMIT 30""", **p)
    users = await _rows(ctx, """
        SELECT s.user_name, count(*) AS sessions, max(coalesce(s.ended_at, s.last_seen_at)) AS last, c.name AS client
        FROM vpn_sessions s JOIN clients c ON c.id = s.client_id
        WHERE s.client_id = ANY(:ids) AND s.user_name ILIKE :like GROUP BY 1, 4 ORDER BY 3 DESC LIMIT 20""", **p)
    domains = await _rows(ctx, """
        SELECT domain, sum(n) AS n, count(DISTINCT src_ip) AS devices FROM events_web_1h
        WHERE client_id = ANY(:ids) AND bucket >= :since AND domain ILIKE :like GROUP BY 1 ORDER BY 2 DESC LIMIT 20""", **p)
    for d in domains:
        d["link"] = "/logs?" + urlencode({"range": "7d", "type": "traffic", "q": f"domain={quote_value(d['domain'])}"})
    sections += [("Log sources", "devices", devices), ("Network clients (hostname)", "clients", hosts),
                 ("VPN users", "users", users), ("Websites (last 7 days)", "domains", domains)]
    found = [s for s in sections if s[2]]
    if sum(len(s[2]) for s in found) == 1:                # exactly one hit: go there
        kind, row = found[0][1], found[0][2][0]
        if kind == "clients" and row.get("ip"):
            return RedirectResponse(f"/ip/{row['ip']}", status_code=303)
        if kind == "users":
            return RedirectResponse(f"/vpn/user?name={quote(row['user_name'])}", status_code=303)
    text_link = "/logs?" + urlencode({"range": "24h", "q": quote_value(q)})
    return ctx.render("search.html", q=q, sections=sections, text_link=text_link)


@router.get("/vpn/user")
async def vpn_user(ctx: Ctx = Depends(current), name: str = "", days: int = 30):
    """Everything about one remote-access VPN user: sessions, where they connected from, totals."""
    if not name:
        raise HTTPException(400, "Which user?")
    days = days if days in (7, 30, 90) else 30
    p = {"ids": ctx.scope_ids, "u": name, "since": datetime.now(UTC) - timedelta(days=days)}
    sessions = await _rows(ctx, """
        SELECT s.started_at, s.ended_at, s.status, s.close_reason, host(s.source_ip) AS source_ip,
               host(s.assigned_ip) AS assigned_ip, s.vpn_type, s.bytes_in, s.bytes_out, d.name AS device, c.name AS client,
               coalesce(s.ended_at, now()) - s.started_at AS dur
        FROM vpn_sessions s JOIN devices d ON d.id = s.device_id JOIN clients c ON c.id = s.client_id
        WHERE s.client_id = ANY(:ids) AND s.user_name = :u AND s.last_seen_at >= :since
        ORDER BY coalesce(s.started_at, s.last_seen_at) DESC LIMIT 1000""", **p)
    if not sessions and not (await ctx.db.execute(text(
            "SELECT 1 FROM vpn_sessions WHERE client_id = ANY(:ids) AND user_name = :u LIMIT 1"), p)).first():
        raise HTTPException(404, "No such VPN user in your scope.")
    sources: dict[str, dict] = {}
    for s in sessions:
        if not s["source_ip"]:
            continue
        r = sources.setdefault(s["source_ip"], {"ip": s["source_ip"], "sessions": 0, "last": None})
        r["sessions"] += 1
        last = s["ended_at"] or s["started_at"]
        r["last"] = max(filter(None, (r["last"], last)), default=None)
    for r in sources.values():
        a = ipaddress.ip_address(r["ip"])
        g = geo().lookup(r["ip"]) if a.is_global else None
        r["where"] = "internal network" if not a.is_global else ", ".join(x for x in ((g.country if g else None),
                                                                                       (g.as_org if g else None)) if x)
    totals = {
        "sessions": len(sessions), "open": sum(1 for s in sessions if s["status"] == "open"),
        "time": sum((s["dur"] for s in sessions if s["dur"] and s["started_at"]), timedelta()),
        "down": sum(s["bytes_in"] or 0 for s in sessions), "up": sum(s["bytes_out"] or 0 for s in sessions),
        "first": min((s["started_at"] for s in sessions if s["started_at"]), default=None),
        "last": max((s["ended_at"] or s["started_at"] for s in sessions if s["ended_at"] or s["started_at"]), default=None),
        "devices": sorted({s["device"] for s in sessions}),
    }
    # Hours of the day the user connects (in the scope's time zone), for a quick "normal pattern" view.
    hours = [0] * 24
    for s in sessions:
        if s["started_at"]:
            hours[s["started_at"].astimezone(ctx_tz(ctx)).hour] += 1
    return ctx.render("vpn_user.html", name=name, days=days, sessions=sessions, totals=totals,
                      sources=sorted(sources.values(), key=lambda r: -r["sessions"]), hours=hours, hours_max=max(hours) or 1,
                      human=human)


def ctx_tz(ctx: Ctx):
    from zoneinfo import ZoneInfo
    return ZoneInfo(ctx.tz)
