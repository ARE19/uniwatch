"""VPN monitor (FortiView VPN equivalent): tunnel availability and flaps, downtime, user sessions.
Available to every role (it is a dashboard view); always client-scoped."""

from datetime import timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import text

from app.audit import audit
from app.web.deps import Ctx, check_csrf, current

router = APIRouter()
RANGES = {"24h": (timedelta(hours=24), 900), "7d": (timedelta(days=7), 3 * 3600), "30d": (timedelta(days=30), 12 * 3600)}
STRIP_STATUS = ((0.999, "good", "≥ 99.9 % up"), (0.99, "warning", "99–99.9 % up"), (0.0, "critical", "< 99 % up"))

# Clip every interval to [since, now] once; everything else aggregates over it.
INTERVALS = """
    WITH iv AS (
        SELECT t.device_id, t.tunnel_name, t.state, t.peer, t.started_at, t.ended_at,
               GREATEST(t.started_at, :since) AS s, LEAST(coalesce(t.ended_at, :now), :now) AS e
        FROM vpn_tunnel_state t
        WHERE t.client_id = ANY(:ids) AND coalesce(t.ended_at, :now) > :since AND t.started_at < :now
          AND (:all_kinds OR t.tunnel_name LIKE 'IPsec %' OR t.tunnel_name LIKE 'ipsec:%')
    )
"""
KINDS = {"ipsec": "IPsec tunnels", "all": "All interfaces"}


def label(tunnel_name: str, names: dict, device_id: int) -> str:
    """Display name: the one set by staff, else the controller's IPsec name, else the technical name."""
    if n := names.get((device_id, tunnel_name)):
        return n
    return tunnel_name[6:] if tunnel_name.startswith("ipsec:") else tunnel_name


def availability(up_s: float, down_s: float) -> float | None:
    known = up_s + down_s
    return None if known <= 0 else up_s / known


def strip_class(frac: float | None) -> str:
    if frac is None:
        return "unknown"
    for floor, cls, _ in STRIP_STATUS:
        if frac >= floor:
            return cls
    return "critical"


def human(seconds: float) -> str:
    seconds = int(round(seconds))
    d, r = divmod(seconds, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    parts = [f"{d}d"] * bool(d) + [f"{h}h"] * bool(h) + [f"{m}m"] * bool(m and not d) + [f"{s}s"] * bool(s and not d and not h)
    return " ".join(parts) or "0s"


@router.get("/vpn")
async def vpn_monitor(ctx: Ctx = Depends(current), rng: str = Query("24h", alias="range"), kind: str = "ipsec",
                      user: str = ""):
    if rng not in RANGES:
        rng = "24h"
    kind = kind if kind in KINDS else "ipsec"
    lookback, step = RANGES[rng]
    (now,) = (await ctx.db.execute(text("SELECT now()"))).one()
    p = {"ids": ctx.scope_ids, "since": now - lookback, "now": now, "step": step, "all_kinds": kind == "all"}
    names = {(r.device_id, r.tunnel_name): r.display_name for r in (await ctx.db.execute(text(
        "SELECT device_id, tunnel_name, display_name FROM vpn_tunnel_names"))).all()}

    tunnels = [dict(r._mapping) for r in (await ctx.db.execute(text(INTERVALS + """
        SELECT iv.device_id, iv.tunnel_name, d.name AS device, cl.name AS client,
               sum(extract(epoch FROM e - s)) FILTER (WHERE state = 'up') AS up_s,
               sum(extract(epoch FROM e - s)) FILTER (WHERE state = 'down') AS down_s,
               sum(extract(epoch FROM e - s)) FILTER (WHERE state = 'unknown') AS unknown_s,
               count(*) FILTER (WHERE state = 'down' AND started_at >= :since) AS downs,
               max(e - s) FILTER (WHERE state = 'down') AS longest_down
        FROM iv JOIN devices d ON d.id = iv.device_id JOIN clients cl ON cl.id = d.client_id
        GROUP BY 1, 2, 3, 4 ORDER BY cl.name, d.name, iv.tunnel_name"""), p)).all()]
    current_rows = {(r.device_id, r.tunnel_name): r for r in (await ctx.db.execute(text("""
        SELECT device_id, tunnel_name, state, started_at, peer FROM vpn_tunnel_state
        WHERE client_id = ANY(:ids) AND ended_at IS NULL"""), p)).all()}

    # Availability strip: per bucket, the share of known (up+down) time that was up.
    strip_rows = (await ctx.db.execute(text(INTERVALS + """
        , b AS (
            SELECT g AS bs, g + make_interval(secs => :step) AS be
            FROM generate_series(to_timestamp(floor(extract(epoch FROM CAST(:since AS timestamptz)) / :step) * :step),
                                 CAST(:now AS timestamptz), make_interval(secs => :step)) g
        )
        SELECT iv.device_id, iv.tunnel_name, b.bs,
               sum(extract(epoch FROM LEAST(iv.e, b.be) - GREATEST(iv.s, b.bs))) FILTER (WHERE iv.state = 'up') AS up_s,
               sum(extract(epoch FROM LEAST(iv.e, b.be) - GREATEST(iv.s, b.bs))) FILTER (WHERE iv.state = 'down') AS down_s,
               count(*) FILTER (WHERE iv.state = 'down' AND iv.started_at >= b.bs) AS downs
        FROM b JOIN iv ON iv.s < b.be AND iv.e > b.bs
        GROUP BY 1, 2, 3 ORDER BY 3"""), p)).all()
    strips: dict = {}
    for r in strip_rows:
        frac = availability(float(r.up_s or 0), float(r.down_s or 0))
        strips.setdefault((r.device_id, r.tunnel_name), {})[r.bs] = (frac, r.downs)
    buckets = [p["since"] - timedelta(seconds=p["since"].timestamp() % step) + timedelta(seconds=step * i)
               for i in range(int(lookback.total_seconds() // step) + 1)]

    for t in tunnels:
        key = (t["device_id"], t["tunnel_name"])
        t["label"] = label(t["tunnel_name"], names, t["device_id"])
        t["renamed"] = key in names
        cur = current_rows.get(key)
        t["state"], t["since"], t["peer"] = (cur.state, cur.started_at, cur.peer) if cur else ("–", None, None)
        t["availability"] = availability(float(t["up_s"] or 0), float(t["down_s"] or 0))
        t["downtime"] = human(float(t["down_s"] or 0))
        t["unknown"] = human(float(t["unknown_s"] or 0)) if t["unknown_s"] else ""
        t["longest_down"] = human(t["longest_down"].total_seconds()) if t["longest_down"] else ""
        cells = strips.get(key, {})
        t["strip"] = [(b, *cells.get(b, (None, 0))) for b in buckets]

    downtimes = (await ctx.db.execute(text(INTERVALS + """
        SELECT d.name AS device, iv.device_id, iv.tunnel_name, iv.started_at, iv.ended_at, iv.e - iv.s AS dur
        FROM iv JOIN devices d ON d.id = iv.device_id WHERE iv.state = 'down'
        ORDER BY dur DESC LIMIT 15"""), p)).all()
    downtimes = [{**dict(d._mapping), "label": label(d.tunnel_name, names, d.device_id)} for d in downtimes]
    # Remote-access users: one row per VPN client name, click one to see only that user's sessions.
    users = (await ctx.db.execute(text("""
        SELECT s.user_name, count(*) AS sessions, count(*) FILTER (WHERE s.status = 'open') AS open,
               sum(coalesce(s.ended_at, now()) - s.started_at) FILTER (WHERE s.started_at IS NOT NULL) AS total,
               max(coalesce(s.ended_at, s.last_seen_at)) AS last, count(DISTINCT s.source_ip) AS sources,
               sum(s.bytes_in) AS bytes_in, sum(s.bytes_out) AS bytes_out, string_agg(DISTINCT d.name, ', ') AS devices
        FROM vpn_sessions s JOIN devices d ON d.id = s.device_id
        WHERE s.client_id = ANY(:ids) AND s.last_seen_at >= :since AND s.user_name IS NOT NULL
        GROUP BY 1 ORDER BY bool_or(s.status = 'open') DESC, 2 DESC"""), p)).all()
    p["user"] = user
    sessions = (await ctx.db.execute(text("""
        SELECT s.user_name, host(s.source_ip) AS source_ip, host(s.assigned_ip) AS assigned_ip, s.vpn_type, s.started_at,
               s.ended_at, s.status, s.close_reason, d.name AS device, s.bytes_in, s.bytes_out,
               coalesce(s.ended_at, now()) - s.started_at AS dur
        FROM vpn_sessions s JOIN devices d ON d.id = s.device_id
        WHERE s.client_id = ANY(:ids) AND s.last_seen_at >= :since AND (:user = '' OR s.user_name = :user)
        ORDER BY coalesce(s.started_at, s.last_seen_at) DESC LIMIT 500"""), p)).all()
    failed_logins = (await ctx.db.execute(text("""
        SELECT host(src_ip) AS ip, src_country, extra->>'src_as_org' AS org, count(*) AS n, max(ts) AS last
        FROM events WHERE client_id = ANY(:ids) AND ts >= :since AND category = 'vpn' AND outcome = 'failure'
          AND src_ip IS NOT NULL
        GROUP BY 1, 2, 3 ORDER BY 4 DESC LIMIT 10"""), p)).all()

    traffic = await _user_traffic(ctx, p) if user else None
    return ctx.render("vpn.html", range=rng, ranges=list(RANGES), tunnels=tunnels, downtimes=downtimes,
                      sessions=sessions, failed_logins=failed_logins, human=human, strip_class=strip_class,
                      strip_legend=STRIP_STATUS, step=step, kind=kind, kinds=KINDS, users=users, vpn_user=user,
                      traffic=traffic)


# A remote-access user's traffic = events to/from the VPN address their session was given, while the session lasted.
USER_SESSIONS = """
    WITH s AS (
        SELECT client_id, assigned_ip, GREATEST(coalesce(started_at, CAST(:since AS timestamptz)), :since) AS s,
               coalesce(ended_at, now()) AS e
        FROM vpn_sessions
        WHERE client_id = ANY(:ids) AND user_name = :user AND assigned_ip IS NOT NULL AND last_seen_at >= :since
    ), m AS (
        SELECT e.*, s.assigned_ip AS vpn_ip
        FROM s JOIN events e ON e.client_id = s.client_id AND e.ts >= s.s AND e.ts <= s.e
                            AND (e.src_ip = s.assigned_ip OR e.dst_ip = s.assigned_ip)
        WHERE e.ts >= :since AND e.category IN ('traffic', 'firewall', 'dns', 'ids')
    )
"""


async def _user_traffic(ctx: Ctx, p: dict) -> dict:
    db = ctx.db
    live = (await db.execute(text("""
        SELECT host(assigned_ip) AS ip, started_at, host(source_ip) AS source_ip FROM vpn_sessions
        WHERE client_id = ANY(:ids) AND user_name = :user AND status = 'open' AND assigned_ip IS NOT NULL
        ORDER BY last_seen_at DESC LIMIT 1"""), p)).first()
    flows = [dict(r._mapping) for r in (await db.execute(text(USER_SESSIONS + """
        SELECT m.ts, host(m.src_ip) AS src, m.src_port, host(m.dst_ip) AS dst, m.dst_port, m.protocol, m.action, m.category,
               m.dst_country, coalesce(m.extra->>'fqdn', m.extra->>'domain') AS dst_name, m.extra->>'app' AS app,
               coalesce(m.bytes_in, 0) + coalesce(m.bytes_out, 0) AS bytes, m.src_ip = m.vpn_ip AS outbound, m.id
        FROM m ORDER BY m.ts DESC LIMIT 200"""), p)).all()]
    top = [dict(r._mapping) for r in (await db.execute(text(USER_SESSIONS + """
        SELECT coalesce(m.extra->>'fqdn', m.extra->>'domain', host(m.dst_ip)) AS dest, max(host(m.dst_ip)) AS ip,
               max(m.dst_country) AS country, string_agg(DISTINCT m.protocol || '/' || m.dst_port, ', ') AS ports,
               max(m.extra->>'app') AS app, count(*) AS flows,
               sum(coalesce(m.bytes_in, 0) + coalesce(m.bytes_out, 0)) AS bytes, max(m.ts) AS last,
               count(*) FILTER (WHERE m.category = 'firewall' OR position('block' in coalesce(m.action, '')) > 0) AS blocked
        FROM m WHERE m.src_ip = m.vpn_ip AND m.dst_ip IS NOT NULL
        GROUP BY 1 ORDER BY sum(coalesce(m.bytes_in, 0) + coalesce(m.bytes_out, 0)) DESC NULLS LAST, count(*) DESC LIMIT 25"""),
        p)).all()]
    ips = sorted({r.ip for r in (await db.execute(text("""
        SELECT DISTINCT host(assigned_ip) AS ip FROM vpn_sessions
        WHERE client_id = ANY(:ids) AND user_name = :user AND assigned_ip IS NOT NULL AND last_seen_at >= :since"""), p)).all()})
    return {"live": live, "flows": flows, "top": top, "ips": ips}


@router.post("/vpn/tunnels/name")
async def name_tunnel(request: Request, device_id: int = Form(...), tunnel_name: str = Form(...),
                      display_name: str = Form(""), ctx: Ctx = Depends(current)):
    """Give a tunnel a readable name (e.g. the IPsec name configured on the firewall). Empty = back to default."""
    await check_csrf(request, ctx.session.csrf_token)
    if not ctx.is_staff:
        raise HTTPException(403, "Only staff can rename tunnels.")
    if (await ctx.db.execute(text("SELECT 1 FROM devices WHERE id = :d AND client_id = ANY(:ids)"),
                             {"d": device_id, "ids": ctx.scope_ids})).first() is None:
        raise HTTPException(404, "No such device.")
    name = display_name.strip()[:100]
    if name:
        await ctx.db.execute(text("""INSERT INTO vpn_tunnel_names (device_id, tunnel_name, display_name) VALUES (:d, :t, :n)
                                     ON CONFLICT (device_id, tunnel_name) DO UPDATE SET display_name = EXCLUDED.display_name"""),
                             {"d": device_id, "t": tunnel_name[:200], "n": name})
    else:
        await ctx.db.execute(text("DELETE FROM vpn_tunnel_names WHERE device_id = :d AND tunnel_name = :t"),
                             {"d": device_id, "t": tunnel_name})
    await audit(ctx.db, "vpn_tunnel_rename", request=request, user=ctx.user, target=tunnel_name,
                details={"device_id": device_id, "display_name": name or None})
    await ctx.db.commit()
    back = request.headers.get("referer") or "/vpn"
    return RedirectResponse(back if back.startswith(("/", str(request.base_url))) else "/vpn", status_code=303)
