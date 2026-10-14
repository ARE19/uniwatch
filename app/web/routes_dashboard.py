"""Dashboard (FortiAnalyzer-style): ingest health + security summary, scoped to the selected client(s)."""

import json
from datetime import timedelta
from urllib.parse import parse_qs, urlencode, urlparse

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import text
from starlette.datastructures import MultiDict

from app.config import get_settings
from app.intel.apps import APP_CATEGORY
from app.reports.data import WAN_DELTAS
from app.audit import audit
from app.web.deps import SCOPE_COOKIE, Ctx, check_csrf, current
from app.web.logquery import LogQuery
from app.web.widgets import BY_ID, CATALOGUE, DEFAULT_LAYOUT, normalise

router = APIRouter()
TRAFFIC_LINKS = 6       # charted WAN links (busiest first); one client's dashboard shows all of its links

# range -> (lookback, chart bucket)
RANGES = {
    "1h": (timedelta(hours=1), "1 minute"),
    "6h": (timedelta(hours=6), "5 minutes"),
    "24h": (timedelta(hours=24), "15 minutes"),
    "7d": (timedelta(days=7), "2 hours"),
}
BUCKET_SECONDS = {"1 minute": 60, "5 minutes": 300, "15 minutes": 900, "2 hours": 7200}


def bucket_grid(since, now, bucket: str) -> list[int]:
    """Every bucket start (epoch ms) in the window, aligned like time_bucket (epoch origin), so empty
    intervals plot as zero instead of a line interpolated across the gap."""
    step = BUCKET_SECONDS[bucket]
    start = int(since.timestamp()) // step * step
    end = int(now.timestamp())
    return [t * 1000 for t in range(start, end + 1, step)]
SILENT_AFTER = timedelta(minutes=15)
MAX_DEVICE_SERIES = 8  # categorical palette size; beyond this the tail folds into "Other"


def _range(r: str) -> tuple[str, timedelta, str]:
    if r not in RANGES:
        r = "24h"
    return (r, *RANGES[r])


# ------------------------------------------------------------------ customisable layouts
async def _dashboards(ctx: Ctx) -> list[dict]:
    """Dashboards this user can choose from (row-level security decides which)."""
    return await _rows(ctx, """
        SELECT d.id, d.name, d.shared, d.client_id, d.is_default, d.owner_id = :u AS mine, d.layout,
               c.name AS client_name, u.display_name AS owner_name
        FROM dashboards d LEFT JOIN clients c ON c.id = d.client_id LEFT JOIN users u ON u.id = d.owner_id
        ORDER BY (d.owner_id = :u) DESC, d.name""", u=ctx.user.id)


def _pick(ctx: Ctx, boards: list[dict], chosen: int | None) -> dict | None:
    """The user's own choice; else the default shared with their (selected) client; else the global default."""
    by_id = {b["id"]: b for b in boards}
    if chosen in by_id:
        return by_id[chosen]
    wanted = [ctx.selected.id] if ctx.selected else ([] if ctx.is_staff else [c.id for c in ctx.clients])
    for cid in wanted:
        for b in boards:
            if b["is_default"] and b["client_id"] == cid:
                return b
    return next((b for b in boards if b["is_default"] and b["client_id"] is None), None)


async def _search_names(ctx: Ctx, ids: list[int] | None = None) -> dict[int, dict]:
    if not ctx.is_staff:
        return {}
    rows = await _rows(ctx, "SELECT id, name, query, shared, user_id = :u AS mine FROM saved_searches ORDER BY name",
                       u=ctx.user.id)
    return {r["id"]: r for r in rows if ids is None or r["id"] in ids}


@router.get("/")
async def dashboard(ctx: Ctx = Depends(current), range: str = "24h"):
    r, _, _ = _range(range)
    boards = await _dashboards(ctx)
    chosen = (await ctx.db.execute(text("SELECT dashboard_id FROM user_dashboards WHERE user_id = :u"),
                                   {"u": ctx.user.id})).scalar()
    board = _pick(ctx, boards, chosen)
    searches = await _search_names(ctx)
    layout = normalise(board["layout"] if board else DEFAULT_LAYOUT, ctx.is_staff, set(searches))
    catalogue = [w for w in CATALOGUE if ctx.is_staff or not w.staff_only]
    can_edit = board is None or board["mine"] or (board["shared"] and ctx.is_staff)
    return ctx.render("dashboard.html", range=r, ranges=list(RANGES), layout=layout, widgets=BY_ID, board=board,
                      boards=boards, catalogue=catalogue, searches=searches, can_edit=can_edit,
                      share_clients=ctx.clients if ctx.is_staff else [],
                      default_layout=normalise(DEFAULT_LAYOUT, ctx.is_staff))


@router.post("/dashboards/save")
async def save_dashboard(request: Request, ctx: Ctx = Depends(current)):
    """JSON: {id, name, layout, share: private|all|client:<id>, is_default, as_new}. Returns {id}."""
    await check_csrf(request, ctx.session.csrf_token)
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(400, "Expected JSON.") from None
    if not isinstance(body, dict):
        raise HTTPException(400, "Expected a JSON object.")
    name = str(body.get("name") or "").strip()[:100] or "My dashboard"
    share = str(body.get("share") or "private")
    client_id = None
    if share != "private":
        if not ctx.is_staff:
            raise HTTPException(403, "Only staff can share dashboards.")
        if share.startswith("client:"):
            if not any(str(c.id) == share[7:] for c in ctx.clients):
                raise HTTPException(400, "Unknown client.")
            client_id = int(share[7:])
        elif share != "all":
            raise HTTPException(400, "Unknown sharing option.")
    shared = share != "private"
    is_default = bool(body.get("is_default")) and shared
    layout = normalise(body.get("layout"), ctx.is_staff, set(await _search_names(ctx)))
    if not layout:
        raise HTTPException(400, "A dashboard needs at least one widget.")
    if is_default:   # one default per audience
        await ctx.db.execute(text("UPDATE dashboards SET is_default = false WHERE is_default AND coalesce(client_id, 0) = :c"),
                             {"c": client_id or 0})
    vals = {"n": name, "l": json.dumps(layout), "s": shared, "c": client_id, "d": is_default, "u": ctx.user.id}
    board_id = body.get("id")
    if board_id and not body.get("as_new"):
        try:
            board_id = int(board_id)
        except (TypeError, ValueError):
            raise HTTPException(400, "Bad dashboard id.") from None
        res = await ctx.db.execute(text("""
            UPDATE dashboards SET name = :n, layout = CAST(:l AS jsonb), shared = :s, client_id = :c, is_default = :d,
                   updated_at = now() WHERE id = :i"""), {**vals, "i": board_id})
        if res.rowcount == 0:
            raise HTTPException(404, "No such dashboard you can change.")
        action = "dashboard_update"
    else:
        board_id = (await ctx.db.execute(text("""
            INSERT INTO dashboards (owner_id, name, layout, shared, client_id, is_default)
            VALUES (:u, :n, CAST(:l AS jsonb), :s, :c, :d) RETURNING id"""), vals)).scalar()
        action = "dashboard_create"
    await ctx.db.execute(text("""INSERT INTO user_dashboards (user_id, dashboard_id) VALUES (:u, :d)
                                 ON CONFLICT (user_id) DO UPDATE SET dashboard_id = EXCLUDED.dashboard_id"""),
                         {"u": ctx.user.id, "d": board_id})
    await audit(ctx.db, action, request=request, user=ctx.user, target=name,
                details={"id": board_id, "share": share, "is_default": is_default, "widgets": len(layout)})
    await ctx.db.commit()
    return {"id": board_id}


@router.post("/dashboards/select")
async def select_dashboard(request: Request, dashboard: str = Form("default"), ctx: Ctx = Depends(current)):
    await check_csrf(request, ctx.session.csrf_token)
    if dashboard.isdigit() and any(b["id"] == int(dashboard) for b in await _dashboards(ctx)):
        await ctx.db.execute(text("""INSERT INTO user_dashboards (user_id, dashboard_id) VALUES (:u, :d)
                                     ON CONFLICT (user_id) DO UPDATE SET dashboard_id = EXCLUDED.dashboard_id"""),
                             {"u": ctx.user.id, "d": int(dashboard)})
    else:   # back to the default for this user
        await ctx.db.execute(text("DELETE FROM user_dashboards WHERE user_id = :u"), {"u": ctx.user.id})
    await ctx.db.commit()
    return RedirectResponse("/", status_code=303)


@router.post("/dashboards/{board_id}/delete")
async def delete_dashboard(board_id: int, request: Request, ctx: Ctx = Depends(current)):
    await check_csrf(request, ctx.session.csrf_token)
    res = await ctx.db.execute(text("DELETE FROM dashboards WHERE id = :i"), {"i": board_id})
    if res.rowcount == 0:
        raise HTTPException(404, "No such dashboard you can delete.")
    await audit(ctx.db, "dashboard_delete", request=request, user=ctx.user, target=str(board_id))
    await ctx.db.commit()
    return RedirectResponse("/", status_code=303)


SEARCH_BUCKETS = {"1h": 300, "6h": 900, "24h": 3600, "7d": 21600}   # seconds


@router.get("/api/dashboard/search/{search_id}")
async def search_widget(search_id: int, ctx: Ctx = Depends(current), range: str = "24h"):
    """Count and trend of a saved Log View search over the dashboard range (staff, like Log View itself)."""
    if not ctx.is_staff:
        raise HTTPException(403, "Log View searches are for staff.")
    saved = (await _search_names(ctx, [search_id])).get(search_id)
    if saved is None:
        raise HTTPException(404, "No such saved search.")
    r, lookback, _ = _range(range)
    (now,) = (await ctx.db.execute(text("SELECT now()"))).one()
    filters = [(k, v) for k, vs in parse_qs(saved["query"]).items() for v in vs if k not in ("range", "from", "to")]
    lq = LogQuery.from_params(MultiDict(filters), ctx.tz, now)
    lq.since, lq.until = now - lookback, None
    where, p = lq.where(ctx.scope_ids)
    step = SEARCH_BUCKETS[r]
    rows = await _rows(ctx, f"""SELECT time_bucket(make_interval(secs => :step), e.ts) AS t, count(*) AS n FROM events e
                                WHERE {where} GROUP BY 1 ORDER BY 1""", step=step, **p)
    points: dict[int, int] = {}
    t = int(lq.since.timestamp()) // step * step   # zero-filled grid (the `range` argument shadows the builtin)
    while t <= int(now.timestamp()):
        points[t * 1000] = 0
        t += step
    for row in rows:
        points[_ms(row["t"])] = int(row["n"])
    return {"name": saved["name"], "count": sum(points.values()), "points": sorted(points.items()),
            "link": "/logs?" + urlencode([*filters, ("range", r if r in ("1h", "24h", "7d") else "24h")])}


DETAIL_PAGES = {"/config/change/": "/config", "/event-monitor/alerts/": "/event-monitor", "/incidents/": "/incidents"}


@router.post("/scope")
async def set_scope(request: Request, client: str = Form("all"), next: str = Form(""), ctx: Ctx = Depends(current)):
    await check_csrf(request, ctx.session.csrf_token)
    back = urlparse(request.headers.get("referer", "/"))
    target = back.path if back.path.startswith("/") and not back.path.startswith("//") else "/"
    # Pages about one client's item would keep showing the old client: go to the new client's overview, or to the list.
    if target.startswith("/site/"):
        target, back = (f"/site/{client}" if client.isdigit() else "/site"), back._replace(query="")
    else:
        for detail, listing in DETAIL_PAGES.items():
            if target.startswith(detail):
                target, back = listing, back._replace(query="")
                break
    if next.startswith("/") and not next.startswith("//"):
        resp = RedirectResponse(next, status_code=303)
    else:
        resp = RedirectResponse(target + (f"?{back.query}" if back.query else ""), status_code=303)
    if client != "all" and not any(str(c.id) == client for c in ctx.clients) \
            and not any(f"g{g.id}" == client for g in ctx.companies):
        raise HTTPException(403, "You cannot select that client.")
    resp.set_cookie(SCOPE_COOKIE, client, httponly=True, secure=get_settings().cookie_secure, samesite="lax",
                    path="/", max_age=86400 * 365)
    return resp


async def _rows(ctx: Ctx, sql: str, **params):
    return [dict(r._mapping) for r in (await ctx.db.execute(text(sql), params)).all()]


def _ms(dt) -> int:
    return int(dt.timestamp() * 1000)


@router.get("/wall")
async def wall(ctx: Ctx = Depends(current), seconds: int = 30, range: str = "24h"):
    """NOC wall: full-screen view rotating through the clients the user can see."""
    r, _, _ = _range(range)
    clients = [{"id": c.id, "name": c.name} for c in (ctx.clients if not ctx.selected else [ctx.selected])]
    return ctx.render("wall.html", seconds=seconds if seconds in (15, 30, 60) else 30, range=r, wall_clients=clients)


@router.get("/api/dashboard")
async def dashboard_data(ctx: Ctx = Depends(current), range: str = "24h", client: int | None = None):
    r, lookback, bucket = _range(range)
    ids = ctx.scope_ids
    if client is not None:     # one client of the user's scope (NOC wall); never widens the scope
        if not any(c.id == client for c in ctx.clients):
            raise HTTPException(403, "You cannot view that client.")
        ids = [client]
    p = {"ids": ids, "since": None, "bucket": bucket}
    (now,) = (await ctx.db.execute(text("SELECT now()"))).one()
    p["since"] = now - lookback

    # --- devices in scope (stable colour order = device id) ---------------------------
    devices = await _rows(ctx, """
        SELECT d.id, d.name, c.name AS client, d.last_log_at, d.is_active,
               coalesce((SELECT sum(lines) FROM raw_logs_1m m WHERE m.device_id = d.id AND m.bucket >= :since), 0) AS lines
        FROM devices d JOIN clients c ON c.id = d.client_id
        WHERE d.client_id = ANY(:ids) ORDER BY d.id""", **p)
    for d in devices:
        d["status"] = ("disabled" if not d["is_active"] else "never" if d["last_log_at"] is None
                       else "silent" if now - d["last_log_at"] > SILENT_AFTER else "ok")
        d["last_log_at"] = _ms(d["last_log_at"]) if d["last_log_at"] else None
        d["lines"] = int(d["lines"])
    shown = devices
    if len(devices) > MAX_DEVICE_SERIES:
        top = {d["id"] for d in sorted(devices, key=lambda d: -d["lines"])[: MAX_DEVICE_SERIES - 1]}
        shown = [d for d in devices if d["id"] in top]
    shown_ids = {d["id"] for d in shown}

    receive = await _rows(ctx, """
        SELECT time_bucket(CAST(:bucket AS interval), bucket) AS t, device_id, sum(lines) AS n
        FROM raw_logs_1m WHERE client_id = ANY(:ids) AND bucket >= :since GROUP BY 1, 2 ORDER BY 1""", **p)
    receive_series: dict[str, dict[int, int]] = {}
    names = {d["id"]: d["name"] for d in devices}
    grid = bucket_grid(p["since"], now, bucket)
    for row in receive:
        key = names.get(row["device_id"], "?") if row["device_id"] in shown_ids else "Other"
        s = receive_series.setdefault(key, {})
        s[_ms(row["t"])] = s.get(_ms(row["t"]), 0) + int(row["n"])

    severity = await _rows(ctx, """
        SELECT time_bucket(CAST(:bucket AS interval), bucket) AS t, severity, sum(n) AS n
        FROM events_5m WHERE client_id = ANY(:ids) AND bucket >= :since GROUP BY 1, 2 ORDER BY 1""", **p)
    categories = await _rows(ctx, """
        SELECT category, sum(n) AS n FROM events_5m WHERE client_id = ANY(:ids) AND bucket >= :since
        GROUP BY 1 ORDER BY 2 DESC""", **p)
    sev_totals = {s: 0 for s in ("critical", "high", "medium", "low")}
    for row in severity:
        sev_totals[row["severity"]] += int(row["n"])

    lines_total = sum(d["lines"] for d in devices)
    # (no parse-failure count here: the tile was removed and counting raw_logs over the range took 40+ s)

    threats = await _rows(ctx, """
        SELECT rule, count(*) AS n, max(ts) AS last, count(DISTINCT src_ip) AS sources
        FROM events WHERE client_id = ANY(:ids) AND ts >= :since AND category = 'ids'
        GROUP BY rule ORDER BY n DESC LIMIT 5""", **p)
    changes = await _rows(ctx, """
        SELECT cc.ts, cc.admin_user, host(cc.source_ip) AS source_ip, cc.summary, d.name AS device
        FROM config_changes cc JOIN devices d ON d.id = cc.device_id
        WHERE cc.client_id = ANY(:ids) AND cc.ts >= :since ORDER BY cc.ts DESC LIMIT 5""", **p)
    for row in threats:
        row["last"] = _ms(row["last"])
    for row in changes:
        row["ts"] = _ms(row["ts"])

    data = {
        "range": r, "tz": ctx.tz, "now": _ms(now),
        "tiles": {"lines": lines_total, "events": sum(sev_totals.values()), "severity": sev_totals,
                  "parse_failures": None,
                  "devices": len(devices), "devices_silent": sum(1 for d in devices if d["status"] in ("silent", "never"))},
        "devices": devices,
        "receive": {"series": [{"name": k, "points": [[t, v.get(t, 0)] for t in grid]} for k, v in receive_series.items()],
                    "order": [d["name"] for d in shown] + (["Other"] if "Other" in receive_series else [])},
        "severity": [{"t": _ms(x["t"]), "severity": x["severity"], "n": int(x["n"])} for x in severity],
        "categories": [{"category": x["category"], "n": int(x["n"])} for x in categories],
        "threats": threats,
        "changes": changes,
    }

    # Device health: latest metrics, current state, firmware, availability over the range (maintenance excluded).
    health = await _rows(ctx, """
        WITH m AS (
            SELECT DISTINCT ON (device_id) device_id, ts, cpu_pct, mem_pct, temp_c, uptime_s, client_count
            FROM device_metrics WHERE client_id = ANY(:ids) AND ts > now() - interval '15 minutes'
            ORDER BY device_id, ts DESC
        ), s AS (
            SELECT device_id,
                   sum(extract(epoch FROM LEAST(coalesce(ended_at, now()), now()) - GREATEST(started_at, :since)))
                       FILTER (WHERE state = 'up') AS up_s,
                   sum(extract(epoch FROM LEAST(coalesce(ended_at, now()), now()) - GREATEST(started_at, :since)))
                       FILTER (WHERE state = 'down') AS down_s
            FROM device_state WHERE client_id = ANY(:ids) AND coalesce(ended_at, now()) > :since GROUP BY 1
        )
        SELECT d.id, d.name, d.model, d.firmware, d.upgradable, d.firmware_latest, d.is_active,
               st.state, st.started_at AS state_since, m.cpu_pct, m.mem_pct, m.temp_c, m.uptime_s, m.client_count,
               s.up_s, s.down_s
        FROM devices d
        LEFT JOIN device_state st ON st.device_id = d.id AND st.ended_at IS NULL
        LEFT JOIN m ON m.device_id = d.id LEFT JOIN s ON s.device_id = d.id
        WHERE d.client_id = ANY(:ids) AND d.is_active ORDER BY d.id""", **p)
    for h in health:
        up, down = float(h.pop("up_s") or 0), float(h.pop("down_s") or 0)
        h["availability"] = round(up / (up + down) * 100, 2) if up + down > 0 else None
        h["state_since"] = _ms(h["state_since"]) if h["state_since"] else None
        for k in ("cpu_pct", "mem_pct", "temp_c"):
            h[k] = float(h[k]) if h[k] is not None else None
    data["health"] = health
    tunnels = await _rows(ctx, """
        SELECT t.tunnel_name, d.name AS device, t.state, t.started_at, t.peer,
               coalesce(n.display_name, regexp_replace(t.tunnel_name, '^ipsec:', '')) AS label,
               (t.tunnel_name LIKE 'ipsec:%' OR t.tunnel_name LIKE 'IPsec %') AS ipsec,
               (SELECT count(*) FROM vpn_tunnel_state x WHERE x.device_id = t.device_id AND x.tunnel_name = t.tunnel_name
                  AND x.state = 'down' AND x.started_at >= :since) AS drops
        FROM vpn_tunnel_state t JOIN devices d ON d.id = t.device_id
        LEFT JOIN vpn_tunnel_names n ON n.device_id = t.device_id AND n.tunnel_name = t.tunnel_name
        WHERE t.client_id = ANY(:ids) AND t.ended_at IS NULL ORDER BY d.name, t.tunnel_name""", **p)
    for t in tunnels:
        t["started_at"] = _ms(t["started_at"])
    data["vpn"] = tunnels
    # Site-to-site tunnels as the UniFi UI lists them (from the controller: status, WAN, local IP, peer, uptime).
    s2s = await _rows(ctx, """
        SELECT coalesce(n.display_name, regexp_replace(i.tunnel_name, '^ipsec:', '')) AS name, d.name AS device, i.status,
               i.vpn_type, i.interface, host(i.local_ip) AS local_ip, i.peer, i.established_at,
               (SELECT count(*) FROM vpn_tunnel_state x WHERE x.device_id = i.device_id AND x.tunnel_name = i.tunnel_name
                  AND x.state = 'down' AND x.started_at >= :since) AS drops
        FROM vpn_tunnel_info i JOIN devices d ON d.id = i.device_id
        LEFT JOIN vpn_tunnel_names n ON n.device_id = i.device_id AND n.tunnel_name = i.tunnel_name
        WHERE i.client_id = ANY(:ids) AND i.status <> 'disabled' AND i.updated_at > now() - interval '15 minutes'
        ORDER BY d.name, (i.status = 'established'), 1""", **p)
    for t in s2s:
        t["uptime_s"] = int((now - t["established_at"]).total_seconds()) if t["established_at"] else None
        t["established_at"] = _ms(t["established_at"]) if t["established_at"] else None
    data["s2s"] = s2s

    # WAN ports + overall internet per gateway: current state, availability over the range, live port details.
    wan = await _rows(ctx, """
        WITH iv AS (
            SELECT device_id, wan_name, state,
                   extract(epoch FROM LEAST(coalesce(ended_at, now()), now()) - GREATEST(started_at, :since)) AS secs
            FROM wan_state WHERE client_id = ANY(:ids) AND coalesce(ended_at, now()) > :since
        ), av AS (
            SELECT device_id, wan_name, sum(secs) FILTER (WHERE state = 'up') AS up_s,
                   sum(secs) FILTER (WHERE state = 'down') AS down_s,
                   count(*) FILTER (WHERE state = 'down') AS downs FROM iv GROUP BY 1, 2
        ), m AS (
            SELECT DISTINCT ON (device_id) device_id, extra FROM device_metrics
            WHERE client_id = ANY(:ids) AND ts > now() - interval '15 minutes' AND extra ? 'wan'
            ORDER BY device_id, ts DESC
        )
        SELECT d.name AS device, w.device_id, w.wan_name, w.label, w.ifname, host(w.ip) AS ip, w.state, w.started_at,
               EXISTS (SELECT 1 FROM wan_state p WHERE p.device_id = w.device_id AND p.wan_name = w.wan_name AND p.state = 'up') AS ever_up,
               av.up_s, av.down_s, av.downs, m.extra
        FROM wan_state w JOIN devices d ON d.id = w.device_id
        LEFT JOIN av ON av.device_id = w.device_id AND av.wan_name = w.wan_name
        LEFT JOIN m ON m.device_id = w.device_id
        WHERE w.client_id = ANY(:ids) AND w.ended_at IS NULL AND w.wan_name <> 'internet'
        ORDER BY d.name, w.wan_name""", **p)
    for w in wan:
        port = next((x for x in ((w.pop("extra") or {}).get("wan") or []) if x.get("name") == w["wan_name"]), {})
        internet = w["wan_name"] == "internet"
        w["is_uplink"], w["media"] = port.get("is_uplink"), port.get("media")
        w["latency_ms"] = port.get("latency_ms")
        up, down = float(w.pop("up_s") or 0), float(w.pop("down_s") or 0)
        w["availability"] = round(up / (up + down) * 100, 2) if up + down > 0 else None
        w["status"] = w["state"] if (w["ever_up"] or internet) else "unused"
        w["started_at"] = _ms(w["started_at"])
        w["downs"] = int(w["downs"] or 0)
    data["wan"] = wan
    data["open_alerts"] = (await ctx.db.execute(text(
        "SELECT count(*) FROM alerts WHERE client_id = ANY(:ids) AND status <> 'resolved'"), {"ids": ids})).scalar()
    # Top apps: by data volume from UniFi traffic flows when there are any, else by DNS lookups.
    data["apps"] = await _rows(ctx, """
        SELECT rule AS app, sum(n) AS n, sum(coalesce(bytes_in, 0) + coalesce(bytes_out, 0)) AS bytes,
               bool_or(action = 'flow') AS flow FROM events_web_1h
        WHERE client_id = ANY(:ids) AND bucket >= :since AND rule IS NOT NULL
          AND action = (SELECT coalesce(max(action) FILTER (WHERE action = 'flow'), 'dns-query') FROM events_web_1h
                        WHERE client_id = ANY(:ids) AND bucket >= :since)
        GROUP BY 1 ORDER BY 3 DESC, 2 DESC LIMIT 10""", **p)
    for a in data["apps"]:
        a["n"], a["bytes"], a["category"] = int(a["n"]), int(a["bytes"] or 0), APP_CATEGORY.get(a["app"], "")
    data["sites"] = await _rows(ctx, """
        SELECT domain, max(rule) AS app, sum(n) AS n, sum(coalesce(bytes_in, 0) + coalesce(bytes_out, 0)) AS bytes,
               bool_or(action = 'flow') AS flow FROM events_web_1h
        WHERE client_id = ANY(:ids) AND bucket >= :since AND domain IS NOT NULL
          AND action = (SELECT coalesce(max(action) FILTER (WHERE action = 'flow'), 'dns-query') FROM events_web_1h
                        WHERE client_id = ANY(:ids) AND bucket >= :since)
        GROUP BY 1 ORDER BY 4 DESC, 3 DESC LIMIT 10""", **p)
    for x in data["sites"]:
        x["n"], x["bytes"] = int(x["n"]), int(x["bytes"] or 0)
    data["talkers"] = await _rows(ctx, """
        SELECT host(w.src_ip) AS ip, sum(w.n) AS n, sum(coalesce(w.bytes_in, 0)) AS down, sum(coalesce(w.bytes_out, 0)) AS up,
               (SELECT nc.hostname FROM network_clients nc WHERE nc.client_id = ANY(:ids) AND nc.ip_internal = w.src_ip
                ORDER BY nc.last_seen DESC LIMIT 1) AS hostname
        FROM events_web_1h w WHERE w.client_id = ANY(:ids) AND w.bucket >= :since AND w.action = 'flow'
        GROUP BY w.src_ip ORDER BY sum(coalesce(w.bytes_in, 0) + coalesce(w.bytes_out, 0)) DESC LIMIT 10""", **p)
    for x in data["talkers"]:
        x["n"], x["down"], x["up"] = int(x["n"]), int(x["down"]), int(x["up"])

    # Internet traffic per WAN port: average Mbps and packets/s per chart bucket, from counter deltas.
    tr = await _rows(ctx, WAN_DELTAS + """
        SELECT time_bucket(CAST(:bucket AS interval), m.ts) AS t, d.name AS device, m.wan_name,
               sum(m.drx) AS rx, sum(m.dtx) AS tx, sum(m.dprx) AS prx, sum(m.dptx) AS ptx, sum(m.secs) AS secs
        FROM m JOIN devices d ON d.id = m.device_id
        WHERE m.ts >= :s AND m.secs > 0 AND m.secs <= 900 AND m.drx >= 0 AND m.dtx >= 0
        GROUP BY 1, 2, 3 ORDER BY 1""", ids=ids, s=p["since"], e=now, bucket=bucket)
    series: dict = {}
    for r in tr:
        key = f"{r['device']} {r['wan_name']}" if len({x['device'] for x in tr}) > 1 else r["wan_name"]
        s_ = series.setdefault(key, {"name": key, "rx": 0, "tx": 0, "points": {}})
        secs = float(r["secs"])
        s_["rx"] += int(r["rx"])
        s_["tx"] += int(r["tx"])
        rx, tx, prx, ptx = (float(r[k] or 0) for k in ("rx", "tx", "prx", "ptx"))   # sums arrive as Decimal
        s_["points"][_ms(r["t"])] = (rx * 8 / secs / 1e6, tx * 8 / secs / 1e6, prx / secs, ptx / secs)
    used = sorted((s_ for s_ in series.values() if s_["rx"] or s_["tx"]), key=lambda s_: -(s_["rx"] + s_["tx"]))
    data["traffic_links"] = len(used)
    data["traffic"] = [
        {"name": s_["name"], "rx_bytes": s_["rx"], "tx_bytes": s_["tx"],
         "points": [[t, *(s_["points"].get(t) or (None, None, None, None))] for t in grid]}
        for s_ in used[:TRAFFIC_LINKS]]

    # Ingest internals (receiver/parser/DB) are platform-wide, so staff only.
    if ctx.is_staff:
        stats = await _rows(ctx, """
            SELECT time_bucket(CAST(:bucket AS interval), ts) AS t, component,
                   sum(received) AS received, sum(stored) AS stored, sum(parsed) AS parsed, sum(failed) AS failed,
                   avg(lag_avg_ms) AS lag_avg, max(lag_max_ms) AS lag_max, max(queue_depth) AS queue
            FROM ingest_stats WHERE ts >= :since GROUP BY 1, 2 ORDER BY 1""", **p)
        unknown = (await ctx.db.execute(text("""
            SELECT count(*) FROM unknown_sources u WHERE NOT ignored
              AND NOT EXISTS (SELECT 1 FROM devices d WHERE d.syslog_source_ip = u.source_ip)"""))).scalar()
        sizes = await _rows(ctx, """
            SELECT 'raw_logs' AS t, raw_size AS bytes FROM storage_sizes()
            UNION ALL SELECT 'events', events_size FROM storage_sizes()""")
        by_key = {(_ms(x["t"]), x["component"]): x for x in stats}
        rates = []
        for comp in ("receiver", "parser"):
            for t in grid:
                x = by_key.get((t, comp), {})
                rates.append({"t": t, "component": comp,
                              "received": int(x.get("received") or 0), "stored": int(x.get("stored") or 0),
                              "parsed": int(x.get("parsed") or 0), "failed": int(x.get("failed") or 0),
                              # no parsing in an interval = no lag sample (gap), not zero lag
                              "lag_avg": float(x["lag_avg"]) if x.get("lag_avg") is not None else None,
                              "lag_max": int(x["lag_max"]) if x.get("lag_max") is not None else None})
        data["ingest"] = {
            "rates": rates,
            "unknown_senders": unknown,
            "storage": {x["t"]: int(x["bytes"] or 0) for x in sizes},
        }
    return data
