"""Log View (FortiAnalyzer-style): search, details pane, raw drill-down, saved searches, CSV export,
live tail (SSE), configuration-change audit, and IP details. Staff only; every query is client-scoped."""

import asyncio
import csv
import io
import ipaddress
import json
import time
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from urllib.parse import parse_qs

from fastapi.responses import RedirectResponse, StreamingResponse
from sqlalchemy import text
from starlette.datastructures import MultiDict

from app import db
from app.audit import audit
from app.enrich.geoip import GeoIP
from app.models.auth import ROLE_ADMIN, ROLE_ENGINEER
from app.parsers.model import CATEGORIES, SEVERITIES
from app.web.deps import Ctx, check_csrf, fmt_ts, require_role, templates
from app.web.logquery import COLUMNS, FIELDS, GROUPABLE, LOGTYPES, PRESET_LABELS, PRESETS, LogQuery, quote_value

router = APIRouter()
templates.env.globals["LOG_COLUMNS"] = COLUMNS
templates.env.filters["qv"] = quote_value
staff = require_role(ROLE_ADMIN, ROLE_ENGINEER)
PAGE = 100
EXPORT_MAX = 100_000
TAIL_SECONDS = 30 * 60
_geo: GeoIP | None = None


def geo() -> GeoIP:
    global _geo
    if _geo is None:
        _geo = GeoIP()
    return _geo


ROW_SQL = """
    SELECT e.id, e.ts, e.raw_id, e.raw_ts, d.name AS device, cl.name AS client, e.category, e.severity, e.action, e.outcome,
           host(e.src_ip) AS src_ip, e.src_port, e.src_country, host(e.dst_ip) AS dst_ip, e.dst_port, e.dst_country,
           e.protocol, e.user_name, e.rule, e.interface, e.message, e.event_name, e.process, e.bytes_in, e.bytes_out,
           e.src_mac::text AS src_mac, e.extra {raw_col}
    FROM events e
    JOIN devices d ON d.id = e.device_id
    JOIN clients cl ON cl.id = e.client_id
    {raw_join}
    WHERE {where} {page}
    ORDER BY e.ts DESC, e.id DESC
    LIMIT :limit
"""


def _row_sql(where: str, raw: bool, page: str = "") -> str:
    return ROW_SQL.format(
        where=where, page=page,
        raw_col=", r.raw" if raw else "",
        raw_join="LEFT JOIN raw_logs r ON r.id = e.raw_id AND r.ts_received = e.raw_ts" if raw else "",
    )


async def _devices(ctx: Ctx):
    return (await ctx.db.execute(text(
        "SELECT d.id, d.name, c.name AS client FROM devices d JOIN clients c ON c.id = d.client_id "
        "WHERE d.client_id = ANY(:ids) ORDER BY c.name, d.name"), {"ids": ctx.scope_ids})).all()


async def _histogram(ctx: Ctx, lq: LogQuery, until) -> list[dict]:
    """Events per time bucket for the current filters; each bar links to the same search narrowed to that bucket."""
    step = lq.histogram_step(until)
    where, p = lq.where(ctx.scope_ids)
    rows = {r.bucket: r.cnt for r in (await ctx.db.execute(text(f"""
        SELECT time_bucket(make_interval(secs => :step), e.ts) AS bucket, count(*) AS cnt FROM events e WHERE {where}
        GROUP BY 1"""), {**p, "step": step})).all()}
    start = datetime.fromtimestamp(int(lq.since.timestamp()) // step * step, UTC)
    out, t = [], start
    while t <= until:
        out.append({"t": t, "n": rows.get(t, 0), "step": step})
        t += timedelta(seconds=step)
    top = max((b["n"] for b in out), default=0) or 1
    from zoneinfo import ZoneInfo
    tz = ZoneInfo(ctx.tz)
    for b in out:
        b["h"] = round(100 * b["n"] / top, 1)
        f, to = b["t"].astimezone(tz), (b["t"] + timedelta(seconds=step)).astimezone(tz)
        b["link"] = lq.qs(range="custom", **{"from": f.strftime("%Y-%m-%dT%H:%M:%S"), "to": to.strftime("%Y-%m-%dT%H:%M:%S")})
    return out


async def _groups(ctx: Ctx, lq: LogQuery) -> list[dict]:
    """FortiAnalyzer-style "group by": top values of one field with counts and data volume."""
    where, p = lq.where(ctx.scope_ids)
    expr = lq.group_expr()
    rows = [dict(r._mapping) for r in (await ctx.db.execute(text(f"""
        SELECT {expr} AS v, count(*) AS n, sum(coalesce(e.bytes_in, 0) + coalesce(e.bytes_out, 0)) AS bytes, max(e.ts) AS last
        FROM events e WHERE {where} GROUP BY 1 ORDER BY 2 DESC LIMIT 200"""), p)).all()]
    top = max((r["n"] for r in rows), default=0) or 1
    for r in rows:
        r["h"] = round(100 * r["n"] / top, 1)
        if r["v"] is not None:
            term = f"{lq.group}={quote_value(str(r['v']))}"
            r["drill"] = lq.qs(group=None, q=f"{lq.q} {term}".strip())
            r["exclude"] = lq.qs(q=f"{lq.q} {lq.group}!={quote_value(str(r['v']))}".strip())
    return rows


async def _search(ctx: Ctx, lq: LogQuery, raw: bool, before_ts=None, before_id=None):
    where, p = lq.where(ctx.scope_ids)
    page = ""
    if before_ts is not None:
        page = "AND (e.ts, e.id) < (:bts, :bid)"
        p.update(bts=before_ts, bid=before_id)
    p["limit"] = PAGE + 1
    rows = [dict(r._mapping) for r in (await ctx.db.execute(text(_row_sql(where, raw, page)), p)).all()]
    more = len(rows) > PAGE
    return rows[:PAGE], more


@router.get("/logs")
async def log_view(request: Request, ctx: Ctx = Depends(staff)):
    lq = LogQuery.from_params(request.query_params, ctx.tz)
    raw = request.query_params.get("view") == "raw"
    groups = []
    if lq.group and not lq.errors:
        rows, more = [], False
        groups = await _groups(ctx, lq)
    else:
        rows, more = ([], False) if lq.errors else await _search(ctx, lq, raw)
    saved = (await ctx.db.execute(text(
        "SELECT id, name, query, shared, user_id = :u AS mine FROM saved_searches "
        "WHERE user_id = :u OR shared ORDER BY name"), {"u": ctx.user.id})).all()
    (now,) = (await ctx.db.execute(text("SELECT now()"))).one()
    histogram = [] if lq.errors else await _histogram(ctx, lq, lq.until or now)
    return ctx.render("logs.html", lq=lq, rows=rows, more=more, raw=raw, devices=await _devices(ctx),
                      groups=groups, groupable=GROUPABLE, histogram=histogram,
                      categories=CATEGORIES, severities=SEVERITIES[::-1], presets=list(PRESETS), preset_labels=PRESET_LABELS,
                      saved=saved, logtypes=LOGTYPES, columns=COLUMNS, fields=FIELDS, n0=0,
                      range_from=lq.since, range_to=lq.until or now)


@router.get("/logs/rows")
async def log_rows(request: Request, before_ts: datetime, before_id: int, n0: int = 0, ctx: Ctx = Depends(staff)):
    lq = LogQuery.from_params(request.query_params, ctx.tz)
    raw = request.query_params.get("view") == "raw"
    rows, more = await _search(ctx, lq, raw, before_ts, before_id)
    return templates.TemplateResponse(request, "logs_rows.html", {"rows": rows, "more": more, "raw": raw, "lq": lq,
                                                                  "scope_tz": ctx.tz, "view": "raw" if raw else "",
                                                                  "columns": COLUMNS, "n0": max(0, n0)})


@router.get("/logs/event/{event_id}")
async def log_event(event_id: int, request: Request, ts: datetime | None = None, ctx: Ctx = Depends(staff)):
    sql = """
        SELECT e.*, host(e.src_ip) AS src_host, host(e.dst_ip) AS dst_host, d.name AS device, cl.name AS client,
               cl.timezone AS client_tz, r.raw, r.transport, host(r.source_ip) AS sender, r.ts_received, r.truncated
        FROM events e JOIN devices d ON d.id = e.device_id JOIN clients cl ON cl.id = e.client_id
        LEFT JOIN raw_logs r ON r.id = e.raw_id AND r.ts_received = e.raw_ts
        WHERE e.id = :id AND e.client_id = ANY(:ids) {ts}"""
    p = {"id": event_id, "ids": ctx.scope_ids}
    if ts is not None:
        p["ts"] = ts
    row = (await ctx.db.execute(text(sql.format(ts="AND e.ts = :ts" if ts is not None else "")), p)).first()
    if row is None:
        raise HTTPException(404, "No such event in your scope.")
    ev = dict(row._mapping)
    incidents = (await ctx.db.execute(text(
        "SELECT id, title FROM incidents WHERE client_id = :c AND status IN ('new', 'investigating') ORDER BY id DESC LIMIT 50"),
        {"c": ev["client_id"]})).all()
    return templates.TemplateResponse(request, "logs_event.html", {"ev": ev, "scope_tz": ctx.tz, "incidents": incidents,
                                                                   "csrf_token": ctx.session.csrf_token,
                                                                   "extra_json": json.dumps(ev["extra"], indent=2, ensure_ascii=False)})


# ------------------------------------------------------------------ CSV export
CSV_COLUMNS = ("ts_utc", "ts_local", "client", "device", "category", "severity", "action", "outcome", "src_ip", "src_port",
               "src_country", "dst_ip", "dst_port", "dst_country", "protocol", "user_name", "rule", "interface", "message",
               "src_name", "remote_name", "app", "service", "bytes_sent", "bytes_received")
CSV_EXTRA = {"src_name": "src_name", "remote_name": "fqdn", "app": "app", "service": "service"}


def _csv_safe(v) -> str:
    s = "" if v is None else str(v)
    # Neutralise spreadsheet formula injection.
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@router.get("/logs/export.csv")
async def export_csv(request: Request, ctx: Ctx = Depends(staff)):
    lq = LogQuery.from_params(request.query_params, ctx.tz)
    if lq.errors:
        raise HTTPException(400, " ".join(lq.errors))
    where, p = lq.where(ctx.scope_ids)
    p["limit"] = EXPORT_MAX
    sql = _row_sql(where, raw=False)
    tz = ctx.tz
    uid, staff_flag = ctx.user.id, ctx.is_staff
    await audit(ctx.db, "log_export", request=request, user=ctx.user, details={"query": lq.qs(), "max_rows": EXPORT_MAX})
    await ctx.db.commit()

    async def gen():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(CSV_COLUMNS)
        yield buf.getvalue()
        # Own session (the request's is closed once streaming starts), bound to the same user's scope.
        async with db.sessionmaker("web")() as s:
            await db.apply_scope(s, uid, staff_flag)
            result = await s.stream(text(sql), p)
            async for r in result:
                m = r._mapping
                buf.seek(0)
                buf.truncate()
                x = m["extra"] or {}
                vals = {**m, **{k: x.get(src) for k, src in CSV_EXTRA.items()},
                        "bytes_sent": m["bytes_out"], "bytes_received": m["bytes_in"]}
                w.writerow([m["ts"].isoformat(), fmt_ts(m["ts"], tz), *(_csv_safe(vals[k]) for k in CSV_COLUMNS[2:])])
                yield buf.getvalue()

    name = f"logs-{datetime.now(UTC):%Y%m%d-%H%M%S}.csv"
    return StreamingResponse(gen(), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})


# ------------------------------------------------------------------ live tail (Server-Sent Events)
@router.get("/logs/tail")
async def tail(request: Request, ctx: Ctx = Depends(staff)):
    lq = LogQuery.from_params(request.query_params, ctx.tz)
    lq.since = datetime.now(UTC) - timedelta(hours=1)  # bounds the chunks scanned; tail only shows new rows
    lq.until = None
    raw = request.query_params.get("view") == "raw"
    where, p = lq.where(ctx.scope_ids)
    (last_id,) = (await ctx.db.execute(text(f"SELECT coalesce(max(e.id), 0) FROM events e WHERE {where}"), p)).one()
    tz = ctx.tz
    uid, staff_flag = ctx.user.id, ctx.is_staff
    tmpl = templates.get_template("logs_rows.html")

    async def gen():
        nonlocal last_id
        started = time.monotonic()
        yield "retry: 5000\n\n"
        while time.monotonic() - started < TAIL_SECONDS:
            if await request.is_disconnected():
                return
            async with db.sessionmaker("web")() as s:
                await db.apply_scope(s, uid, staff_flag)
                q = dict(p, last_id=last_id, limit=200)
                q["since"] = datetime.now(UTC) - timedelta(hours=1)
                rows = [dict(r._mapping) for r in (await s.execute(
                    text(_row_sql(where, raw, "AND e.id > :last_id")), q)).all()]
            if rows:
                last_id = max(r["id"] for r in rows)
                html = tmpl.render(rows=rows, more=False, raw=raw, lq=lq, scope_tz=tz, view="", columns=COLUMNS, n0=None)
                yield "event: rows\n" + "".join(f"data: {line}\n" for line in html.splitlines()) + "\n"
            else:
                yield ": keep-alive\n\n"
            await asyncio.sleep(2)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


# ------------------------------------------------------------------ saved searches
@router.post("/logs/saved")
async def save_search(request: Request, name: str = Form(""), query: str = Form(""), shared: bool = Form(False),
                      ctx: Ctx = Depends(staff)):
    await check_csrf(request, ctx.session.csrf_token)
    name = name.strip()[:100]
    if not name:
        raise HTTPException(400, "Give the search a name.")
    # Re-validate: only known filter keys are stored.
    lq = LogQuery.from_params(MultiDict([(k, v) for k, vs in parse_qs(query).items() for v in vs]), ctx.tz)
    await ctx.db.execute(text("INSERT INTO saved_searches (user_id, name, query, shared) VALUES (:u, :n, :q, :s)"),
                         {"u": ctx.user.id, "n": name, "q": lq.qs(), "s": shared})
    await audit(ctx.db, "saved_search_create", request=request, user=ctx.user, target=name, details={"shared": shared})
    await ctx.db.commit()
    return RedirectResponse("/logs?" + lq.qs(), status_code=303)


@router.post("/logs/saved/{search_id}/delete")
async def delete_search(search_id: int, request: Request, ctx: Ctx = Depends(staff)):
    await check_csrf(request, ctx.session.csrf_token)
    res = await ctx.db.execute(text("DELETE FROM saved_searches WHERE id = :i AND user_id = :u"),
                               {"i": search_id, "u": ctx.user.id})
    if res.rowcount == 0:
        raise HTTPException(404, "No such saved search of yours.")
    await audit(ctx.db, "saved_search_delete", request=request, user=ctx.user, target=str(search_id))
    await ctx.db.commit()
    return RedirectResponse("/logs", status_code=303)


# ------------------------------------------------------------------ configuration-change audit
@router.get("/logs/config-changes")
async def config_changes(request: Request, ctx: Ctx = Depends(staff), range: str = "30d", admin: str = ""):
    since = datetime.now(UTC) - PRESETS.get(range, PRESETS["30d"])
    p = {"ids": ctx.scope_ids, "since": since}
    extra = ""
    if admin:
        extra = "AND cc.admin_user ILIKE :admin"
        p["admin"] = f"%{admin}%"
    rows = (await ctx.db.execute(text(f"""
        SELECT cc.id, cc.ts, cc.admin_user, host(cc.source_ip) AS source_ip, cc.action, cc.summary, cc.details,
               d.name AS device, cl.name AS client, e.id AS event_id, e.ts AS event_ts
        FROM config_changes cc JOIN devices d ON d.id = cc.device_id JOIN clients cl ON cl.id = cc.client_id
        LEFT JOIN events e ON e.raw_id = cc.raw_id AND e.raw_ts = cc.raw_ts
        WHERE cc.client_id = ANY(:ids) AND cc.ts >= :since {extra}
        ORDER BY cc.ts DESC LIMIT 500"""), p)).all()
    return ctx.render("config_changes.html", rows=rows, range=range if range in PRESETS else "30d",
                      presets=list(PRESETS), admin=admin)


# ------------------------------------------------------------------ IP details
@router.get("/ip/{ip}")
async def ip_details(ip: str, ctx: Ctx = Depends(staff)):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(400, "Not an IP address.")
    ip = str(addr)
    since = datetime.now(UTC) - timedelta(days=30)
    p = {"ip": ip, "ids": ctx.scope_ids, "since": since}
    base = "e.client_id = ANY(:ids) AND e.ts >= :since AND (e.src_ip = CAST(:ip AS inet) OR e.dst_ip = CAST(:ip AS inet))"
    summary = (await ctx.db.execute(text(f"SELECT count(*) AS n, min(ts) AS first, max(ts) AS last FROM events e WHERE {base}"), p)).one()
    by_cat = (await ctx.db.execute(text(f"SELECT category, count(*) AS n FROM events e WHERE {base} GROUP BY 1 ORDER BY 2 DESC"), p)).all()
    peers = (await ctx.db.execute(text(f"""
        SELECT host(CASE WHEN e.src_ip = CAST(:ip AS inet) THEN e.dst_ip ELSE e.src_ip END) AS peer, count(*) AS n
        FROM events e WHERE {base} AND e.src_ip IS NOT NULL AND e.dst_ip IS NOT NULL
        GROUP BY 1 ORDER BY 2 DESC LIMIT 10"""), p)).all()
    # What the network knows about this host (latest DHCP / WiFi sightings).
    host_info = (await ctx.db.execute(text("""
        SELECT e.ts, e.category, e.action, e.src_mac::text AS mac, e.extra->>'hostname' AS hostname,
               e.extra->>'client_hostname' AS client_hostname, e.extra->>'ssid' AS ssid, e.extra->>'ap' AS ap,
               d.name AS device
        FROM events e JOIN devices d ON d.id = e.device_id
        WHERE e.client_id = ANY(:ids) AND e.ts >= :since AND e.src_ip = CAST(:ip AS inet) AND e.category IN ('dhcp', 'wifi')
        ORDER BY e.ts DESC LIMIT 5"""), p)).all()
    web = (await ctx.db.execute(text("""
        SELECT coalesce(rule, domain) AS name, (rule IS NOT NULL) AS is_app, sum(n) AS n,
               sum(coalesce(bytes_in, 0) + coalesce(bytes_out, 0)) AS bytes, max(bucket) AS last
        FROM events_web_1h WHERE client_id = ANY(:ids) AND bucket >= :wsince AND src_ip = CAST(:ip AS inet)
          AND (rule IS NOT NULL OR domain IS NOT NULL)
        GROUP BY 1, 2 ORDER BY 4 DESC, 3 DESC LIMIT 20"""), dict(p, wsince=datetime.now(UTC) - timedelta(days=7)))).all()
    # Identity as the UniFi controller knows it (polled network clients).
    identity = (await ctx.db.execute(text("""
        SELECT nc.hostname, nc.mac::text AS mac, nc.vendor, nc.network, nc.ssid, nc.ap, nc.is_wired, nc.first_seen,
               nc.last_seen, c.name AS client
        FROM network_clients nc JOIN clients c ON c.id = nc.client_id
        WHERE nc.client_id = ANY(:ids) AND nc.ip_internal = CAST(:ip AS inet) ORDER BY nc.last_seen DESC LIMIT 3"""), p)).all()
    # Remote-access VPN sessions that used this address (as the user's source or as the address handed out).
    vpn = (await ctx.db.execute(text("""
        SELECT s.user_name, s.started_at, s.ended_at, s.status, host(s.source_ip) = :ip AS as_source, d.name AS device
        FROM vpn_sessions s JOIN devices d ON d.id = s.device_id
        WHERE s.client_id = ANY(:ids) AND (s.source_ip = CAST(:ip AS inet) OR s.assigned_ip = CAST(:ip AS inet))
          AND s.last_seen_at >= :since
        ORDER BY coalesce(s.started_at, s.last_seen_at) DESC LIMIT 15"""), p)).all()
    security = (await ctx.db.execute(text(f"""
        SELECT count(*) FILTER (WHERE e.category = 'ids' AND e.action IS DISTINCT FROM 'ioc-match') AS ids,
               count(*) FILTER (WHERE e.outcome = 'blocked' AND e.category <> 'ids') AS blocked,
               count(*) FILTER (WHERE e.outcome = 'failure') AS failed,
               count(*) FILTER (WHERE e.action = 'ioc-match') AS intel
        FROM events e WHERE {base}"""), p)).one()
    top_ids = (await ctx.db.execute(text(f"""
        SELECT e.rule, count(*) AS n, max(e.ts) AS last FROM events e WHERE {base} AND e.category = 'ids'
          AND e.action IS DISTINCT FROM 'ioc-match' GROUP BY 1 ORDER BY 2 DESC LIMIT 5"""), p)).all()
    lq = LogQuery(range="30d", since=since, ip=ip)
    recent, _ = await _search(ctx, lq, raw=False)
    g = geo().lookup(ip) if addr.is_global else None
    return ctx.render("ip.html", ip=ip, internal=not addr.is_global, geo=g, summary=summary, by_cat=by_cat,
                      peers=peers, host_info=host_info, rows=recent[:50], lq=lq, web=web, identity=identity, vpn=vpn,
                      security=security, top_ids=top_ids)
