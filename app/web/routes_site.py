"""Site overview: everything about one client site on one page (gateway, internet / WAN, site-to-site VPN, devices and
access points, open alerts, configuration changes, CCTV, latest reports). Every role, client-scoped; times in the
site's own time zone."""

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy import text

from app.web.deps import Ctx, current
from app.web.routes_sources import PRODUCTS

router = APIRouter()
SEV = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"


@router.get("/site")
async def site_pick(ctx: Ctx = Depends(current)):
    """The selected client's overview, or a list of sites to choose from."""
    if ctx.selected:
        return RedirectResponse(f"/site/{ctx.selected.id}", status_code=303)
    return ctx.render("site_pick.html", sites=sorted(ctx.clients, key=lambda c: c.name.lower()))


async def _rows(ctx: Ctx, sql: str, **p) -> list[dict]:
    return [dict(r._mapping) for r in (await ctx.db.execute(text(sql), p)).all()]


@router.get("/site/{client_id}")
async def site(client_id: int, ctx: Ctx = Depends(current)):
    c = next((x for x in ctx.clients if x.id == client_id), None)
    if c is None:
        raise HTTPException(404, "No such site.")
    p = {"c": client_id}
    (now,) = (await ctx.db.execute(text("SELECT now()"))).one()
    p["hour"], p["day"] = now - timedelta(hours=1), now - timedelta(days=1)
    gateways = await _rows(ctx, """
        SELECT d.id, d.name, d.model, d.firmware, d.last_log_at, st.state, st.started_at AS since, st.reason
        FROM devices d LEFT JOIN device_state st ON st.device_id = d.id AND st.ended_at IS NULL
        WHERE d.client_id = :c AND d.is_active ORDER BY d.name""", **p)
    wans = await _rows(ctx, """
        SELECT w.wan_name, w.label, host(w.ip) AS ip, w.state, w.started_at, d.name AS device
        FROM wan_state w JOIN devices d ON d.id = w.device_id
        WHERE w.client_id = :c AND w.ended_at IS NULL ORDER BY (w.wan_name = 'internet') DESC, w.wan_name""", **p)
    isp = (await ctx.db.execute(text("""
        SELECT round(avg(m.avg_latency)::numeric, 1) AS latency, max(m.packet_loss) AS loss, max(h.isp) AS isp
        FROM sitemanager_hosts h LEFT JOIN isp_metrics m ON m.device_id = h.device_id AND m.period_s = 300 AND m.ts >= :hour
        WHERE h.client_id = :c"""), p)).one()
    tunnels = await _rows(ctx, """
        SELECT replace(i.tunnel_name, 'ipsec:', '') AS name, i.status, i.peer, host(i.local_ip) AS local_ip, i.interface,
               i.established_at, i.updated_at
        FROM vpn_tunnel_info i WHERE i.client_id = :c ORDER BY 1""", **p)
    devices = await _rows(ctx, """
        SELECT i.name, i.type, i.model, i.firmware, i.upgradable, i.firmware_latest, i.connected, i.client_count, i.uptime_s,
               coalesce((i.extra->>'eol')::boolean, false) AS eol, i.extra->'uplink'->>'device' AS uplink,
               i.extra->'uplink'->>'port' AS uplink_port
        FROM device_inventory i JOIN devices g ON g.id = i.poll_device_id
        WHERE g.client_id = :c ORDER BY i.connected NULLS FIRST, i.type, i.name""", **p)
    for d in devices:
        d["product"] = PRODUCTS.get((d["type"] or "").lower(), d["type"] or "")
    alerts = await _rows(ctx, f"""
        SELECT id, title, severity, status, first_seen, last_seen FROM alerts
        WHERE client_id = :c AND status <> 'resolved' ORDER BY {SEV}, last_seen DESC LIMIT 15""", **p)
    resolved_24h = (await ctx.db.execute(text(
        "SELECT count(*) FROM alerts WHERE client_id = :c AND status = 'resolved' AND resolved_at >= :day"), p)).scalar()
    changes = await _rows(ctx, """
        SELECT cc.ts, cc.admin_user, cc.summary, d.name AS device FROM config_changes cc JOIN devices d ON d.id = cc.device_id
        WHERE cc.client_id = :c ORDER BY cc.ts DESC LIMIT 10""", **p)
    cctv = (await ctx.db.execute(text("""
        SELECT (SELECT status FROM protect_consoles WHERE client_id = :c ORDER BY last_sync DESC LIMIT 1) AS status,
               (SELECT count(*) FROM protect_activity WHERE client_id = :c AND ts >= :day AND kind = 'access') AS sign_ins,
               (SELECT count(*) FROM protect_activity WHERE client_id = :c AND ts >= :day AND action = 'cameraTimelineViewed') AS viewed,
               (SELECT max(ts) FROM protect_activity WHERE client_id = :c) AS last"""), p)).one()
    reports = await _rows(ctx, """
        SELECT id, report_type, period_start, period_end, status, finished_at FROM report_runs
        WHERE client_id = :c ORDER BY created_at DESC LIMIT 5""", **p)
    last_log = max((g["last_log_at"] for g in gateways if g["last_log_at"]), default=None)
    internet = next((w for w in wans if w["wan_name"] == "internet"), None)
    summary = {
        "internet": internet["state"] if internet else None,
        "wan_down": sum(1 for w in wans if w["wan_name"] != "internet" and w["state"] == "down"),
        "vpn_total": len(tunnels), "vpn_down": sum(1 for t in tunnels if t["status"] != "established"),
        "dev_total": len(devices), "dev_offline": sum(1 for d in devices if d["connected"] is False),
        "updates": sum(1 for d in devices if d["upgradable"]), "eol": sum(1 for d in devices if d["eol"]),
        "alerts": len(alerts), "alerts_high": sum(1 for a in alerts if a["severity"] in ("critical", "high")),
        "resolved_24h": resolved_24h, "logs_ok": bool(last_log and now - last_log < timedelta(minutes=15)),
    }
    from app.reports.data import BUNDLE_TITLES, TITLES, report_types
    report_types()                                   # loads the report packs' titles
    return ctx.render("site.html", site=c, tz=c.timezone, gateways=gateways, wans=wans, isp=isp, tunnels=tunnels,
                      devices=devices, alerts=alerts, changes=changes, cctv=cctv, reports=reports, last_log=last_log,
                      summary=summary, report_titles={**TITLES, **BUNDLE_TITLES})
