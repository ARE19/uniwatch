"""Fleet: every UniFi console of the Site Manager account on one page (MSP overview), problems first."""

from datetime import timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import text

from app.web.deps import Ctx, current

router = APIRouter()


@router.get("/fleet")
async def fleet(ctx: Ctx = Depends(current)):
    p = {"ids": ctx.scope_ids}
    (now,) = (await ctx.db.execute(text("SELECT now()"))).one()
    p["day"], p["hour"] = now - timedelta(hours=24), now - timedelta(hours=1)
    rows = [dict(r._mapping) for r in (await ctx.db.execute(text("""
        SELECT h.host_id, h.name, h.model, h.state, h.isp, h.last_sync, h.counts, h.client_id, h.device_id,
               c.name AS client, c.slug,
               (d.poll_config->>'driver') = 'unifi' AS local_api,
               (SELECT max(dd.last_log_at) FROM devices dd WHERE dd.client_id = h.client_id) AS last_log,
               (SELECT w.state FROM wan_state w WHERE w.device_id = h.device_id AND w.wan_name = 'internet' AND w.ended_at IS NULL) AS internet,
               (SELECT count(*) FROM alerts a WHERE a.client_id = h.client_id AND a.status <> 'resolved') AS open_alerts,
               (SELECT count(*) FROM device_inventory i WHERE i.poll_device_id = h.device_id) AS dev_total,
               (SELECT count(*) FROM device_inventory i WHERE i.poll_device_id = h.device_id AND i.connected) AS dev_online,
               (SELECT count(*) FROM device_inventory i WHERE i.poll_device_id = h.device_id AND i.upgradable) AS dev_updates,
               (SELECT round(avg(m.avg_latency)::numeric, 1) FROM isp_metrics m WHERE m.device_id = h.device_id AND m.period_s = 300 AND m.ts >= :hour) AS latency,
               (SELECT max(m.packet_loss) FROM isp_metrics m WHERE m.device_id = h.device_id AND m.period_s = 300 AND m.ts >= :hour) AS loss,
               (SELECT bool_and(coalesce(m.uptime, 0) = 0 AND coalesce(m.avg_latency, 0) = 0) FROM isp_metrics m
                 WHERE m.device_id = h.device_id AND m.period_s = 300 AND m.ts >= :hour) AS no_health
        FROM sitemanager_hosts h JOIN clients c ON c.id = h.client_id LEFT JOIN devices d ON d.id = h.device_id
        WHERE h.client_id = ANY(:ids)"""), p)).all()]
    wans = {}
    for w in (await ctx.db.execute(text("""
            SELECT w.device_id, w.wan_name, w.label, host(w.ip) AS ip, w.state,
                   EXISTS (SELECT 1 FROM wan_state x WHERE x.device_id = w.device_id AND x.wan_name = w.wan_name AND x.state = 'up') AS ever_up
            FROM wan_state w WHERE w.ended_at IS NULL AND w.wan_name <> 'internet' AND w.client_id = ANY(:ids)
            ORDER BY w.wan_name"""), p)).all():
        wans.setdefault(w.device_id, []).append(dict(w._mapping))
    # Internet availability over 24 h from the state intervals (same basis as the dashboard).
    avail = {r.device_id: r for r in (await ctx.db.execute(text("""
        SELECT device_id,
               sum(extract(epoch FROM LEAST(coalesce(ended_at, now()), now()) - GREATEST(started_at, :day))) FILTER (WHERE state = 'up') AS up_s,
               sum(extract(epoch FROM LEAST(coalesce(ended_at, now()), now()) - GREATEST(started_at, :day))) FILTER (WHERE state = 'down') AS down_s
        FROM wan_state WHERE wan_name = 'internet' AND client_id = ANY(:ids) AND coalesce(ended_at, now()) > :day
        GROUP BY 1"""), p)).all()}
    for r in rows:
        r["wans"] = wans.get(r["device_id"], [])
        a = avail.get(r["device_id"])
        known = float((a.up_s or 0) + (a.down_s or 0)) if a else 0
        r["availability"] = (float(a.up_s or 0) / known * 100) if known else None
        r["syslog"] = bool(r["last_log"] and now - r["last_log"] < timedelta(minutes=60))
        problems = []
        if r["state"] != "connected":
            problems.append("console offline / not reachable by the cloud")
        if r["internet"] == "down":
            problems.append("internet down")
        if any(w["state"] == "down" and w["ever_up"] for w in r["wans"]):
            problems.append("a WAN link is down")
        if r["dev_total"] and r["dev_online"] < r["dev_total"]:
            problems.append(f"{r['dev_total'] - r['dev_online']} device(s) offline")
        if (r["loss"] or 0) >= 5:
            problems.append(f"packet loss {r['loss']:g} %")
        r["problems"] = problems
        r["severity"] = 2 if (r["state"] != "connected" or r["internet"] == "down") else 1 if problems else 0
    rows.sort(key=lambda r: (-r["severity"], -int(r["open_alerts"] or 0), r["name"].lower()))
    summary = {"total": len(rows), "problems": sum(1 for r in rows if r["severity"]),
               "offline": sum(1 for r in rows if r["state"] != "connected"),
               "updates": sum(int(r["dev_updates"] or 0) for r in rows),
               "alerts": sum(int(r["open_alerts"] or 0) for r in rows),
               "synced": max((r["last_sync"] for r in rows), default=None)}
    return ctx.render("fleet.html", rows=rows, summary=summary)
