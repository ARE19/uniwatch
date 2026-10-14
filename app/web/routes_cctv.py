"""CCTV -> Access log: who opened UniFi Protect, when, from where and for how long, and which camera recordings
(timelines) or settings they viewed. Every role, always client-scoped; times in each site's own time zone."""

from datetime import timedelta
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text

from app.web.deps import Ctx, current

router = APIRouter()
RANGES = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30), "90d": timedelta(days=90)}
KINDS = {"all": "Everything", "access": "Sign-ins", "recordings": "Recordings viewed", "settings": "Settings & devices"}
KIND_SQL = {"all": "true", "access": "a.kind = 'access'", "recordings": "a.action = 'cameraTimelineViewed'",
            "settings": "a.kind = 'adminActivity' AND a.action <> 'cameraTimelineViewed'"}
LIMIT = 1000


def duration(seconds: float | None) -> str:
    if seconds is None:
        return ""
    s = int(round(seconds))
    d, r = divmod(s, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    return " ".join([f"{d}d"] * bool(d) + [f"{h}h"] * bool(h) + [f"{m}m"] * bool(m) + [f"{s}s"] * bool(s and not d)) or "0s"


@router.get("/cctv")
async def cctv(ctx: Ctx = Depends(current), rng: str = Query("7d", alias="range"), kind: str = "all", user: str = "",
               camera: str = ""):
    rng = rng if rng in RANGES else "7d"
    kind = kind if kind in KINDS else "all"
    (now,) = (await ctx.db.execute(text("SELECT now()"))).one()
    p = {"ids": ctx.scope_ids, "since": now - RANGES[rng], "user": user.strip(), "camera": camera.strip()}
    where = f"""a.client_id = ANY(:ids) AND a.ts >= :since AND {KIND_SQL[kind]}
                AND (:user = '' OR a.user_name = :user) AND (:camera = '' OR a.camera_name = :camera)"""
    rows = [dict(r._mapping) for r in (await ctx.db.execute(text(f"""
        SELECT a.ts, a.ended_at, a.kind, a.action, a.title, a.user_name, host(a.ip) AS ip, a.platform, a.camera_name,
               a.duration_s, a.message, c.name AS client, c.timezone
        FROM protect_activity a JOIN clients c ON c.id = a.client_id
        WHERE {where} ORDER BY a.ts DESC LIMIT {LIMIT}"""), p)).all()]
    for r in rows:
        tz = ZoneInfo(r["timezone"] or "UTC")
        r["local"] = r["ts"].astimezone(tz).strftime("%Y-%m-%d %H:%M:%S")
        r["local_end"] = r["ended_at"].astimezone(tz).strftime("%H:%M:%S") if r["ended_at"] else ""
        r["dur"] = duration(r["duration_s"])
    stats = (await ctx.db.execute(text(f"""
        SELECT count(*) FILTER (WHERE a.kind = 'access') AS sessions, count(DISTINCT a.user_name) AS users,
               count(*) FILTER (WHERE a.action = 'cameraTimelineViewed') AS recordings,
               count(DISTINCT host(a.ip)) AS ips, max(a.ts) AS last
        FROM protect_activity a WHERE {where}"""), p)).one()
    users = [r.user_name for r in (await ctx.db.execute(text("""
        SELECT DISTINCT user_name FROM protect_activity WHERE client_id = ANY(:ids) AND ts >= :since AND user_name IS NOT NULL
        ORDER BY 1"""), p)).all()]
    cameras = [r.camera_name for r in (await ctx.db.execute(text("""
        SELECT DISTINCT camera_name FROM protect_activity WHERE client_id = ANY(:ids) AND ts >= :since AND camera_name IS NOT NULL
        ORDER BY 1"""), p)).all()]
    consoles = (await ctx.db.execute(text("""
        SELECT c.name AS client, p.status, p.version, p.last_sync FROM protect_consoles p JOIN clients c ON c.id = p.client_id
        WHERE p.client_id = ANY(:ids) ORDER BY (p.status = 'ok') DESC, c.name"""), p)).all()
    return ctx.render("cctv.html", rows=rows, stats=stats, users=users, cameras=cameras, consoles=consoles,
                      ranges=list(RANGES), range=rng, kinds=KINDS, kind=kind, sel_user=p["user"], sel_camera=p["camera"],
                      limit=LIMIT)
