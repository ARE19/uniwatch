"""Threat Intel: feed status, indicator lookup, recent matches; admins manage feeds."""

import ipaddress
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import text

from app.audit import audit
from app.intel import feeds as intel
from app.models.auth import ROLE_ADMIN, ROLE_ENGINEER
from app.web.deps import Ctx, check_csrf, require_role

router = APIRouter()
staff = require_role(ROLE_ADMIN, ROLE_ENGINEER)
admin_only = require_role(ROLE_ADMIN)


@router.get("/threat-intel")
async def threat_intel(ctx: Ctx = Depends(staff), q: str = ""):
    feeds = (await ctx.db.execute(text("""
        SELECT f.*, (SELECT count(*) FROM ioc_networks n WHERE n.feed_id = f.id) +
                    (SELECT count(*) FROM ioc_domains d WHERE d.feed_id = f.id) AS indicators
        FROM ioc_feeds f ORDER BY f.name"""))).all()
    lookup = None
    q = q.strip()
    if q:
        try:
            ip = str(ipaddress.ip_address(q))
            hits = (await ctx.db.execute(text("""SELECT f.name, n.net::text AS match FROM ioc_networks n JOIN ioc_feeds f ON f.id = n.feed_id
                                                 WHERE CAST(:ip AS inet) <<= n.net ORDER BY f.name"""), {"ip": ip})).all()
        except ValueError:
            hits = (await ctx.db.execute(text("""SELECT f.name, d.domain AS match FROM ioc_domains d JOIN ioc_feeds f ON f.id = d.feed_id
                                                 WHERE d.domain = lower(:d) ORDER BY f.name"""), {"d": q})).all()
        lookup = {"q": q, "hits": hits}
    # One row per indicator (FortiAnalyzer-style roll-up), with how often and when it was seen.
    matches = (await ctx.db.execute(text("""
        SELECT cl.name AS client, e.extra->>'value' AS value, max(e.extra->>'side') AS side,
               max(e.extra->>'feeds') AS feeds, count(*) AS hits, min(e.ts) AS first, max(e.ts) AS last,
               max(coalesce(e.src_country, e.dst_country)) AS country, string_agg(DISTINCT d.name, ', ') AS devices,
               (SELECT string_agg(DISTINCT o.action, ', ') FROM events o
                 WHERE o.id = ANY(array_agg((e.extra->>'matched_event_id')::bigint)) AND o.action IS NOT NULL) AS actions
        FROM events e JOIN devices d ON d.id = e.device_id JOIN clients cl ON cl.id = e.client_id
        WHERE e.action = 'ioc-match' AND e.client_id = ANY(:ids) AND e.ts > now() - interval '7 days'
        GROUP BY 1, 2 ORDER BY max(e.ts) DESC LIMIT 200"""), {"ids": ctx.scope_ids})).all()
    return ctx.render("threat_intel.html", feeds=feeds, lookup=lookup, matches=matches, is_admin=ctx.role == ROLE_ADMIN)


@router.post("/threat-intel/feeds")
async def add_feed(request: Request, name: str = Form(""), url: str = Form(""), format: str = Form("ip_list"),
                   ctx: Ctx = Depends(admin_only)):
    await check_csrf(request, ctx.session.csrf_token)
    u = urlparse(url.strip())
    if u.scheme != "https" or not u.netloc or not name.strip() or format not in ("ip_list", "hostfile", "spamhaus_json"):
        raise HTTPException(400, "Give a name, an https:// URL and a supported format.")
    await ctx.db.execute(text("INSERT INTO ioc_feeds (name, url, format) VALUES (:n, :u, :f)"),
                         {"n": name.strip()[:200], "u": url.strip(), "f": format})
    await audit(ctx.db, "intel_feed_add", request=request, user=ctx.user, target=name, details={"url": url, "format": format})
    await ctx.db.commit()
    return RedirectResponse("/threat-intel", status_code=303)


@router.post("/threat-intel/feeds/{feed_id}/{action}")
async def feed_action(feed_id: int, action: str, request: Request, ctx: Ctx = Depends(admin_only)):
    await check_csrf(request, ctx.session.csrf_token)
    name = (await ctx.db.execute(text("SELECT name FROM ioc_feeds WHERE id = :i"), {"i": feed_id})).scalar()
    if name is None:
        raise HTTPException(404, "No such feed.")
    if action == "toggle":
        await ctx.db.execute(text("UPDATE ioc_feeds SET enabled = NOT enabled WHERE id = :i"), {"i": feed_id})
    elif action == "delete":
        await ctx.db.execute(text("DELETE FROM ioc_feeds WHERE id = :i"), {"i": feed_id})
    elif action == "refresh":
        await ctx.db.commit()
        await intel.refresh([feed_id], role="web")
    else:
        raise HTTPException(404, "Unknown action.")
    await audit(ctx.db, f"intel_feed_{action}", request=request, user=ctx.user, target=name)
    await ctx.db.commit()
    return RedirectResponse("/threat-intel", status_code=303)
