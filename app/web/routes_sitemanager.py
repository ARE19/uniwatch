"""Admin -> UniFi Site Manager: the API key of the Site Manager account (unifi.ui.com) whose consoles this server
monitors. Saved encrypted and never shown again; a saved key replaces UNIFI_SITE_MANAGER_API_KEY from .env and the
poller uses it from its next cycle. "Test connection" asks Site Manager how many consoles the key can see."""

import re

import httpx
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import text

from app import sitemanager_key
from app.audit import audit
from app.config import get_settings
from app.models.auth import ROLE_ADMIN
from app.web.deps import Ctx, check_csrf, require_role

router = APIRouter()
admin_only = require_role(ROLE_ADMIN)
KEY_RE = re.compile(r"^[A-Za-z0-9_\-\.=+/]{16,300}$")


async def _page(ctx: Ctx, status_code: int = 200, **kw):
    row = await sitemanager_key.saved(ctx.db)
    env = bool(get_settings().unifi_site_manager_api_key)
    stats = (await ctx.db.execute(text("SELECT count(*) AS consoles, max(last_sync) AS last_sync FROM sitemanager_hosts"))).first()
    return ctx.render("sitemanager_settings.html", status_code, row=row, source="web" if row else ("env" if env else None),
                      consoles=stats.consoles, last_sync=stats.last_sync, **kw)


async def _effective(ctx: Ctx) -> str:
    row = await sitemanager_key.saved(ctx.db)
    return (row or {}).get("key") or get_settings().unifi_site_manager_api_key


@router.get("/admin/site-manager")
async def page(saved: int = 0, removed: int = 0, ctx: Ctx = Depends(admin_only)):
    return await _page(ctx, saved=bool(saved), removed=bool(removed))


@router.post("/admin/site-manager")
async def save(request: Request, api_key: str = Form(""), ctx: Ctx = Depends(admin_only)):
    await check_csrf(request, ctx.session.csrf_token)
    key = api_key.strip()
    if not KEY_RE.match(key):
        return await _page(ctx, 400, errors=["API key: paste the key exactly as Site Manager shows it (no spaces)."])
    await ctx.db.execute(text("""
        INSERT INTO sitemanager_settings (id, api_key_enc, updated_at, updated_by) VALUES (1, :k, now(), :by)
        ON CONFLICT (id) DO UPDATE SET api_key_enc = :k, updated_at = now(), updated_by = :by"""),
        {"k": sitemanager_key.encode(key), "by": ctx.user.username})
    await audit(ctx.db, "sitemanager_key_set", request=request, user=ctx.user, details={"key": "changed"})
    await ctx.db.commit()
    return RedirectResponse("/admin/site-manager?saved=1", status_code=303)


@router.post("/admin/site-manager/remove")
async def remove(request: Request, ctx: Ctx = Depends(admin_only)):
    """Forget the saved key: the server goes back to UNIFI_SITE_MANAGER_API_KEY from .env (or to no Site Manager)."""
    await check_csrf(request, ctx.session.csrf_token)
    await ctx.db.execute(text("DELETE FROM sitemanager_settings"))
    await audit(ctx.db, "sitemanager_key_remove", request=request, user=ctx.user)
    await ctx.db.commit()
    return RedirectResponse("/admin/site-manager?removed=1", status_code=303)


@router.post("/admin/site-manager/test")
async def test(request: Request, ctx: Ctx = Depends(admin_only)):
    await check_csrf(request, ctx.session.csrf_token)
    key = await _effective(ctx)
    if not key:
        return await _page(ctx, 400, errors=["No API key is set."])
    try:
        n = await sitemanager_key.count_consoles(key)
        result, ok = f"connected: the key can see {n} console{'' if n == 1 else 's'}", True
    except httpx.HTTPStatusError as e:
        code = e.response.status_code
        result, ok = ("failed: Site Manager rejected the key (HTTP %d)" % code if code in (401, 403)
                      else "failed: Site Manager answered HTTP %d" % code), False
    except httpx.HTTPError as e:
        result, ok = f"failed: Site Manager could not be reached ({type(e).__name__})", False
    await audit(ctx.db, "sitemanager_key_test", request=request, user=ctx.user, details={"result": result}, success=ok)
    await ctx.db.commit()
    return await _page(ctx, test_result=result, test_ok=ok)
