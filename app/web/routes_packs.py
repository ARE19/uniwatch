"""Admin -> Report packs: upload a pack and its licence, see what is installed, remove a pack. See app/packs.py."""

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse

from app import packs
from app.audit import audit
from app.config import get_settings
from app.models.auth import ROLE_ADMIN
from app.web.deps import Ctx, check_csrf, require_role

router = APIRouter()
admin_only = require_role(ROLE_ADMIN)


def _page(ctx: Ctx, status_code: int = 200, **kw):
    packs.refresh()
    rows = packs.status()
    return ctx.render("packs.html", status_code, rows=rows, loaded=packs.loaded(),
                      enabled=bool((packs.SETTINGS or get_settings()).pack_public_key), **kw)


@router.get("/admin/packs")
async def packs_page(installed: str = "", removed: str = "", ctx: Ctx = Depends(admin_only)):
    return _page(ctx, installed=installed[:60], removed=removed[:60])


async def _read(f: UploadFile | None) -> bytes | None:
    if f is None or not f.filename:
        return None
    blob = await f.read(packs.MAX_BYTES + 1)
    if len(blob) > packs.MAX_BYTES:
        raise packs.PackError("The file is too large.")
    return blob or None


@router.post("/admin/packs")
async def upload(request: Request, pack: UploadFile | None = File(None), licence: UploadFile | None = File(None),
                 ctx: Ctx = Depends(admin_only)):
    await check_csrf(request, ctx.session.csrf_token)
    try:
        done = packs.install(await _read(pack), await _read(licence))
    except packs.PackError as e:
        await audit(ctx.db, "pack_install", request=request, user=ctx.user, details={"error": str(e)}, success=False)
        await ctx.db.commit()
        return _page(ctx, 400, errors=[str(e)])
    except OSError as e:
        return _page(ctx, 500, errors=[f"The pack folder on the server cannot be written ({type(e).__name__})."])
    await audit(ctx.db, "pack_install", request=request, user=ctx.user, target=done["pack"],
                details={"stored": done["stored"], "customer": done["customer"], "expires": done["expires"]})
    await ctx.db.commit()
    return RedirectResponse(f"/admin/packs?installed={done['pack']}", status_code=303)


@router.post("/admin/packs/{pack_id}/remove")
async def remove(pack_id: str, request: Request, ctx: Ctx = Depends(admin_only)):
    await check_csrf(request, ctx.session.csrf_token)
    if not packs.remove(pack_id):
        raise HTTPException(404, "No such pack.")
    await audit(ctx.db, "pack_remove", request=request, user=ctx.user, target=pack_id)
    await ctx.db.commit()
    return RedirectResponse(f"/admin/packs?removed={pack_id}", status_code=303)
