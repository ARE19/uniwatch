"""System → Storage & forwarding (admin): per-client usage, retention and quota; forwarding targets."""

import ipaddress
import re
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import text

from app.audit import audit
from app.forwarder import send, storage_usage, syslog_wrap
from app.models.auth import ROLE_ADMIN
from app.web.deps import Ctx, check_csrf, require_role

router = APIRouter()
admin_only = require_role(ROLE_ADMIN)
HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")


@router.get("/admin/storage")
async def storage(ctx: Ctx = Depends(admin_only)):
    usage = await storage_usage(ctx.db)
    targets = (await ctx.db.execute(text("""SELECT t.*, c.name AS client FROM forwarding_targets t
                                            LEFT JOIN clients c ON c.id = t.client_id ORDER BY t.name"""))).all()
    return ctx.render("storage.html", usage=usage, targets=targets)


@router.post("/admin/storage/clients/{client_id}")
async def set_client_storage(client_id: int, request: Request, retention_days: int = Form(...), quota_gb: str = Form(""),
                             ctx: Ctx = Depends(admin_only)):
    await check_csrf(request, ctx.session.csrf_token)
    if not 1 <= retention_days <= 3650:
        raise HTTPException(400, "Retention must be 1-3650 days.")
    try:
        quota = float(quota_gb) if quota_gb.strip() else None
    except ValueError:
        raise HTTPException(400, "Quota must be a number of GB.")
    if quota is not None and quota <= 0:
        raise HTTPException(400, "Quota must be positive.")
    res = await ctx.db.execute(text("UPDATE clients SET retention_days = :r, quota_gb = :q WHERE id = :i"),
                               {"r": retention_days, "q": quota, "i": client_id})
    if res.rowcount == 0:
        raise HTTPException(404, "No such client.")
    await audit(ctx.db, "client_storage_set", request=request, user=ctx.user, client_id=client_id,
                details={"retention_days": retention_days, "quota_gb": quota})
    await ctx.db.commit()
    return RedirectResponse("/admin/storage", status_code=303)


@router.post("/admin/storage/forwarding")
async def add_target(request: Request, name: str = Form(""), host: str = Form(""), port: int = Form(514),
                     protocol: str = Form("udp"), format: str = Form("cef"), min_severity: str = Form("low"),
                     client_id: str = Form(""), ctx: Ctx = Depends(admin_only)):
    await check_csrf(request, ctx.session.csrf_token)
    host = host.strip()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not HOST_RE.match(host):
            raise HTTPException(400, "Host must be an IP address or hostname.")
    if (not name.strip() or not 1 <= port <= 65535 or protocol not in ("udp", "tcp", "tls")
            or format not in ("raw", "cef", "json") or min_severity not in ("low", "medium", "high", "critical")):
        raise HTTPException(400, "Invalid forwarding target.")
    cid = int(client_id) if client_id.isdigit() else None
    await ctx.db.execute(text("""INSERT INTO forwarding_targets (client_id, name, host, port, protocol, format, min_severity)
                                 VALUES (:c, :n, :h, :p, :pr, :f, :s)"""),
                         {"c": cid, "n": name.strip()[:100], "h": host, "p": port, "pr": protocol, "f": format, "s": min_severity})
    await audit(ctx.db, "forwarding_add", request=request, user=ctx.user, target=name,
                details={"host": host, "port": port, "protocol": protocol, "format": format, "client_id": cid})
    await ctx.db.commit()
    return RedirectResponse("/admin/storage", status_code=303)


@router.post("/admin/storage/forwarding/{tid}/{action}")
async def target_action(tid: int, action: str, request: Request, ctx: Ctx = Depends(admin_only)):
    await check_csrf(request, ctx.session.csrf_token)
    t = (await ctx.db.execute(text("SELECT * FROM forwarding_targets WHERE id = :i"), {"i": tid})).first()
    if t is None:
        raise HTTPException(404, "No such target.")
    result = None
    if action == "toggle":
        await ctx.db.execute(text("UPDATE forwarding_targets SET enabled = NOT enabled WHERE id = :i"), {"i": tid})
    elif action == "delete":
        await ctx.db.execute(text("DELETE FROM forwarding_targets WHERE id = :i"), {"i": tid})
    elif action == "test":
        try:
            await send(dict(t._mapping), [syslog_wrap("Uniwatch forwarding test", datetime.now(UTC), "uniwatch")])
            result = "sent"
        except Exception as e:  # noqa: BLE001
            result = f"failed: {type(e).__name__}: {e}"[:200]
        await ctx.db.execute(text("UPDATE forwarding_targets SET last_error = :e WHERE id = :i"),
                             {"e": None if result == "sent" else result, "i": tid})
    else:
        raise HTTPException(404, "Unknown action.")
    await audit(ctx.db, f"forwarding_{action}", request=request, user=ctx.user, target=t.name, details={"result": result} if result else None)
    await ctx.db.commit()
    return RedirectResponse("/admin/storage", status_code=303)
