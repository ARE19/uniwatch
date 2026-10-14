"""Admin -> Mail (SMTP): the server used for alert and report e-mails. Saved settings replace SMTP_* from .env; the password
is stored encrypted and never shown again; "Send test e-mail" checks delivery with the effective settings."""

import asyncio
import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import text

from app import mail
from app.audit import audit
from app.config import get_settings
from app.drivers.base import encrypt_secret
from app.models.auth import ROLE_ADMIN
from app.web.deps import Ctx, check_csrf, require_role

router = APIRouter()
admin_only = require_role(ROLE_ADMIN)
HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
EMAIL_RE = re.compile(r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$")


async def _page(ctx: Ctx, status_code: int = 200, **kw):
    row = await mail.saved(ctx.db)
    env = get_settings()
    eff = mail.apply(env, row)
    return ctx.render("mail.html", status_code, row=row, eff=eff, source="web" if row else ("env" if env.smtp_host else None),
                      has_password=bool(eff.smtp_password), **kw)


@router.get("/admin/mail")
async def mail_page(saved: int = 0, ctx: Ctx = Depends(admin_only)):
    return await _page(ctx, saved=bool(saved))


@router.post("/admin/mail")
async def save(request: Request, host: str = Form(""), port: int = Form(587), username: str = Form(""),
               password: str = Form(""), clear_password: str = Form(""), from_addr: str = Form(""),
               starttls: str = Form(""), subject_prefix: str = Form(""), ctx: Ctx = Depends(admin_only)):
    await check_csrf(request, ctx.session.csrf_token)
    host, username, from_addr = host.strip(), username.strip(), from_addr.strip()
    subject_prefix = " ".join(subject_prefix.split())            # one line
    errors = []
    if not HOST_RE.match(host):
        errors.append("SMTP server: a host name such as smtp.office365.com.")
    if not 1 <= port <= 65535:
        errors.append("Port: 1-65535.")
    addr = re.search(r"<([^>]+)>\s*$", from_addr)
    if not EMAIL_RE.match(addr.group(1) if addr else from_addr):
        errors.append("From: an e-mail address, optionally with a name: Uniwatch <logserver@example.com>.")
    if len(subject_prefix) > 80:
        errors.append("Subject prefix: at most 80 characters.")
    if len(username) > 200 or len(from_addr) > 300 or len(password) > 500:
        errors.append("Value too long.")
    if errors:
        return await _page(ctx, 400, errors=errors)
    old = await mail.saved(ctx.db)
    if password:
        pw_enc = encrypt_secret({"password": password})
    elif clear_password or not username:
        pw_enc = None
    elif old:
        pw_enc = old["password_enc"]
    else:                                               # first save from the .env values: keep the .env password
        env_pw = get_settings().smtp_password
        pw_enc = encrypt_secret({"password": env_pw}) if env_pw else None
    await ctx.db.execute(text("""
        INSERT INTO mail_settings (id, host, port, username, password_enc, from_addr, starttls, subject_prefix, updated_at, updated_by)
        VALUES (1, :h, :p, :u, :pw, :f, :t, :sp, now(), :by)
        ON CONFLICT (id) DO UPDATE SET host = :h, port = :p, username = :u, password_enc = :pw, from_addr = :f,
            starttls = :t, subject_prefix = :sp, updated_at = now(), updated_by = :by"""),
        {"h": host, "p": port, "u": username, "pw": pw_enc, "f": from_addr, "t": bool(starttls), "sp": subject_prefix,
         "by": ctx.user.username})
    await audit(ctx.db, "mail_settings_set", request=request, user=ctx.user, target=host,
                details={"port": port, "username": username, "from": from_addr, "starttls": bool(starttls),
                         "subject_prefix": subject_prefix,
                         "password": "changed" if password else ("cleared" if pw_enc is None else "unchanged")})
    await ctx.db.commit()
    return RedirectResponse("/admin/mail?saved=1", status_code=303)


@router.post("/admin/mail/reset")
async def reset(request: Request, ctx: Ctx = Depends(admin_only)):
    """Forget the saved settings: e-mail goes back to the SMTP_* values in .env."""
    await check_csrf(request, ctx.session.csrf_token)
    await ctx.db.execute(text("DELETE FROM mail_settings"))
    await audit(ctx.db, "mail_settings_reset", request=request, user=ctx.user)
    await ctx.db.commit()
    return RedirectResponse("/admin/mail", status_code=303)


@router.post("/admin/mail/test")
async def test(request: Request, to: str = Form(""), ctx: Ctx = Depends(admin_only)):
    await check_csrf(request, ctx.session.csrf_token)
    to = to.strip()
    if not EMAIL_RE.match(to):
        return await _page(ctx, 400, errors=["Test recipient: one e-mail address."], test_to=to)
    st = await mail.effective(get_settings(), ctx.db)
    if not st.smtp_host:
        return await _page(ctx, 400, errors=["No SMTP server is configured."], test_to=to)
    try:
        await asyncio.to_thread(mail.send_test, st, to)
        result = "sent"
    except Exception as e:  # noqa: BLE001 - shown to the admin
        result = f"failed: {type(e).__name__}: {e}"[:300]
    await audit(ctx.db, "mail_test", request=request, user=ctx.user, target=to, details={"result": result},
                success=result == "sent")
    await ctx.db.commit()
    return await _page(ctx, test_result=result, test_to=to)
