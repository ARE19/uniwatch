from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import audit, client_ip, recent_failures
from app.config import get_settings
from app.db import get_db
from app.models import User, WebSession
from app.security import passwords, sessions, totp
from app.web.deps import Ctx, check_csrf, current, pending_mfa, templates

router = APIRouter()


def _set_session_cookie(resp, token: str) -> None:
    resp.set_cookie(
        sessions.COOKIE_NAME, token, httponly=True, secure=get_settings().cookie_secure, samesite="lax", path="/"
    )


def _login_page(request: Request, error: str | None = None, status_code: int = 200, username: str = ""):
    token = sessions.new_token()
    resp = templates.TemplateResponse(
        request, "login.html", {"error": error, "csrf_token": token, "username": username}, status_code=status_code
    )
    resp.set_cookie(
        sessions.PRELOGIN_COOKIE, token, httponly=True, secure=get_settings().cookie_secure, samesite="strict",
        path="/login", max_age=3600,
    )
    return resp


@router.get("/login")
async def login_form(request: Request):
    return _login_page(request)


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    csrf_token: str = Form(""),
    db: AsyncSession = Depends(get_db),
):
    s = get_settings()
    username = username.strip()[:64]
    if not sessions.csrf_ok(request.cookies.get(sessions.PRELOGIN_COOKIE), csrf_token):
        return _login_page(request, "The form expired. Please try again.", 403, username)
    if not username or not password:
        return _login_page(request, "Enter your username and password.", 400, username)

    if await recent_failures(db, "login", username, s.login_window_minutes) >= s.login_max_failures:
        await audit(db, "login_locked", request=request, username=username, success=False)
        await db.commit()
        return _login_page(request, "Too many failed attempts. Try again later.", 429, username)

    user = (await db.execute(select(User).where(func.lower(User.username) == username.lower()))).scalar_one_or_none()
    usable = user is not None and user.is_active
    if not passwords.verify_password(user.password_hash if usable else None, password):
        reason = "unknown_user" if user is None else ("inactive" if not user.is_active else "bad_password")
        await audit(db, "login", request=request, user=user, username=username, success=False, details={"reason": reason})
        await db.commit()
        return _login_page(request, "Invalid username or password.", 401, username)

    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(password)
    token, _row = await sessions.create_session(db, user, client_ip(request), request.headers.get("user-agent"))
    await audit(db, "login", request=request, user=user, details={"stage": "password"})
    await db.commit()

    resp = RedirectResponse("/mfa", status_code=303)
    _set_session_cookie(resp, token)
    resp.delete_cookie(sessions.PRELOGIN_COOKIE, path="/login")
    return resp


def _mfa_page(ctx: Ctx, error: str | None = None, status_code: int = 200):
    user = ctx.user
    if user.totp_enabled:
        return ctx.render("mfa_verify.html", status_code, error=error)
    secret = totp.decrypt_secret(user.totp_secret_enc) if user.totp_secret_enc else None
    uri = totp.provisioning_uri(secret, user.username) if secret else None
    return ctx.render("mfa_enroll.html", status_code, error=error, secret=secret, qr=totp.qr_svg(uri) if uri else None)


@router.get("/mfa")
async def mfa_form(ctx: Ctx = Depends(pending_mfa)):
    user = ctx.user
    # Enrolment secret is generated once and kept until confirmed, so a page reload shows the same QR code.
    if not user.totp_enabled and (not user.totp_secret_enc or totp.decrypt_secret(user.totp_secret_enc) is None):
        user.totp_secret_enc = totp.encrypt_secret(totp.new_secret())
        await ctx.db.commit()
    return _mfa_page(ctx)


@router.post("/mfa")
async def mfa_submit(code: str = Form(""), ctx: Ctx = Depends(pending_mfa)):
    await check_csrf(ctx.request, ctx.session.csrf_token)
    db, user, row = ctx.db, ctx.user, ctx.session
    secret = totp.decrypt_secret(user.totp_secret_enc) if user.totp_secret_enc else None
    step = totp.verify_code(secret, code, user.totp_last_step) if secret else None

    if step is None:
        row.mfa_failures += 1
        await audit(db, "mfa", request=ctx.request, user=user, success=False,
                    details={"enrolment": not user.totp_enabled, "failures": row.mfa_failures})
        if row.mfa_failures >= get_settings().mfa_max_failures:
            await sessions.end_session(db, row)
            await audit(db, "mfa_lockout", request=ctx.request, user=user, success=False)
            await db.commit()
            resp = RedirectResponse("/login", status_code=303)
            resp.delete_cookie(sessions.COOKIE_NAME, path="/")
            return resp
        await db.commit()
        return _mfa_page(ctx, "That code is not valid. Check your authenticator app's clock and try again.", 401)

    user.totp_last_step = step
    if not user.totp_enabled:
        user.totp_enabled = True
        await audit(db, "mfa_enrolled", request=ctx.request, user=user)
    row.mfa_ok = True
    token, _new = await sessions.rotate_session(db, row)
    user.last_login_at = datetime.now(UTC)
    await audit(db, "login", request=ctx.request, user=user, details={"stage": "mfa"})
    await db.commit()

    resp = RedirectResponse("/account/password" if user.must_change_password else "/", status_code=303)
    _set_session_cookie(resp, token)
    return resp


@router.post("/logout")
async def logout(request: Request, db: AsyncSession = Depends(get_db)):
    row = await sessions.load_session(db, request.cookies.get(sessions.COOKIE_NAME))
    if row is not None:
        await check_csrf(request, row.csrf_token)
        user = await db.get(User, row.user_id)
        await sessions.end_session(db, row)
        await audit(db, "logout", request=request, user=user)
        await db.commit()
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(sessions.COOKIE_NAME, path="/")
    return resp


@router.get("/account/password")
async def password_form(ctx: Ctx = Depends(current)):
    return ctx.render("account_password.html")


@router.post("/account/password")
async def password_submit(
    current_password: str = Form(""),
    new_password: str = Form(""),
    confirm_password: str = Form(""),
    ctx: Ctx = Depends(current),
):
    await check_csrf(ctx.request, ctx.session.csrf_token)
    user, db = ctx.user, ctx.db
    errors = []
    if not passwords.verify_password(user.password_hash, current_password):
        errors.append("Current password is wrong.")
    if new_password != confirm_password:
        errors.append("New passwords do not match.")
    if new_password == current_password:
        errors.append("New password must differ from the current one.")
    errors += passwords.password_problems(new_password, user.username)
    if errors:
        await audit(db, "password_change", request=ctx.request, user=user, success=False)
        await db.commit()
        return ctx.render("account_password.html", 400, errors=errors)

    user.password_hash = passwords.hash_password(new_password)
    user.password_changed_at = datetime.now(UTC)
    user.must_change_password = False
    # Sign out every other session for this user.
    await db.execute(
        delete(WebSession).where(WebSession.user_id == user.id, WebSession.token_hash != ctx.session.token_hash)
    )
    await audit(db, "password_change", request=ctx.request, user=user)
    await db.commit()
    return ctx.render("account_password.html", message="Password changed. Other sessions were signed out.")
