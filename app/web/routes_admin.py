import re

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select

from app.audit import audit
from app.models import AuditLog, Client, Role, User, UserClient
from app.models.auth import ROLE_ADMIN, ROLE_CLIENT_READONLY
from app.security import passwords, sessions
from app.web.deps import Ctx, check_csrf, require_role

router = APIRouter(prefix="/admin")
admin_only = require_role(ROLE_ADMIN)
USERNAME_RE = re.compile(r"^[A-Za-z0-9._@-]{2,64}$")


async def _users_page(ctx: Ctx, status_code: int = 200, **kw):
    users = (await ctx.db.execute(select(User).order_by(func.lower(User.username)))).scalars().all()
    roles = (await ctx.db.execute(select(Role).order_by(Role.id))).scalars().all()
    clients = (await ctx.db.execute(select(Client).order_by(Client.name))).scalars().all()
    return ctx.render("admin_users.html", status_code, users=users, roles=roles, clients=clients, **kw)


@router.get("/users")
async def users(ctx: Ctx = Depends(admin_only)):
    return await _users_page(ctx)


@router.post("/users")
async def create_user(
    request: Request,
    username: str = Form(""),
    display_name: str = Form(""),
    role_id: int = Form(0),
    password: str = Form(""),
    ctx: Ctx = Depends(admin_only),
):
    await check_csrf(request, ctx.session.csrf_token)
    form = await request.form()
    client_ids = [int(c) for c in form.getlist("client_ids") if str(c).isdigit()]
    username = username.strip()
    db = ctx.db
    errors = []
    role = await db.get(Role, role_id)
    if role is None:
        errors.append("Pick a role.")
    if not USERNAME_RE.match(username):
        errors.append("Username: 2-64 characters, letters, digits and . _ @ - only.")
    elif (await db.execute(select(User).where(func.lower(User.username) == username.lower()))).first():
        errors.append("That username already exists.")
    errors += passwords.password_problems(password, username)
    if role is not None and role.name == ROLE_CLIENT_READONLY and not client_ids:
        errors.append("A client_readonly user must be assigned at least one client.")
    if errors:
        return await _users_page(ctx, 400, errors=errors)

    user = User(
        username=username,
        display_name=display_name.strip()[:200],
        password_hash=passwords.hash_password(password),
        role_id=role.id,
        must_change_password=True,
    )
    db.add(user)
    await db.flush()
    for cid in client_ids:
        db.add(UserClient(user_id=user.id, client_id=cid))
    await audit(db, "user_create", request=request, user=ctx.user, target=username,
                details={"role": role.name, "client_ids": client_ids})
    await db.commit()
    return RedirectResponse("/admin/users", status_code=303)


async def _target(ctx: Ctx, user_id: int) -> User:
    target = await ctx.db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "No such user.")
    return target


@router.post("/users/{user_id}/active")
async def toggle_active(user_id: int, request: Request, ctx: Ctx = Depends(admin_only)):
    await check_csrf(request, ctx.session.csrf_token)
    target = await _target(ctx, user_id)
    if target.id == ctx.user.id:
        raise HTTPException(400, "You cannot deactivate your own account.")
    target.is_active = not target.is_active
    if not target.is_active:
        await sessions.end_all_sessions(ctx.db, target.id)
    await audit(ctx.db, "user_activate" if target.is_active else "user_deactivate", request=request,
                user=ctx.user, target=target.username)
    await ctx.db.commit()
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/users/{user_id}/reset-mfa")
async def reset_mfa(user_id: int, request: Request, ctx: Ctx = Depends(admin_only)):
    await check_csrf(request, ctx.session.csrf_token)
    target = await _target(ctx, user_id)
    target.totp_enabled = False
    target.totp_secret_enc = None
    target.totp_last_step = None
    await sessions.end_all_sessions(ctx.db, target.id)
    await audit(ctx.db, "mfa_reset", request=request, user=ctx.user, target=target.username)
    await ctx.db.commit()
    if target.id == ctx.user.id:
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/users/{user_id}/delete")
async def delete_user(user_id: int, request: Request, ctx: Ctx = Depends(admin_only)):
    """Remove an account. Its sessions, client assignments and personal saved items go with it; the audit log,
    comments and report history keep the username as text."""
    await check_csrf(request, ctx.session.csrf_token)
    target = await _target(ctx, user_id)
    if target.id == ctx.user.id:
        raise HTTPException(400, "You cannot delete your own account.")
    # (the deleting admin can never delete themselves, so an active admin always remains)
    details = {"role": target.role.name, "display_name": target.display_name}
    username = target.username
    await sessions.end_all_sessions(ctx.db, target.id)
    await ctx.db.delete(target)
    await audit(ctx.db, "user_delete", request=request, user=ctx.user, target=username, details=details)
    await ctx.db.commit()
    return RedirectResponse("/admin/users", status_code=303)


@router.get("/audit")
async def audit_view(ctx: Ctx = Depends(admin_only), action: str = "", username: str = "", limit: int = 200):
    q = select(AuditLog).order_by(AuditLog.ts.desc(), AuditLog.id.desc()).limit(max(1, min(limit, 1000)))
    if action:
        q = q.where(AuditLog.action == action)
    if username:
        q = q.where(func.lower(AuditLog.username) == username.lower())
    rows = (await ctx.db.execute(q)).scalars().all()
    actions = (await ctx.db.execute(select(AuditLog.action).distinct().order_by(AuditLog.action))).scalars().all()
    return ctx.render("admin_audit.html", rows=rows, actions=actions, action=action, username=username)
