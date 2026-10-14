import re
from dataclasses import dataclass, field
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import Depends, HTTPException, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import apply_scope, get_db
from app.models import Client, Company, User, UserClient, WebSession
from app.models.auth import ALL_ROLES, ROLE_CLIENT_READONLY
from app.security import sessions
from app.web import menu

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


def fmt_ts(dt, tz: str | None = None) -> str:
    """Stored UTC -> display time zone (client's, else the default)."""
    if dt is None:
        return ""
    z = ZoneInfo(tz or get_settings().default_timezone)
    return dt.astimezone(z).strftime("%Y-%m-%d %H:%M:%S %Z")


def fmt_ts_short(dt, tz: str | None = None) -> str:
    """Compact form for dense tables; the zone is shown once in the top bar."""
    if dt is None:
        return ""
    return dt.astimezone(ZoneInfo(tz or get_settings().default_timezone)).strftime("%b %d %H:%M:%S")


templates.env.filters["ts"] = fmt_ts
templates.env.filters["ts_short"] = fmt_ts_short


def fmt_bytes(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


templates.env.filters["bsize"] = fmt_bytes

# UniFi names VPN clients "<person>'s Desktop" (every real CTS KL/SG name has this form). Show just the person; the
# stored name is unchanged, so search and filters still use it.
_DEVICE_SUFFIX = re.compile(r"^(?P<person>.+?)['’]s (?:Desktop|Laptop|PC|Computer|Mac|MacBook|iPhone|iPad|Phone|Mobile|Android|Tablet)$")


def person(name: str | None) -> str:
    if not name:
        return ""
    m = _DEVICE_SUFFIX.match(name.strip())
    return m["person"] if m else name


templates.env.filters["person"] = person
templates.env.filters["fromjson_list"] = lambda v: __import__("json").loads(v) if isinstance(v, str) else (v or [])
templates.env.globals["app_name"] = lambda: get_settings().app_name
templates.env.globals["default_tz"] = lambda: get_settings().default_timezone


def _licence_notices() -> list[str]:
    """Shown to admins on every page: a licence that ends soon or has ended (app/packs.py)."""
    from app import packs
    try:
        return packs.expiry_notices()
    except Exception:  # noqa: BLE001 - a reminder must never break a page
        return []


templates.env.globals["licence_notices"] = _licence_notices


SCOPE_COOKIE = "cls_scope"


class Redirect(Exception):
    """Raised by dependencies to send the browser elsewhere (login, MFA, password change)."""

    def __init__(self, url: str):
        self.url = url


@dataclass
class Ctx:
    request: Request
    db: AsyncSession
    session: WebSession
    user: User
    # Client scope (FortiAnalyzer "ADOM"): what this user may see, and what is selected right now.
    clients: list[Client] = field(default_factory=list)      # clients the user may select
    selected: Client | None = None                            # None = all of `clients` (or the company's sites)
    companies: list[Company] = field(default_factory=list)    # companies with at least one of `clients`
    company: Company | None = None                            # a company picked instead of one client

    @property
    def role(self) -> str:
        return self.user.role.name

    @property
    def is_staff(self) -> bool:
        return self.role != ROLE_CLIENT_READONLY

    @property
    def scope_ids(self) -> list[int]:
        """Client ids every data query must be limited to (never empty-means-all)."""
        if self.selected:
            return [self.selected.id]
        if self.company:
            return [c.id for c in self.clients if c.company_id == self.company.id]
        return [c.id for c in self.clients]

    @property
    def scope_label(self) -> str:
        return self.selected.name if self.selected else (self.company.name if self.company else "All clients")

    @property
    def tz(self) -> str:
        return self.selected.timezone if self.selected else get_settings().default_timezone

    def render(self, template: str, status_code: int = 200, **kw):
        kw.setdefault("user", self.user)
        kw.setdefault("csrf_token", self.session.csrf_token)
        kw.setdefault("scope_clients", self.clients)
        kw.setdefault("scope_selected", self.selected)
        kw.setdefault("scope_tz", self.tz)
        kw.setdefault("scope_label", self.scope_label)
        kw.setdefault("scope_companies", self.companies)
        kw.setdefault("scope_company", self.company)
        kw.setdefault("nav", self.request.url.path)
        kw.setdefault("menu", menu.build(self.request.url.path, dict(self.request.query_params), self.role))
        # The app shell (menu, client picker, sign-out) only exists once both factors are done.
        kw.setdefault("shell", bool(self.session.mfa_ok))
        return templates.TemplateResponse(self.request, template, kw, status_code=status_code)


async def _load_scope(ctx: "Ctx") -> None:
    q = select(Client).order_by(Client.name)
    if ctx.role == ROLE_CLIENT_READONLY:
        q = q.join(UserClient, UserClient.client_id == Client.id).where(UserClient.user_id == ctx.user.id)
    ctx.clients = list((await ctx.db.execute(q)).scalars())
    wanted = ctx.request.cookies.get(SCOPE_COOKIE, "")
    ctx.selected = next((c for c in ctx.clients if str(c.id) == wanted), None)
    ids = {c.company_id for c in ctx.clients if c.company_id}
    if ids:
        ctx.companies = list((await ctx.db.execute(select(Company).where(Company.id.in_(ids)).order_by(Company.name))).scalars())
    ctx.company = next((g for g in ctx.companies if f"g{g.id}" == wanted), None)


async def _load(request: Request, db: AsyncSession) -> tuple[WebSession, User] | None:
    row = await sessions.load_session(db, request.cookies.get(sessions.COOKIE_NAME))
    if row is None:
        return None
    user = await sessions.user_for_session(db, row)
    if user is None:
        await sessions.end_session(db, row)
        await db.commit()
        return None
    return row, user


async def pending_mfa(request: Request, db: AsyncSession = Depends(get_db)) -> Ctx:
    """Password accepted, second factor not yet."""
    loaded = await _load(request, db)
    if loaded is None:
        raise Redirect("/login")
    row, user = loaded
    if row.mfa_ok:
        raise Redirect("/")
    return Ctx(request, db, row, user)


async def current(request: Request, db: AsyncSession = Depends(get_db)) -> Ctx:
    """Fully authenticated (password + TOTP). Forces a pending password change first."""
    loaded = await _load(request, db)
    if loaded is None:
        raise Redirect("/login")
    row, user = loaded
    if not row.mfa_ok:
        raise Redirect("/mfa")
    if user.must_change_password and request.url.path not in ("/account/password", "/logout"):
        raise Redirect("/account/password")
    ctx = Ctx(request, db, row, user)
    # Tell the database who is asking BEFORE any client data is read: row-level security and the scoped
    # views derive the visible clients from this user (and nothing the browser sends).
    await apply_scope(db, user.id, user.role.name != ROLE_CLIENT_READONLY)
    await _load_scope(ctx)
    return ctx


def require_role(*roles: str):
    assert all(r in ALL_ROLES for r in roles)

    async def dep(ctx: Ctx = Depends(current)) -> Ctx:
        if ctx.role not in roles:
            raise HTTPException(status_code=403, detail="Your role does not allow this page.")
        return ctx

    return dep


async def check_csrf(request: Request, expected: str) -> None:
    supplied = request.headers.get("x-csrf-token")
    if supplied is None:
        form = await request.form()
        supplied = form.get("csrf_token")
    if not sessions.csrf_ok(expected, supplied if isinstance(supplied, str) else None):
        raise HTTPException(status_code=403, detail="Form expired or invalid. Reload the page and try again.")
