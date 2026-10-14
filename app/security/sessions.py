import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models import User, WebSession

COOKIE_NAME = "cls_session"
PRELOGIN_COOKIE = "cls_prelogin"  # double-submit CSRF token for the login form only


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


async def create_session(db: AsyncSession, user: User, ip: str | None, user_agent: str | None) -> tuple[str, WebSession]:
    """Returns (cookie token, row). Only the token's hash is stored."""
    s = get_settings()
    token = new_token()
    row = WebSession(
        token_hash=_hash(token),
        user_id=user.id,
        mfa_ok=False,
        csrf_token=new_token(),
        ip=ip,
        user_agent=(user_agent or "")[:400],
        expires_at=datetime.now(UTC) + timedelta(hours=s.session_max_hours),
    )
    db.add(row)
    await db.flush()
    return token, row


async def rotate_session(db: AsyncSession, row: WebSession) -> tuple[str, WebSession]:
    """Issue a new token for an existing session (after MFA) to prevent session fixation."""
    token = new_token()
    new = WebSession(
        token_hash=_hash(token),
        user_id=row.user_id,
        mfa_ok=row.mfa_ok,
        csrf_token=new_token(),
        ip=row.ip,
        user_agent=row.user_agent,
        expires_at=row.expires_at,
    )
    await db.delete(row)
    db.add(new)
    await db.flush()
    return token, new


async def load_session(db: AsyncSession, token: str | None) -> WebSession | None:
    if not token:
        return None
    row = await db.get(WebSession, _hash(token))
    if row is None:
        return None
    now = datetime.now(UTC)
    idle = timedelta(minutes=get_settings().session_idle_minutes)
    if row.expires_at <= now or row.last_seen_at + idle <= now:
        await db.delete(row)
        await db.commit()
        return None
    if now - row.last_seen_at > timedelta(minutes=1):
        row.last_seen_at = now
        await db.commit()
    return row


async def end_session(db: AsyncSession, row: WebSession) -> None:
    await db.delete(row)


async def end_all_sessions(db: AsyncSession, user_id: int) -> None:
    await db.execute(delete(WebSession).where(WebSession.user_id == user_id))


async def purge_expired(db: AsyncSession) -> None:
    await db.execute(delete(WebSession).where(WebSession.expires_at <= datetime.now(UTC)))


def csrf_ok(expected: str | None, supplied: str | None) -> bool:
    return bool(expected) and bool(supplied) and secrets.compare_digest(expected, supplied)


async def user_for_session(db: AsyncSession, row: WebSession) -> User | None:
    user = (await db.execute(select(User).where(User.id == row.user_id))).scalar_one_or_none()
    return user if user and user.is_active else None
