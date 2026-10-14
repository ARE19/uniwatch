from fastapi import Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from psycopg.types.json import Jsonb

from app.models import User


def client_ip(request: Request | None) -> str | None:
    # uvicorn runs with --proxy-headers, so request.client is the real address forwarded by Caddy.
    return request.client.host if request is not None and request.client else None


async def audit(
    db: AsyncSession,
    action: str,
    *,
    request: Request | None = None,
    user: User | None = None,
    username: str | None = None,
    success: bool = True,
    target: str | None = None,
    client_id: int | None = None,
    details: dict | None = None,
) -> None:
    """Append an audit row to the current transaction (the caller commits).
    Plain INSERT without RETURNING: the web role may append to the audit log but (unless staff) not read it,
    and RETURNING would require read access to the new row."""
    await db.execute(
        text("""INSERT INTO audit_log (user_id, username, client_id, action, success, target, ip, user_agent, details)
                VALUES (:uid, :uname, :cid, :action, :ok, :target, :ip, :ua, :details)"""),
        {"uid": user.id if user else None, "uname": user.username if user else (username or None), "cid": client_id,
         "action": action, "ok": success, "target": target, "ip": client_ip(request),
         "ua": request.headers.get("user-agent", "")[:400] if request is not None else None,
         "details": Jsonb(details) if details is not None else None},
    )


async def recent_failures(db: AsyncSession, action: str, username: str, minutes: int) -> int:
    # A SECURITY DEFINER function: the web role cannot read the audit log, and this runs before login.
    return (await db.execute(text("SELECT login_failures(:u, :a, :m)"), {"u": username, "a": action, "m": minutes})).scalar_one()
