"""Database engines.

Two roles, two engines:
- "app": ingest and background services (receiver, parser, poller, reporter, alerts). Full DML on the tables.
- "web": the web UI. Least privilege: no direct access to the log hypertables (it sees them only through
  the security-barrier views in schema `scoped`, which shadow them via search_path), and row-level security
  on every other client table. Its tenant scope comes from two settings applied at the start of EVERY
  transaction: app.user_id and app.staff. Until a request authenticates, they deny everything."""

from collections.abc import AsyncIterator

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session

from app.config import get_settings

_engines: dict[str, AsyncEngine] = {}
_makers: dict[str, async_sessionmaker[AsyncSession]] = {}


def engine(role: str = "app") -> AsyncEngine:
    if role not in _engines:
        s = get_settings()
        options = "-c timezone=UTC" + (" -c search_path=scoped,public" if role == "web" else "")
        _engines[role] = create_async_engine(
            s.db_url(web=role == "web"), pool_size=5, max_overflow=5, pool_pre_ping=True,
            connect_args={"options": options},
        )
        _makers[role] = async_sessionmaker(_engines[role], expire_on_commit=False, info={"role": role})
    return _engines[role]


def sessionmaker(role: str = "app") -> async_sessionmaker[AsyncSession]:
    engine(role)
    return _makers[role]


@event.listens_for(Session, "after_begin")
def _apply_scope(session, transaction, connection) -> None:
    """Every web transaction starts with the caller's scope (deny-all until authenticated)."""
    if session.info.get("role") != "web":
        return
    connection.execute(text("SELECT set_config('app.user_id', :u, true), set_config('app.staff', :s, true)"),
                       {"u": str(session.info.get("user_id", 0)), "s": "on" if session.info.get("staff") else "off"})


async def apply_scope(session: AsyncSession, user_id: int, staff: bool) -> None:
    """Bind an authenticated user to a web session (now, and for every later transaction)."""
    session.info["user_id"], session.info["staff"] = user_id, staff
    await session.execute(text("SELECT set_config('app.user_id', :u, true), set_config('app.staff', :s, true)"),
                          {"u": str(user_id), "s": "on" if staff else "off"})


async def get_db() -> AsyncIterator[AsyncSession]:
    """Web request session (web role, deny-all until apply_scope)."""
    async with sessionmaker("web")() as session:
        yield session


async def dispose() -> None:
    for e in _engines.values():
        await e.dispose()
    _engines.clear()
    _makers.clear()
