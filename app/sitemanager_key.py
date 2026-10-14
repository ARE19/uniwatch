"""The UniFi Site Manager API key in effect: the one saved in System Settings -> UniFi Site Manager when there is one
(stored encrypted in sitemanager_settings), otherwise UNIFI_SITE_MANAGER_API_KEY from .env.

The poller asks at the start of every cycle, so a key saved, replaced or removed in the portal applies within a minute
without restarting anything."""

from sqlalchemy import text

from app.drivers.base import decrypt_secret, encrypt_secret

API = "https://api.ui.com"


def decode(api_key_enc: str | None) -> str:
    return (decrypt_secret(api_key_enc) or {}).get("key", "") if api_key_enc else ""


def encode(key: str) -> str:
    return encrypt_secret({"key": key})


async def saved(session) -> dict | None:
    """The saved row (SQLAlchemy session), without the key itself."""
    row = (await session.execute(text("SELECT api_key_enc, updated_at, updated_by FROM sitemanager_settings WHERE id = 1"))).first()
    return {"key": decode(row.api_key_enc), "updated_at": row.updated_at, "updated_by": row.updated_by} if row else None


async def saved_key(conn) -> str:
    """The saved key for the services (psycopg connection); '' = none saved."""
    cur = await conn.execute("SELECT api_key_enc FROM sitemanager_settings WHERE id = 1")
    row = await cur.fetchone()
    return decode(row[0]) if row else ""


async def count_consoles(key: str, transport=None) -> int:
    """How many consoles the key can see (GET /v1/hosts, read-only; the same call the sync makes). Raises httpx.HTTPError."""
    import httpx
    n, token = 0, None
    async with httpx.AsyncClient(base_url=API, timeout=20, headers={"X-API-KEY": key, "Accept": "application/json"},
                                 transport=transport) as h:
        for _ in range(50):
            r = await h.get("/v1/hosts", params={"pageSize": 100, **({"nextToken": token} if token else {})})
            r.raise_for_status()
            body = r.json()
            n += len(body.get("data") or [])
            token = body.get("nextToken")
            if not token:
                break
    return n
