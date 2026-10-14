"""Client lists (device names) of consoles that are not polled locally, through the UniFi Site Manager connector, so
reports and Insights can show a device's name instead of its MAC. Read-only.

Verified 2026-10-08 on CTS KL (Network 10.6.106) through https://api.ui.com/v1/connector/consoles/<host id>/proxy/network:
  GET integration/v1/sites                         {data: [{id, internalReference ("default"), name}]}
  GET integration/v1/sites/<id>/clients?offset&limit  {offset, limit, count, totalCount,
      data: [{id, name, macAddress, ipAddress, type WIRED|WIRELESS, connectedAt, access, uplinkDeviceId}]}
The list holds the clients connected now; names are kept in network_clients after a device leaves.
`name` is what the UniFi UI shows: the alias set by an admin, else the device's own hostname."""

import httpx

from app.drivers.base import PollError
from app.parsers.util import to_ip, to_mac

CONNECTOR = "https://api.ui.com/v1/connector/consoles/{host}/proxy/network/integration/v1"
PAGE = 200


async def fetch_clients_connector(api_key: str, host_id: str, transport=None) -> list[dict]:
    async with httpx.AsyncClient(timeout=60, headers={"X-API-KEY": api_key, "Accept": "application/json"},
                                 transport=transport) as http:
        base = CONNECTOR.format(host=host_id)

        async def get(path, **params):
            r = await http.get(base + path, params=params)
            if r.status_code in (401, 403):
                raise PollError(f"Site Manager key rejected by the console (HTTP {r.status_code})")
            if r.status_code != 200:
                raise PollError(f"HTTP {r.status_code} for {path}")
            return r.json()

        out: list[dict] = []
        for site in (await get("/sites")).get("data", []):
            offset = 0
            while True:
                body = await get(f"/sites/{site['id']}/clients", offset=offset, limit=PAGE)
                rows = body.get("data") or []
                out += [r for r in rows if isinstance(r, dict)]
                offset += len(rows)
                if not rows or offset >= int(body.get("totalCount") or 0) or offset >= 5000:
                    break
        return out


async def store(conn, client_id: int, device_id: int, clients: list[dict], now) -> int:
    n = 0
    async with conn.transaction():
        for c in clients:
            mac = to_mac(c.get("macAddress"))
            if not mac:
                continue
            name = (c.get("name") or "").strip() or None
            await conn.execute("""
                INSERT INTO network_clients (client_id, device_id, mac, ip_internal, hostname, is_wired, first_seen, last_seen)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (device_id, mac) DO UPDATE SET ip_internal = coalesce(EXCLUDED.ip_internal, network_clients.ip_internal),
                    hostname = coalesce(EXCLUDED.hostname, network_clients.hostname), is_wired = EXCLUDED.is_wired,
                    last_seen = EXCLUDED.last_seen""",
                (client_id, device_id, mac, to_ip(c.get("ipAddress")), name,
                 {"WIRED": True, "WIRELESS": False}.get(c.get("type")), now, now))
            n += 1
    return n
