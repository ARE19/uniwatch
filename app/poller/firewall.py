"""Firewall policy snapshots (UniFi zone-based firewall), read-only, for the Rule & Policy report.

Verified 2026-10-08 on CTS KL (Network 10.6.106) through the Site Manager connector
(https://api.ui.com/v1/connector/consoles/<host id>/proxy/network/...) and available on a local console at
/proxy/network/... the same way; real trimmed responses in samples/unifi-firewall-policies-2026-10-08.json:
  GET v2/api/site/<site>/firewall-policies  [{_id, name, index (evaluation order), action ALLOW|BLOCK|REJECT, enabled,
      predefined, protocol, ip_version, logging, schedule {mode}, source / destination {zone_id, matching_target ANY|IP|...,
      ips, port_matching_type, ...}, hits, last_hit (ms)}]   hits / last_hit are absent on policies never hit
  GET v2/api/site/<site>/firewall/zone      [{_id, name, zone_key}]
Each fetch replaces the device's snapshot (deleted policies disappear)."""

import logging
from datetime import UTC, datetime

import httpx
from psycopg.types.json import Jsonb

from app.drivers.base import PollError
from app.drivers.unifi import tls_fingerprint

log = logging.getLogger("poller.firewall")
CONNECTOR = "https://api.ui.com/v1/connector/consoles/{host}/proxy/network"


async def _get_both(client: httpx.AsyncClient, base: str, site: str) -> tuple[list, list]:
    out = []
    for path in (f"/v2/api/site/{site}/firewall-policies", f"/v2/api/site/{site}/firewall/zone"):
        r = await client.get(base + path)
        if r.status_code in (401, 403):
            raise PollError(f"API key rejected (HTTP {r.status_code})")
        if r.status_code != 200:
            raise PollError(f"HTTP {r.status_code} for {path}")
        body = r.json()
        if not isinstance(body, list):
            raise PollError(f"unexpected response for {path}")
        out.append(body)
    return out[0], out[1]


async def fetch_connector(api_key: str, host_id: str, site: str = "default") -> tuple[list, list]:
    """Through the Site Manager connector (no VPN or port forward to the site)."""
    async with httpx.AsyncClient(timeout=60, headers={"X-API-KEY": api_key, "Accept": "application/json"}) as c:
        return await _get_both(c, CONNECTOR.format(host=host_id), site)


async def fetch_local(config: dict, secret: dict | None) -> tuple[list, list]:
    """From a locally polled console (pinned certificate, as the poller's other local calls)."""
    base = (config.get("base_url") or "").rstrip("/")
    key = (secret or {}).get("api_key")
    pinned = config.get("tls_fingerprint")
    if not base or not key or not pinned:
        raise PollError("firewall policies need base_url, an API key and a pinned certificate")
    if await tls_fingerprint(base) != pinned:
        raise PollError("TLS certificate fingerprint changed since it was pinned; API key not sent")
    async with httpx.AsyncClient(verify=False, timeout=60, headers={"X-API-KEY": key, "Accept": "application/json"}) as c:
        return await _get_both(c, base + "/proxy/network", config.get("site") or "default")


def normalize(p: dict) -> dict | None:
    if not isinstance(p, dict) or not p.get("_id"):
        return None
    last = p.get("last_hit")
    return {"policy_id": str(p["_id"]), "name": p.get("name"), "idx": p.get("index"), "action": p.get("action"),
            "enabled": p.get("enabled"), "predefined": p.get("predefined"), "protocol": p.get("protocol"),
            "ip_version": p.get("ip_version"), "logging": p.get("logging"),
            "source": p.get("source") if isinstance(p.get("source"), dict) else {},
            "destination": p.get("destination") if isinstance(p.get("destination"), dict) else {},
            "schedule": p.get("schedule") if isinstance(p.get("schedule"), dict) else {},
            "hits": p.get("hits") if isinstance(p.get("hits"), int) else None,
            "last_hit": datetime.fromtimestamp(last / 1000, UTC) if isinstance(last, int) and last > 0 else None}


async def store(conn, client_id: int, device_id: int, policies: list, zones: list, now: datetime) -> int:
    rows = [r for r in (normalize(p) for p in policies) if r]
    async with conn.transaction():
        await conn.execute("DELETE FROM firewall_policies WHERE device_id = %s", (device_id,))
        await conn.execute("DELETE FROM firewall_zones WHERE device_id = %s", (device_id,))
        for r in rows:
            await conn.execute("""
                INSERT INTO firewall_policies (device_id, policy_id, client_id, name, idx, action, enabled, predefined, protocol,
                    ip_version, logging, source, destination, schedule, hits, last_hit, fetched_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (device_id, policy_id) DO NOTHING""",
                (device_id, r["policy_id"], client_id, r["name"], r["idx"], r["action"], r["enabled"], r["predefined"],
                 r["protocol"], r["ip_version"], r["logging"], Jsonb(r["source"]), Jsonb(r["destination"]),
                 Jsonb(r["schedule"]), r["hits"], r["last_hit"], now))
        for z in zones:
            if isinstance(z, dict) and z.get("_id"):
                await conn.execute("""INSERT INTO firewall_zones (device_id, zone_id, client_id, name, zone_key, fetched_at)
                                      VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING""",
                                   (device_id, str(z["_id"]), client_id, z.get("name"), z.get("zone_key"), now))
    return len(rows)
