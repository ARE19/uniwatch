"""CCTV access log from UniFi Protect, through the Site Manager connector. Read-only.

Verified 2026-10-09 (Protect 7.2.105 / 6.2.88) on 15 consoles via
https://api.ui.com/v1/connector/consoles/<host id>/proxy/protect (samples/unifi-protect-access-events-2026-10-09.json):
  GET integration/v1/meta/info                       {"applicationVersion": "7.2.105"}
  GET api/events?start=<ms>&end=<ms>&limit=&orderDirection=DESC&types=access&types=adminActivity
      access:        {id, type "access", start, end, user, metadata {userName, ip, clientPlatform},
                      description {eventMetadata {title "Full Session"}, messageRaw "{userLink} accessed UniFi Protect
                      using the web for 2s.", messageKeys [{key, text}]}}
      adminActivity: {id, type "adminActivity", start, camera, metadata {userName, userAction "cameraTimelineViewed",
                      clientData {start, end}}, description {eventMetadata {title}, messageRaw "{userLink} viewed the
                      timeline of {deviceLink} for 6m 48s.", messageKeys [..., {key "deviceLink", text <camera name>}]}}
A console without Protect, or one the key may not read (HTTP 403), is recorded in protect_consoles and skipped."""

import json
import re
from datetime import UTC, datetime

import httpx

from app.parsers.util import to_ip

BASE = "https://api.ui.com/v1/connector/consoles/{host}/proxy/protect"
TYPES = ("access", "adminActivity")
LIMIT = 2000


class NoProtect(Exception):
    """The console answers but has no Protect (or the key may not read it)."""


async def fetch_activity(api_key: str, host_id: str, since_ms: int, until_ms: int, transport=None) -> tuple[str | None, list[dict]]:
    async with httpx.AsyncClient(timeout=60, headers={"X-API-KEY": api_key, "Accept": "application/json"},
                                 transport=transport) as http:
        base = BASE.format(host=host_id)
        r = await http.get(base + "/integration/v1/meta/info")
        if r.status_code == 403:
            raise NoProtect("denied")
        if r.status_code != 200:
            raise NoProtect("no protect")
        version = (r.json() or {}).get("applicationVersion")
        params = [("start", since_ms), ("end", until_ms), ("limit", LIMIT), ("orderDirection", "DESC")]
        params += [("types", t) for t in TYPES]
        r = await http.get(base + "/api/events", params=params)
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code} for Protect events")
        body = r.json()
        return version, [e for e in body if isinstance(e, dict) and e.get("type") in TYPES] if isinstance(body, list) else []


def _ms(v) -> datetime | None:
    return datetime.fromtimestamp(float(v) / 1000, UTC) if isinstance(v, (int, float)) and v > 0 else None


def parse(e: dict) -> dict | None:
    """One Protect event as a protect_activity row (without host/client), or None when it is not usable."""
    start = _ms(e.get("start")) or _ms(e.get("timestamp"))
    if not e.get("id") or start is None:
        return None
    md, desc = e.get("metadata") or {}, e.get("description") or {}
    meta = desc.get("eventMetadata") or {}
    keys = {k.get("key"): k for k in desc.get("messageKeys") or [] if isinstance(k, dict)}
    text = re.sub(r"\{(\w+)\}", lambda m: str((keys.get(m.group(1)) or {}).get("text") or m.group(1)), desc.get("messageRaw") or "")
    end = _ms(e.get("end"))
    cd = md.get("clientData") or {}
    if e["type"] == "access":
        dur = (end - start).total_seconds() if end else None
    elif isinstance(cd.get("start"), (int, float)) and isinstance(cd.get("end"), (int, float)):
        dur = max(0.0, (cd["end"] - cd["start"]) / 1000)
    else:
        dur = None
    cam = keys.get("deviceLink") or {}
    return {"event_id": str(e["id"]), "ts": start, "ended_at": end, "kind": e["type"],
            "action": md.get("userAction") or meta.get("subCategory") or e["type"], "title": meta.get("title"),
            "user_name": md.get("userName") or (keys.get("userLink") or {}).get("text"), "user_ref": e.get("user"),
            "ip": to_ip(md.get("ip")), "platform": md.get("clientPlatform"),
            "camera_ref": e.get("camera") or (cam.get("params") or {}).get("deviceId"),
            "camera_name": cam.get("text") if cam.get("text") not in (None, "unknown device") else None,
            "duration_s": dur, "message": text or meta.get("title") or e["type"], "raw": e}


async def store(conn, host_id: str, client_id: int, device_id: int | None, events: list[dict]) -> int:
    n = 0
    async with conn.transaction():
        for e in events:
            row = parse(e)
            if row is None:
                continue
            await conn.execute("""
                INSERT INTO protect_activity (host_id, event_id, client_id, device_id, ts, ended_at, kind, action, title,
                    user_name, user_ref, ip, platform, camera_ref, camera_name, duration_s, message, raw)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (host_id, event_id) DO UPDATE SET ended_at = EXCLUDED.ended_at, duration_s = EXCLUDED.duration_s,
                    message = EXCLUDED.message, raw = EXCLUDED.raw, client_id = EXCLUDED.client_id,
                    device_id = EXCLUDED.device_id""",
                (host_id, row["event_id"], client_id, device_id, row["ts"], row["ended_at"], row["kind"], row["action"],
                 row["title"], row["user_name"], row["user_ref"], row["ip"], row["platform"], row["camera_ref"],
                 row["camera_name"], row["duration_s"], row["message"], json.dumps(row["raw"])))
            n += 1
    return n
