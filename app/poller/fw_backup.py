"""Local copies of the UniFi consoles' own backup files (.unf: full, restorable configuration), downloaded over the local
network. Read-only: only backups the console already made (its auto-backups) are listed and downloaded.

Verified 2026-10-11 on NW-HK (Network 10.6.106, local API key, pinned certificate):
  POST /proxy/network/api/s/default/cmd/backup {"cmd": "list-backups"}
       -> {data: [{filename "autobackup_10.6.106_20260930_1630_<ms>.unf", datetime, size, version, days, type, time}]}
  GET  /proxy/network/dl/autobackup/<filename> -> the file (21 MB, size as listed)
Through UniFi Site Manager the download times out (HTTP 408 DeviceTimeout, also for 1 MB byte ranges), so remote
consoles need a local path (site agent / RMM / VPN) before their backup files can be copied.

A .unf file holds every secret of the site (Wi-Fi and VPN keys, admin hashes), so it is stored encrypted (Fernet, a key
derived from SECRET_KEY for this purpose only) and only admins can download it."""

import base64
import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path

import httpx
from cryptography.fernet import Fernet

from app.config import get_settings
from app.drivers.base import PollError
from app.drivers.unifi import tls_fingerprint

NAME_RE = re.compile(r"^autobackup_[0-9A-Za-z._-]+\.unf$")


def _fernet() -> Fernet:
    key = hashlib.sha256(("firewall-backups:" + get_settings().secret_key).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt(data: bytes) -> bytes:
    return _fernet().encrypt(data)


def decrypt(token: bytes) -> bytes:
    return _fernet().decrypt(token)


async def _client(config: dict, secret: dict | None, transport=None) -> tuple[httpx.AsyncClient, str]:
    base = (config.get("base_url") or "").rstrip("/")
    key = (secret or {}).get("api_key")
    pinned = config.get("tls_fingerprint")
    if not base or not key or not pinned:
        raise PollError("local backups need base_url, an API key and a pinned certificate")
    if transport is None and await tls_fingerprint(base) != pinned:
        raise PollError("TLS certificate fingerprint changed since it was pinned; API key not sent")
    return httpx.AsyncClient(verify=False, timeout=300, transport=transport,
                             headers={"X-API-KEY": key, "Accept": "application/json"}), base + "/proxy/network"


async def list_backups(config: dict, secret: dict | None, transport=None) -> list[dict]:
    http, base = await _client(config, secret, transport)
    async with http:
        r = await http.post(f"{base}/api/s/{config.get('site') or 'default'}/cmd/backup", json={"cmd": "list-backups"})
        if r.status_code != 200:
            raise PollError(f"HTTP {r.status_code} listing backups")
        return [b for b in r.json().get("data", []) if isinstance(b, dict) and NAME_RE.match(str(b.get("filename") or ""))]


async def download(config: dict, secret: dict | None, filename: str, transport=None) -> bytes:
    if not NAME_RE.match(filename):
        raise PollError("unexpected backup file name")
    http, base = await _client(config, secret, transport)
    async with http:
        r = await http.get(f"{base}/dl/autobackup/{filename}")
        if r.status_code != 200:
            raise PollError(f"HTTP {r.status_code} downloading {filename}")
        return r.content


def taken_at(b: dict) -> datetime | None:
    if isinstance(b.get("time"), (int, float)):
        return datetime.fromtimestamp(b["time"] / 1000, UTC)
    try:
        return datetime.fromisoformat(str(b.get("datetime")).replace("Z", "+00:00"))
    except ValueError:
        return None


def store_file(root: Path, client_slug: str, device_id: int, filename: str, data: bytes) -> tuple[Path, str]:
    """Encrypted copy on disk; returns (path, sha256 of the original file)."""
    folder = root / client_slug / str(device_id)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / (filename + ".enc")
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(encrypt(data))
    tmp.replace(path)
    return path, hashlib.sha256(data).hexdigest()
