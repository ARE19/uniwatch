"""Poller driver interface: poll(device config, secret) -> metrics + inventory + network clients."""

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings


class PollError(Exception):
    pass


@dataclass
class DeviceSnapshot:
    mac: str
    name: str | None = None
    model: str | None = None
    type: str | None = None
    ip: str | None = None
    firmware: str | None = None
    upgradable: bool | None = None
    firmware_latest: str | None = None
    connected: bool | None = None
    is_gateway: bool = False
    cpu_pct: float | None = None
    mem_pct: float | None = None
    temp_c: float | None = None
    uptime_s: int | None = None
    client_count: int | None = None
    wan_ip: str | None = None
    extra: dict = field(default_factory=dict)


@dataclass
class NetClient:
    mac: str
    ip: str | None = None
    hostname: str | None = None
    ssid: str | None = None
    ap_mac: str | None = None
    is_wired: bool | None = None
    vendor: str | None = None
    network: str | None = None
    rssi: int | None = None
    last_seen: datetime | None = None
    signal_dbm: int | None = None      # Wi-Fi signal strength as UniFi shows it (e.g. -67); rssi is signal minus noise


@dataclass
class WanPort:
    name: str                      # controller's WAN id: "WAN", "WAN2", ...
    alive: bool
    label: str | None = None       # network name, e.g. "Internet 2"
    ifname: str | None = None      # e.g. eth7
    ip: str | None = None
    is_uplink: bool | None = None  # currently carrying traffic
    media: str | None = None
    latency_ms: float | None = None
    availability: float | None = None
    # cumulative counters (rx = from the internet / download, tx = upload)
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    rx_packets: int | None = None
    tx_packets: int | None = None
    rx_dropped: int | None = None
    tx_dropped: int | None = None
    rx_errors: int | None = None
    tx_errors: int | None = None
    link_speed_mbps: int | None = None


@dataclass
class IpsecTunnel:
    name: str
    peer: str | None
    enabled: bool
    up: bool | None = None         # None = cannot be told apart (several enabled tunnels, some down)
    interface: str | None = None   # WAN port name as in WanPort.name: WAN, WAN2, ...
    vpn_type: str | None = None
    established_at: datetime | None = None


@dataclass
class PollResult:
    devices: list[DeviceSnapshot]
    clients: list[NetClient]
    controller: dict = field(default_factory=dict)
    tls_fingerprint: str | None = None
    wans: list[WanPort] = field(default_factory=list)          # WAN ports of the polled gateway
    internet_up: bool | None = None                            # controller's overall internet health
    internet_latency_ms: float | None = None
    ipsec: list[IpsecTunnel] = field(default_factory=list)


class PollDriver:
    name = "base"

    async def poll(self, config: dict, secret: dict | None) -> PollResult:  # pragma: no cover - interface
        raise NotImplementedError


# ---- credential storage (encrypted with SECRET_KEY, separate key derivation from TOTP) ------------
def _fernet() -> Fernet:
    key = hashlib.sha256(("poller-credentials:" + get_settings().secret_key).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt_secret(value: dict) -> str:
    return _fernet().encrypt(json.dumps(value).encode()).decode()


def decrypt_secret(token: str) -> dict | None:
    try:
        return json.loads(_fernet().decrypt(token.encode()))
    except (InvalidToken, ValueError):
        return None
