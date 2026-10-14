"""UniFi Network controller (UniFi OS console) driver.

Verified 2026-10-06 against UniFi Network 10.6.106 on UniFi OS 5.1.33 (UDM Pro SE), API key auth
(X-API-KEY header), endpoints:
  /proxy/network/api/s/<site>/stat/sysinfo   controller version
  /proxy/network/api/s/<site>/stat/health    subsystem status; 'wan' carries wan_ip
  /proxy/network/api/s/<site>/stat/device    per adopted device: mac, name, model, type, ip, version,
                                              upgradable, upgrade_to_firmware, state (1 = connected),
                                              system-stats {cpu, mem}, temperatures [{name, value}],
                                              uptime, num_sta
  /proxy/network/api/s/<site>/stat/sta       connected clients: mac, ip, hostname, essid, ap_mac,
                                              is_wired, oui, network, rssi/signal, last_seen
  gateway device (verified 2026-10-07):       last_wan_interfaces {"WAN2": {"alive": true, "ip": ...}},
                                              wan1/wan2 {name (ifname), is_uplink, media, latency, availability,
                                              speed, cumulative rx/tx_bytes, rx/tx_packets, rx/tx_dropped, rx/tx_errors}
  stat/health 'www':                          status ("ok"), latency
  stat/health 'vpn':                          site_to_site_num_active / site_to_site_num_inactive (counts only)
  /proxy/network/api/s/<site>/rest/networkconf  purpose wan (name, wan_networkgroup) and
                                              purpose site-vpn (name, ipsec_peer_ip, enabled, vpn_type)
  POST /proxy/network/v2/api/site/<site>/traffic-flows   (verified 2026-10-07) body {timestampFrom, timestampTo (ms),
                                              pageNumber, pageSize}; filters on record `time`, newest first; pageSize up
                                              to at least 5000; returns {data, has_next, total_element_count}. Records
                                              of still-open flows can update for a minute or two, so collection lags.
Fields not in a response are left empty, never guessed. The console uses a self-signed certificate,
so trust is pinned to its SHA-256 fingerprint on first successful poll (trust on first use)."""

import asyncio
import hashlib
import ssl
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from app.drivers.base import DeviceSnapshot, IpsecTunnel, NetClient, PollDriver, PollError, PollResult, WanPort
from app.parsers.util import to_ip, to_mac

GATEWAY_TYPES = {"udm", "ugw", "uxg"}


def _f(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _i(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def parse_devices(data: list[dict], wan_ip: str | None) -> list[DeviceSnapshot]:
    out = []
    for d in data:
        mac = to_mac(d.get("mac"))
        if not mac:
            continue
        stats = d.get("system-stats") or {}
        temps = [_f(t.get("value")) for t in d.get("temperatures") or [] if _f(t.get("value")) is not None]
        is_gw = d.get("type") in GATEWAY_TYPES
        out.append(DeviceSnapshot(
            mac=mac, name=d.get("name"), model=d.get("model"), type=d.get("type"), ip=to_ip(d.get("ip")),
            firmware=d.get("version"), upgradable=d.get("upgradable"),
            firmware_latest=d.get("upgrade_to_firmware") or None,
            connected=(d.get("state") == 1) if d.get("state") is not None else None,
            is_gateway=is_gw,
            cpu_pct=_f(stats.get("cpu")), mem_pct=_f(stats.get("mem")),
            temp_c=max(temps) if temps else None,
            uptime_s=_i(d.get("uptime")), client_count=_i(d.get("num_sta")),
            wan_ip=wan_ip if is_gw else None,
            extra={k: v for k, v in {"temperatures": d.get("temperatures"),
                                     "displayable_version": d.get("displayable_version"),
                                     **_ap_and_poe(d)}.items() if v not in (None, [], {})},
        ))
    return out


def _ap_and_poe(d: dict) -> dict:
    """Asset fields (serial, end-of-life / LTS flags; verified 2026-10-11), access point radios / PoE and switch PoE,
    from stat/device (fields verified 2026-10-10 on 22 consoles):
    AP: state, disconnected_at (epoch), radio_table_stats [{radio, channel, cu_total, satisfaction (-1 = no clients),
    num_sta}], uplink {uplink_device_name, uplink_remote_port, uplink_port_poe_compatibility COMPATIBLE|UNKNOWN|...};
    switch / gateway: total_used_power, total_max_power (W), port_table [{port_idx, up, poe_enable, poe_good, poe_power}]."""
    out: dict = {"serial": d.get("serial") or None,
                 # UniFi's own lifecycle flags (stat/device): end of life / long-term support model
                 "eol": True if d.get("model_in_eol") else None, "lts": True if d.get("model_in_lts") else None}
    if isinstance(d.get("disconnected_at"), (int, float)):
        out["disconnected_at"] = int(d["disconnected_at"])
    if d.get("type") == "uap":
        out["radios"] = [{"radio": r.get("radio"), "channel": r.get("channel"), "cu_total": _i(r.get("cu_total")),
                          "satisfaction": _i(r.get("satisfaction")), "num_sta": _i(r.get("num_sta"))}
                         for r in d.get("radio_table_stats") or [] if isinstance(r, dict)]
        up = d.get("uplink") or {}
        out["uplink"] = {k: v for k, v in {"device": up.get("uplink_device_name"), "port": up.get("uplink_remote_port"),
                                           "poe": up.get("uplink_port_poe_compatibility")}.items() if v is not None}
    if _f(d.get("total_max_power")):
        out["poe_budget"] = {"used_w": _f(d.get("total_used_power")) or 0.0, "max_w": _f(d.get("total_max_power"))}
    faults = [p.get("port_idx") for p in d.get("port_table") or []
              if isinstance(p, dict) and p.get("poe_enable") and p.get("up") and p.get("poe_good") is False]
    if faults:
        out["poe_faults"] = faults
    return out


def parse_wans(gateway: dict, networks: list[dict]) -> list[WanPort]:
    """WAN ports of a gateway. 'WAN' maps to the wan1 object, 'WAN2' to wan2, and so on."""
    labels = {n.get("wan_networkgroup"): n.get("name") for n in networks if n.get("purpose") == "wan"}
    out = []
    for name, st in sorted((gateway.get("last_wan_interfaces") or {}).items()):
        port = gateway.get("wan" + (name[3:] or "1")) or {}
        out.append(WanPort(name=name, alive=bool(st.get("alive")), label=labels.get(name), ifname=port.get("name"),
                           ip=to_ip(st.get("ip")), is_uplink=port.get("is_uplink"), media=port.get("media"),
                           latency_ms=_f(port.get("latency")), availability=_f(port.get("availability")),
                           **{k: _i(port.get(k)) for k in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                                                             "rx_dropped", "tx_dropped", "rx_errors", "tx_errors")},
                           link_speed_mbps=_i(port.get("speed"))))
    return out


def _wan_port(interface: str | None) -> str | None:
    """networkconf ipsec_interface ("wan", "wan2") -> WAN port name as reported elsewhere ("WAN", "WAN2")."""
    return interface.upper() if interface else None


def parse_ipsec(networks: list[dict], vpn_health: dict, connections: dict | None = None) -> list[IpsecTunnel]:
    """Site-to-site IPsec tunnels. With the live connection list (v2 vpn/connections, verified 2026-10-09 on Network
    10.6.106: {connections: [{network_id, status CONNECTED|DISCONNECTED, assoc_time, remote_ip}]}) each tunnel's own
    state and since-when are known. Without it the controller reports only HOW MANY are active, so a tunnel's state is
    known when all enabled tunnels are up, all are down, or there is exactly one."""
    conf = [n for n in networks if n.get("purpose") == "site-vpn" and n.get("vpn_type") == "ipsec-vpn"]
    tunnels = [IpsecTunnel(name=n.get("name") or n.get("_id"), peer=n.get("ipsec_peer_ip"), enabled=bool(n.get("enabled")),
                           interface=_wan_port(n.get("ipsec_interface")), vpn_type="IPsec") for n in conf]
    live = {c.get("network_id"): c for c in (connections or {}).get("connections") or [] if isinstance(c, dict)}
    if live:
        for n, t in zip(conf, tunnels):
            c = live.get(n.get("_id"))
            if c is not None and t.enabled:
                t.up = c.get("status") == "CONNECTED"
                at = _i(c.get("assoc_time"))
                t.established_at = datetime.fromtimestamp(at, UTC) if t.up and at else None
        return tunnels
    enabled = [t for t in tunnels if t.enabled]
    active = _i(vpn_health.get("site_to_site_num_active"))
    if active is not None and enabled:
        state = True if active >= len(enabled) else False if active == 0 else None
        for t in enabled:
            t.up = state
    return tunnels


def parse_clients(data: list[dict]) -> list[NetClient]:
    out = []
    for c in data:
        mac = to_mac(c.get("mac"))
        if not mac:
            continue
        ls = _i(c.get("last_seen"))
        out.append(NetClient(
            mac=mac, ip=to_ip(c.get("ip")), hostname=c.get("name") or c.get("hostname"),
            ssid=c.get("essid"), ap_mac=to_mac(c.get("ap_mac")), is_wired=c.get("is_wired"),
            vendor=c.get("oui"), network=c.get("network"),
            rssi=_i(c.get("rssi") if c.get("rssi") is not None else c.get("signal")),
            last_seen=datetime.fromtimestamp(ls, UTC) if ls else None,
            signal_dbm=_i(c.get("signal")) if not c.get("is_wired") else None,
        ))
    return out


async def tls_fingerprint(base_url: str, timeout: float = 10.0) -> str:
    """SHA-256 of the server certificate, fetched in a handshake that sends nothing else."""
    u = urlparse(base_url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(u.hostname, u.port or 443, ssl=ctx, server_hostname=u.hostname), timeout)
    except (OSError, TimeoutError) as e:
        raise PollError(f"cannot reach {u.hostname}: {type(e).__name__}: {e}") from e
    try:
        der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    finally:
        writer.close()
    return hashlib.sha256(der).hexdigest()


class UnifiControllerDriver(PollDriver):
    name = "unifi"

    async def poll(self, config: dict, secret: dict | None) -> PollResult:
        base = config.get("base_url", "").rstrip("/")
        site = config.get("site") or "default"
        key = (secret or {}).get("api_key")
        if not base or not key:
            raise PollError("UniFi poller needs base_url and an API key")
        pinned = config.get("tls_fingerprint")
        # Check the certificate BEFORE the API key is sent anywhere.
        seen_fp = await tls_fingerprint(base) if base.startswith("https://") else None
        if pinned and seen_fp != pinned:
            raise PollError("TLS certificate fingerprint changed since it was pinned; API key not sent")

        async with httpx.AsyncClient(verify=False, timeout=20.0,
                                     headers={"X-API-KEY": key, "Accept": "application/json"}) as http:
            return await collect(http, base, site, seen_fp, "API key rejected")


async def collect(http: httpx.AsyncClient, base: str, site: str, seen_fp: str | None, auth_msg: str) -> PollResult:
    """The controller calls and parsing shared by the local and the Site Manager (cloud) driver: the paths below the
    base are the same, only the base address and the key differ."""
    async def get(path: str):
        try:
            r = await http.get(base + path)
        except httpx.HTTPError as e:
            raise PollError(f"{type(e).__name__}: {e}") from e
        if r.status_code == 429:
            raise PollError("rate limited (HTTP 429)")
        if r.status_code in (401, 403):
            raise PollError(f"{auth_msg} (HTTP {r.status_code})")
        if r.status_code != 200:
            raise PollError(f"HTTP {r.status_code} for {path}")
        return r.json().get("data", [])

    sysinfo = await get(f"/proxy/network/api/s/{site}/stat/sysinfo")
    health = await get(f"/proxy/network/api/s/{site}/stat/health")
    wan = next((h for h in health if h.get("subsystem") == "wan"), {})
    www = next((h for h in health if h.get("subsystem") == "www"), {})
    vpn = next((h for h in health if h.get("subsystem") == "vpn"), {})
    raw_devices = await get(f"/proxy/network/api/s/{site}/stat/device")
    devices = parse_devices(raw_devices, to_ip(wan.get("wan_ip")))
    clients = parse_clients(await get(f"/proxy/network/api/s/{site}/stat/sta"))
    networks = await get(f"/proxy/network/api/s/{site}/rest/networkconf")
    connections = None
    if any(n.get("purpose") == "site-vpn" for n in networks):
        try:                                         # optional: older controllers have no v2 VPN status
            r = await http.get(base + f"/proxy/network/v2/api/site/{site}/vpn/connections")
            connections = r.json() if r.status_code == 200 else None
        except (httpx.HTTPError, ValueError):
            connections = None
    gateway = next((d for d in raw_devices if d.get("type") in GATEWAY_TYPES), None)
    info = sysinfo[0] if sysinfo else {}
    controller = {k: info.get(k) for k in ("version", "console_display_version", "hostname", "timezone") if info.get(k)}
    controller["health"] = {h.get("subsystem"): h.get("status") for h in health if h.get("subsystem")}
    return PollResult(devices=devices, clients=clients, controller=controller, tls_fingerprint=seen_fp,
                      wans=parse_wans(gateway, networks) if gateway else [],
                      internet_up=(www.get("status") == "ok") if www.get("status") else None,
                      internet_latency_ms=_f(www.get("latency")),
                      ipsec=parse_ipsec(networks, vpn, connections if isinstance(connections, dict) else None))


CONNECTOR = "https://api.ui.com/v1/connector/consoles/{host}"


# The Site Manager key in effect, set by the poller every cycle (a key saved in the portal replaces the one from .env);
# None = not set yet: the .env value is used.
SITE_MANAGER_KEY: str | None = None


class UnifiCloudDriver(PollDriver):
    """The same controller data as the local driver, through the UniFi Site Manager connector (no VPN or port forward
    to the site). Verified 2026-10-09 on CTS KL: stat/device returns system-stats cpu / mem, uptime and the gateway's
    wan1 / wan2 byte counters, as on a local console. Key: UNIFI_SITE_MANAGER_API_KEY; config: {"host_id": ...}."""
    name = "unifi_cloud"

    def __init__(self, transport=None):
        self.transport = transport                      # tests

    async def poll(self, config: dict, secret: dict | None) -> PollResult:
        from app.config import get_settings
        key = get_settings().unifi_site_manager_api_key if SITE_MANAGER_KEY is None else SITE_MANAGER_KEY
        host = config.get("host_id")
        if not key or not host:
            raise PollError("cloud poll needs the Site Manager API key and the console's host_id")
        async with httpx.AsyncClient(timeout=30.0, headers={"X-API-KEY": key, "Accept": "application/json"},
                                     transport=self.transport) as http:
            return await collect(http, CONNECTOR.format(host=host), config.get("site") or "default", None,
                                 "Site Manager key rejected by the console")


FLOW_PAGE = 5000
FLOW_MAX_PAGES = 40


async def fetch_flows(config: dict, secret: dict | None, since_ms: int, until_ms: int) -> list[dict]:
    """Traffic-flow records with since_ms < time <= until_ms, exactly as returned. Needs a pinned certificate."""
    base = config.get("base_url", "").rstrip("/")
    site = config.get("site") or "default"
    key = (secret or {}).get("api_key")
    pinned = config.get("tls_fingerprint")
    if not base or not key or not pinned:
        raise PollError("traffic flows need base_url, an API key and a pinned certificate (run a normal poll first)")
    if await tls_fingerprint(base) != pinned:
        raise PollError("TLS certificate fingerprint changed since it was pinned; API key not sent")
    out: list[dict] = []
    async with httpx.AsyncClient(verify=False, timeout=60.0,
                                 headers={"X-API-KEY": key, "Accept": "application/json"}) as http:
        for page in range(FLOW_MAX_PAGES):
            try:
                r = await http.post(f"{base}/proxy/network/v2/api/site/{site}/traffic-flows",
                                    json={"timestampFrom": since_ms, "timestampTo": until_ms,
                                          "pageNumber": page, "pageSize": FLOW_PAGE})
            except httpx.HTTPError as e:
                raise PollError(f"{type(e).__name__}: {e}") from e
            if r.status_code in (401, 403):
                raise PollError(f"API key rejected (HTTP {r.status_code})")
            if r.status_code != 200:
                raise PollError(f"HTTP {r.status_code} for traffic-flows")
            body = r.json()
            out.extend(f for f in body.get("data", []) if isinstance(f, dict) and isinstance(f.get("time"), int)
                       and since_ms < f["time"] <= until_ms)
            if not body.get("has_next"):
                break
        else:
            raise PollError(f"more than {FLOW_MAX_PAGES * FLOW_PAGE} flow records in one window")
    return out
