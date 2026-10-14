"""UniFi Site Manager (https://api.ui.com, X-API-KEY, read-only) for every console of the account.

Verified 2026-10-08 against the live API (trimmed real responses: samples/sitemanager-2026-10-08.json):
  GET /v1/hosts      consoles: id, ipAddress, reportedState {name, hostname, state connected|disconnected, timezone,
                     hardware.shortname, mac}
  GET /v1/sites      per console site: hostId, meta {name, desc, timezone}, statistics {counts, ispInfo, internetIssues,
                     wans {WAN|WAN2: {externalIp, portUp, wanUptime, failoverPriority, ispInfo}}}
  GET /v1/devices    per console: devices [{mac, name, model, ip, productLine, status online|offline, version,
                     updateAvailable, isConsole}]
  GET /ea/isp-metrics/5m (about 24 h) and /1h (about 30 days): per site, periods [{metricTime, data.wan {avgLatency,
                     maxLatency, packetLoss, uptime, downtime, download_kbps, upload_kbps, ispName, ispAsn}}]
  Lists page with pageSize / nextToken.
Facts learned on the live data, used below:
  - download/upload_kbps never change over 30 days: they are the LINE SPEED, not traffic. Stored as line_*_kbps.
  - The metrics follow the WAN with failover priority 1; where that port is unplugged (NW HK, MGN HK) everything is 0.
Consoles the server already polls through the local UniFi API (NW-HK) keep their richer local WAN state and inventory;
Site Manager adds nothing for them."""

import json
import logging
import re
from datetime import UTC, datetime, timedelta
from zoneinfo import available_timezones

import httpx
from psycopg.types.json import Jsonb

from app.config import Settings
from app.parsers.util import to_ip, to_mac

log = logging.getLogger("poller.sitemanager")
API = "https://api.ui.com"
TIMEZONES = available_timezones()


def norm(name: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:30] or "site"
    return s if len(s) >= 2 else f"{s}-site"


async def fetch_all(api_key: str, with_hourly: bool) -> dict:
    """Everything the sync needs, read-only. Raises httpx.HTTPError / ValueError on failure."""
    async with httpx.AsyncClient(base_url=API, timeout=30, headers={"X-API-KEY": api_key, "Accept": "application/json"}) as h:
        async def pages(path: str) -> list:
            out, token = [], None
            for _ in range(50):
                r = await h.get(path, params={"pageSize": 100, **({"nextToken": token} if token else {})})
                r.raise_for_status()
                body = r.json()
                out += body.get("data") or []
                token = body.get("nextToken")
                if not token:
                    break
            return out

        async def get(path: str) -> list:
            r = await h.get(path)
            r.raise_for_status()
            return r.json().get("data") or []

        data = {"hosts": await pages("/v1/hosts"), "sites": await pages("/v1/sites"), "devices": await pages("/v1/devices"),
                "isp_5m": await get("/ea/isp-metrics/5m")}
        data["isp_1h"] = await get("/ea/isp-metrics/1h") if with_hourly else []
        return data


class SiteManagerSync:
    def __init__(self, settings: Settings, poller, fetch=None):
        self.s = settings
        self.poller = poller                       # reuses Poller._interval for WAN/internet state intervals
        self.fetch = fetch or fetch_all

    async def sync(self, conn, now: datetime | None = None) -> dict:
        now = now or datetime.now(UTC)
        cur = await conn.execute("SELECT count(*) FROM isp_metrics WHERE period_s = 3600")
        hourly = (await cur.fetchone())[0] == 0    # first run: also take the 30-day hourly history
        data = await self.fetch(self.s.unifi_site_manager_api_key, hourly)
        stats = {"consoles": 0, "clients_created": 0, "metrics": 0, "inventory": 0}
        sites = {}
        for site in data["sites"]:
            sites.setdefault(site.get("hostId"), site)            # one (default) site per console in practice
        devices_by_host = {d.get("hostId"): d.get("devices") or [] for d in data["devices"]}
        site_device: dict[str, tuple[int, int, bool]] = {}         # siteId -> (device_id, client_id, locally polled)

        for host in data["hosts"]:
            rs = host.get("reportedState") or {}
            name = (rs.get("name") or rs.get("hostname") or "").strip()
            if not name:
                continue
            site = sites.get(host["id"]) or {}
            st = site.get("statistics") or {}
            wans = st.get("wans") or {}
            wan_ips = [ip for ip in (to_ip((w or {}).get("externalIp")) for w in wans.values()) if ip]
            if not wan_ips and to_ip(host.get("ipAddress")):
                wan_ips = [to_ip(host.get("ipAddress"))]
            client_id, device_id, created = await self._link(conn, host, name, rs, site, wan_ips)
            stats["clients_created"] += created
            stats["consoles"] += 1
            cur = await conn.execute("SELECT poll_config FROM devices WHERE id = %s", (device_id,))
            cfg = (await cur.fetchone())[0] or {}
            local = cfg.get("driver") == "unifi"
            if not cfg.get("driver") and cfg.get("cloud_poll") is not False and rs.get("state") == "connected":
                # Every console not polled locally is polled through the connector every minute (CPU, memory, uptime,
                # WAN bandwidth, clients) like a local console. "cloud_poll": false in poll_config opts a device out.
                await conn.execute("UPDATE devices SET poll_config = poll_config || %s WHERE id = %s",
                                   (Jsonb({"driver": "unifi_cloud", "host_id": host["id"]}), device_id))
                cfg = {**cfg, "driver": "unifi_cloud"}
            polled = cfg.get("driver") in ("unifi", "unifi_cloud")
            if site.get("siteId"):
                site_device[site["siteId"]] = (device_id, client_id, local)
            isp = ((st.get("ispInfo") or {}).get("name"))
            await conn.execute("""
                INSERT INTO sitemanager_hosts (host_id, site_id, client_id, device_id, name, model, state, wan_ips, isp, counts, last_sync)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s::inet[], %s, %s, %s)
                ON CONFLICT (host_id) DO UPDATE SET site_id = EXCLUDED.site_id, client_id = EXCLUDED.client_id,
                    device_id = EXCLUDED.device_id, name = EXCLUDED.name, model = EXCLUDED.model, state = EXCLUDED.state,
                    wan_ips = EXCLUDED.wan_ips, isp = EXCLUDED.isp, counts = EXCLUDED.counts, last_sync = EXCLUDED.last_sync""",
                (host["id"], site.get("siteId"), client_id, device_id, name, (rs.get("hardware") or {}).get("shortname"),
                 rs.get("state"), wan_ips, isp, Jsonb(st.get("counts") or {}), now))
            if polled:
                continue                                # polled every minute (locally or via the connector): richer data
            if rs.get("state") == "connected":         # a disconnected console's WAN data is stale: assert nothing
                for wan_name, w in wans.items():
                    w = w or {}
                    await self.poller._interval(conn, "wan_state", device_id, client_id, wan_name,
                                                "up" if w.get("portUp") else "down", now,
                                                label=(w.get("ispInfo") or {}).get("name"), ip=to_ip(w.get("externalIp")),
                                                reason="site manager: port " + ("up" if w.get("portUp") else "down"))
                if wans:
                    up = any((w or {}).get("portUp") for w in wans.values())
                    await self.poller._interval(conn, "wan_state", device_id, client_id, "internet", "up" if up else "down", now,
                                                label="Internet", reason="site manager: " + ("a WAN is up" if up else "no WAN up"))
            stats["inventory"] += await self._inventory(conn, device_id, devices_by_host.get(host["id"]), now)

        stats["metrics"] += await self._metrics(conn, data["isp_5m"], 300, site_device)
        if data.get("isp_1h"):
            stats["metrics"] += await self._metrics(conn, data["isp_1h"], 3600, site_device, older_than_5m=True)
        return stats

    async def _link(self, conn, host, name, rs, site, wan_ips) -> tuple[int, int, int]:
        """(client_id, device_id, created): known console, else a device with the same name or WAN IP, else a new client."""
        cur = await conn.execute("SELECT client_id, device_id FROM sitemanager_hosts WHERE host_id = %s", (host["id"],))
        row = await cur.fetchone()
        if row and row[1]:
            return row[0], row[1], 0
        cur = await conn.execute("""
            SELECT d.client_id, d.id FROM devices d
            WHERE d.is_active AND (regexp_replace(lower(d.name), '[^a-z0-9]', '', 'g') = %s
                                   OR d.syslog_source_ip = ANY(%s::inet[]) OR d.alt_source_ips && %s::inet[])
            ORDER BY (regexp_replace(lower(d.name), '[^a-z0-9]', '', 'g') = %s) DESC, d.id LIMIT 1""",
            (norm(name), wan_ips, wan_ips, norm(name)))
        row = await cur.fetchone()
        if row:
            return row[0], row[1], 0
        tz = rs.get("timezone") or (site.get("meta") or {}).get("timezone")
        tz = tz if tz in TIMEZONES else self.s.default_timezone
        base = slugify(name)
        slug = base
        for i in range(2, 100):
            cur = await conn.execute("SELECT 1 FROM clients WHERE slug = %s", (slug,))
            if not await cur.fetchone():
                break
            slug = f"{base[:27]}-{i}"
        cur = await conn.execute("INSERT INTO clients (name, slug, timezone) VALUES (%s, %s, %s) RETURNING id", (name, slug, tz))
        client_id = (await cur.fetchone())[0]
        # WAN IPs as additional source addresses: if the console later sends syslog it is recognised. (Not the primary
        # syslog source, so "log source silent" does not fire for consoles that only report through Site Manager.)
        free = []
        for ip in wan_ips:
            cur = await conn.execute("SELECT 1 FROM devices WHERE syslog_source_ip = %s::inet OR %s::inet = ANY(alt_source_ips)", (ip, ip))
            if not await cur.fetchone():
                free.append(ip)
        cur = await conn.execute("""
            INSERT INTO devices (client_id, name, vendor, model, site, mac, alt_source_ips)
            VALUES (%s, %s, 'unifi', %s, %s, %s, %s::inet[]) RETURNING id""",
            (client_id, name, (rs.get("hardware") or {}).get("shortname") or "", (site.get("meta") or {}).get("desc") or "",
             to_mac(rs.get("mac")), free))
        device_id = (await cur.fetchone())[0]
        await conn.execute("INSERT INTO audit_log (username, action, target, client_id, details) VALUES ('site-manager', 'client_create', %s, %s, %s)",
                           (name, client_id, Jsonb({"host_id": host["id"], "device_id": device_id, "slug": slug, "timezone": tz})))
        log.info("site manager: created client %s (%s)", name, slug)
        return client_id, device_id, 1

    async def _inventory(self, conn, console_id: int, devices: list | None, now) -> int:
        n = 0
        for d in devices or []:
            mac = to_mac(d.get("mac"))
            if not mac:
                continue
            update = d.get("updateAvailable") or None
            await conn.execute("""
                INSERT INTO device_inventory (poll_device_id, mac, device_id, name, model, type, ip, firmware, upgradable,
                                              firmware_latest, connected, seen_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (poll_device_id, mac) DO UPDATE SET device_id = coalesce(EXCLUDED.device_id, device_inventory.device_id),
                    name = EXCLUDED.name, model = EXCLUDED.model, type = EXCLUDED.type, ip = EXCLUDED.ip, firmware = EXCLUDED.firmware,
                    upgradable = EXCLUDED.upgradable, firmware_latest = EXCLUDED.firmware_latest, connected = EXCLUDED.connected,
                    seen_at = EXCLUDED.seen_at""",
                (console_id, mac, console_id if d.get("isConsole") else None, d.get("name"), d.get("model"), d.get("productLine"),
                 to_ip(d.get("ip")), d.get("version"), bool(update), update, d.get("status") == "online", now))
            if d.get("isConsole"):
                await conn.execute("""UPDATE devices SET mac = coalesce(mac, %s), firmware = coalesce(%s, firmware), upgradable = %s,
                                      firmware_latest = %s, model = CASE WHEN model = '' THEN coalesce(%s, '') ELSE model END WHERE id = %s""",
                                   (mac, d.get("version"), bool(update), update, d.get("model"), console_id))
            n += 1
        return n

    async def _metrics(self, conn, sites: list, period: int, site_device: dict, older_than_5m: bool = False) -> int:
        n = 0
        for site in sites:
            target = site_device.get(site.get("siteId"))
            if not target or target[2]:              # unknown site, or locally polled (its primary-WAN metrics are wrong)
                continue
            device_id, client_id, _ = target
            limit = None
            if older_than_5m:
                cur = await conn.execute("SELECT min(ts) FROM isp_metrics WHERE device_id = %s AND period_s = 300", (device_id,))
                limit = (await cur.fetchone())[0]
            rows = []
            for p in site.get("periods") or []:
                w = (p.get("data") or {}).get("wan") or {}
                try:
                    ts = datetime.fromisoformat(p["metricTime"].replace("Z", "+00:00"))
                except (KeyError, ValueError):
                    continue
                if limit and ts >= limit:
                    continue
                rows.append((ts, client_id, device_id, period, w.get("avgLatency"), w.get("maxLatency"), w.get("packetLoss"),
                             w.get("uptime"), w.get("downtime"), w.get("download_kbps"), w.get("upload_kbps"),
                             w.get("ispName") or None, str(w.get("ispAsn") or "") or None))
            for r in rows:
                cur = await conn.execute("""
                    INSERT INTO isp_metrics (ts, client_id, device_id, period_s, avg_latency, max_latency, packet_loss, uptime,
                                             downtime, line_down_kbps, line_up_kbps, isp_name, isp_asn)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING""", r)
                n += cur.rowcount
        return n


def summary(stats: dict) -> str:
    return json.dumps(stats)
