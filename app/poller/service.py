"""Poller: runs each device's driver on an interval and records metrics, inventory, network clients and
up/down state.

Device state rules (evaluated every cycle for every active device):
  1. Inside a maintenance window                      -> maintenance (excluded from availability)
  2. A controller reported the device recently        -> up if it says connected, else down
  3. Otherwise, syslog                                -> up if a line arrived within `silent_after`, else down
  A device that has never logged and was never polled has no state yet."""

import asyncio
import json
import logging
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import httpx
import psycopg
from psycopg.types.json import Jsonb

from app.config import Settings
from app.drivers import DRIVERS, PollError
from app.drivers.base import PollResult, decrypt_secret
from app.drivers.unifi import fetch_flows
from app.parsers.util import to_ip

log = logging.getLogger("poller")
AP_EXTRA = ("disconnected_at", "radios", "uplink", "poe_budget", "poe_faults", "serial", "eol", "lts")   # device_inventory.extra


@dataclass
class PollerConfig:
    interval: float = 60.0
    poll_timeout: float = 45.0
    silent_after: timedelta = timedelta(minutes=15)
    inventory_fresh: timedelta = timedelta(minutes=5)   # controller evidence older than this is ignored
    sm_fresh: timedelta = timedelta(minutes=15)         # Site Manager "connected" older than this is ignored
    # Traffic flows (devices with poll_config.collect_flows): records younger than flow_lag may still change;
    # one cycle collects at most flow_window, so a long outage is caught up gradually (back to flow_backfill).
    flow_lag: timedelta = timedelta(minutes=3)
    flow_window: timedelta = timedelta(minutes=30)
    flow_first: timedelta = timedelta(minutes=15)
    flow_backfill: timedelta = timedelta(hours=6)
    flow_timeout: float = 120.0
    # Through Site Manager (consoles not polled locally): the console keeps only ~25 minutes and a query reports at most
    # 10,000 records, so windows stay small.
    cloud_flow_window: timedelta = timedelta(minutes=2)
    cloud_flow_first: timedelta = timedelta(minutes=10)
    cloud_flow_backfill: timedelta = timedelta(minutes=25)


class Poller:
    def __init__(self, settings: Settings, cfg: PollerConfig | None = None, drivers: dict | None = None, flow_fetch=None,
                 cloud_flow_fetch=None):
        from app.poller.connector import fetch_flows_connector
        self.s = settings
        self.cfg = cfg or PollerConfig()
        self.drivers = drivers if drivers is not None else DRIVERS
        self.flow_fetch = flow_fetch or fetch_flows
        self.cloud_flow_fetch = cloud_flow_fetch or fetch_flows_connector
        self._sm_last = 0.0
        self._fw_last = 0.0
        self._cl_last = 0.0
        self._pr_last = 0.0
        self._cfg_last = 0.0
        self._fwb_last = 0.0
        self._cloud_pause_until = 0.0

    async def connect(self) -> psycopg.AsyncConnection:
        return await psycopg.AsyncConnection.connect(self.s.db_conninfo(), connect_timeout=5, autocommit=True)

    # ------------------------------------------------------------------ polling
    async def poll_all(self, conn, now: datetime | None = None) -> dict[int, str]:
        now = now or datetime.now(UTC)
        cur = await conn.execute("""
            SELECT d.id, d.client_id, d.poll_config, c.secret_enc
            FROM devices d LEFT JOIN device_credentials c ON c.device_id = d.id
            WHERE d.is_active AND d.poll_config ? 'driver'""")
        import time as _time
        rows = await cur.fetchall()
        cloud_paused = _time.monotonic() < self._cloud_pause_until
        rows = [r for r in rows if not (cloud_paused and r[2].get("driver") == "unifi_cloud")]
        gate = asyncio.Semaphore(6)                  # consoles are polled in parallel, results stored one by one

        async def fetch(cfg, secret_enc):
            driver = self.drivers.get(cfg.get("driver"))
            if driver is None:
                raise PollError(f"unknown driver {cfg.get('driver')!r}")
            async with gate:
                return await asyncio.wait_for(driver.poll(cfg, decrypt_secret(secret_enc) if secret_enc else None),
                                              self.cfg.poll_timeout)
        fetched = await asyncio.gather(*(fetch(cfg, sec) for _, _, cfg, sec in rows), return_exceptions=True)
        results = {}
        for (device_id, client_id, cfg, secret_enc), res in zip(rows, fetched):
            if isinstance(res, (PollError, TimeoutError)):
                results[device_id] = f"error: {res or 'timeout'}"
                if "HTTP 429" in str(res) and cfg.get("driver") == "unifi_cloud":
                    self._cloud_pause_until = _time.monotonic() + 300    # Site Manager rate limit: pause cloud polls
            elif isinstance(res, BaseException):    # one broken controller must not stop the others
                log.error("poll of device %s crashed: %s: %s", device_id, type(res).__name__, res)
                results[device_id] = f"error: {type(res).__name__}: {res}"
            else:
                try:
                    await self.store(conn, device_id, client_id, cfg, res, now)
                    results[device_id] = "ok"
                except Exception as e:  # noqa: BLE001
                    log.exception("storing poll of device %s failed", device_id)
                    results[device_id] = f"error: {type(e).__name__}: {e}"
            await conn.execute("UPDATE devices SET last_poll_at = %s, poll_status = %s WHERE id = %s",
                               (now, results[device_id][:300], device_id))
            if results[device_id] != "ok":
                log.warning("poll device %s: %s", device_id, results[device_id])
        return results

    async def _ap_metrics(self, conn, poll_device_id: int, client_id: int, snap, res: PollResult, now: datetime) -> None:
        """One row per access point per poll: the busiest radio's channel utilisation, the lowest Wi-Fi experience of
        radios with clients, and the signal of each Wi-Fi client on it (for the Wi-Fi quality alert)."""
        radios = snap.extra.get("radios") or []
        busy = max((r for r in radios if r.get("cu_total") is not None), key=lambda r: r["cu_total"], default=None)
        exp = [r["satisfaction"] for r in radios if (r.get("num_sta") or 0) > 0 and (r.get("satisfaction") or -1) >= 0]
        signals = [c.signal_dbm for c in res.clients if c.ap_mac == snap.mac and c.signal_dbm is not None]
        await conn.execute("""
            INSERT INTO ap_metrics (ts, client_id, poll_device_id, mac, name, cu_max, cu_radio, exp_min, clients, signals)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::smallint[]) ON CONFLICT DO NOTHING""",
            (now, client_id, poll_device_id, snap.mac, snap.name, busy["cu_total"] if busy else None,
             busy.get("radio") if busy else None, min(exp) if exp else None, snap.client_count, signals))

    async def store(self, conn, poll_device_id: int, client_id: int, cfg: dict, res: PollResult, now: datetime) -> None:
        async with conn.transaction():
            if res.tls_fingerprint and not cfg.get("tls_fingerprint"):
                # Trust on first use: pin the certificate the first successful poll saw.
                await conn.execute("UPDATE devices SET poll_config = poll_config || %s WHERE id = %s",
                                   (Jsonb({"tls_fingerprint": res.tls_fingerprint}), poll_device_id))
            if res.controller:
                await conn.execute("UPDATE devices SET poll_config = poll_config || %s WHERE id = %s",
                                   (Jsonb({"controller": res.controller}), poll_device_id))
            cur = await conn.execute("""
                SELECT id, host(syslog_source_ip), host(mgmt_ip), mac::text FROM devices
                WHERE client_id = %s AND is_active""", (client_id,))
            known = await cur.fetchall()
            by_mac = {m: i for i, _, _, m in known if m}
            by_ip: dict[str, int] = {}
            for i, sip, mip, _ in known:
                for ip in (sip, mip):
                    if ip:
                        by_ip.setdefault(ip, i)
            gateway_id = None
            for snap in res.devices:
                device_id = by_mac.get(snap.mac) or (by_ip.get(snap.ip) if snap.ip else None)
                if device_id is None and snap.is_gateway and poll_device_id not in by_mac.values():
                    device_id = poll_device_id  # the console being polled is itself the gateway
                if snap.is_gateway and device_id is not None:
                    gateway_id = device_id
                    snap.extra["wan"] = [asdict(w) for w in res.wans]
                    snap.extra["internet"] = {"up": res.internet_up, "latency_ms": res.internet_latency_ms}
                await conn.execute("""
                    INSERT INTO device_inventory (poll_device_id, mac, device_id, name, model, type, ip, firmware,
                                                  upgradable, firmware_latest, connected, seen_at,
                                                  cpu_pct, mem_pct, temp_c, uptime_s, client_count, extra)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (poll_device_id, mac) DO UPDATE SET device_id = EXCLUDED.device_id, name = EXCLUDED.name,
                        model = EXCLUDED.model, type = EXCLUDED.type, ip = EXCLUDED.ip, firmware = EXCLUDED.firmware,
                        upgradable = EXCLUDED.upgradable, firmware_latest = EXCLUDED.firmware_latest,
                        connected = EXCLUDED.connected, seen_at = EXCLUDED.seen_at, cpu_pct = EXCLUDED.cpu_pct,
                        mem_pct = EXCLUDED.mem_pct, temp_c = EXCLUDED.temp_c, uptime_s = EXCLUDED.uptime_s,
                        client_count = EXCLUDED.client_count, extra = EXCLUDED.extra""",
                    (poll_device_id, snap.mac, device_id, snap.name, snap.model, snap.type, snap.ip, snap.firmware,
                     snap.upgradable, snap.firmware_latest, snap.connected, now,
                     snap.cpu_pct, snap.mem_pct, snap.temp_c, snap.uptime_s, snap.client_count,
                     Jsonb({k: snap.extra[k] for k in AP_EXTRA if k in snap.extra})))
                if snap.type == "uap" and snap.connected:
                    await self._ap_metrics(conn, poll_device_id, client_id, snap, res, now)
                if device_id is None:
                    continue
                await conn.execute("""
                    UPDATE devices SET mac = %s, firmware = coalesce(%s, firmware), upgradable = %s, firmware_latest = %s
                    WHERE id = %s""", (snap.mac, snap.firmware, snap.upgradable, snap.firmware_latest, device_id))
                await conn.execute("""
                    INSERT INTO device_metrics (ts, client_id, device_id, cpu_pct, mem_pct, temp_c, uptime_s, client_count,
                                                wan_ip, extra) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (now, client_id, device_id, snap.cpu_pct, snap.mem_pct, snap.temp_c, snap.uptime_s,
                     snap.client_count, snap.wan_ip, Jsonb(snap.extra)))
            gw = gateway_id or poll_device_id
            for w in res.wans:
                if w.rx_bytes is not None or w.tx_bytes is not None:
                    await conn.execute("""
                        INSERT INTO wan_metrics (ts, client_id, device_id, wan_name, rx_bytes, tx_bytes, rx_packets, tx_packets,
                                                 rx_dropped, tx_dropped, rx_errors, tx_errors, link_speed_mbps, latency_ms)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                        (now, client_id, gw, w.name, w.rx_bytes, w.tx_bytes, w.rx_packets, w.tx_packets, w.rx_dropped,
                         w.tx_dropped, w.rx_errors, w.tx_errors, w.link_speed_mbps, w.latency_ms))
                await self._interval(conn, "wan_state", gw, client_id, w.name, "up" if w.alive else "down", now,
                                     label=w.label, ifname=w.ifname, ip=w.ip,
                                     reason="alive" if w.alive else "not alive (controller)")
            if res.internet_up is not None:
                await self._interval(conn, "wan_state", gw, client_id, "internet", "up" if res.internet_up else "down", now,
                                     label="Internet", reason="controller internet health " + ("ok" if res.internet_up else "not ok"))
            wan_ip = {w.name: w.ip for w in res.wans}
            for t in res.ipsec:
                status = ("disabled" if not t.enabled else "established" if t.up else "not established" if t.up is False
                          else "unknown")
                await conn.execute("""
                    INSERT INTO vpn_tunnel_info (device_id, tunnel_name, client_id, vpn_type, interface, local_ip, peer,
                                                 status, established_at, updated_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (device_id, tunnel_name) DO UPDATE SET vpn_type = EXCLUDED.vpn_type, interface = EXCLUDED.interface,
                        local_ip = EXCLUDED.local_ip, peer = EXCLUDED.peer, status = EXCLUDED.status,
                        established_at = EXCLUDED.established_at, updated_at = EXCLUDED.updated_at""",
                    (gw, f"ipsec:{t.name}", client_id, t.vpn_type, t.interface, wan_ip.get(t.interface), t.peer, status,
                     t.established_at, now))
                if not t.enabled:
                    await conn.execute("UPDATE vpn_tunnel_state SET ended_at = %s, reason = coalesce(reason, '') || ' (tunnel disabled)' "
                                       "WHERE device_id = %s AND tunnel_name = %s AND ended_at IS NULL", (now, gw, f"ipsec:{t.name}"))
                    continue
                state = "up" if t.up else "down" if t.up is False else "unknown"
                await self._interval(conn, "vpn_tunnel_state", gw, client_id, f"ipsec:{t.name}", state, now,
                                     peer=t.peer, reason="controller site-to-site count")
            ap_names = {s.mac: s.name for s in res.devices}
            for c in res.clients:
                await conn.execute("""
                    INSERT INTO network_clients (client_id, device_id, mac, ip_internal, hostname, ssid, ap, is_wired,
                                                 vendor, network, rssi, first_seen, last_seen)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (device_id, mac) DO UPDATE SET ip_internal = coalesce(EXCLUDED.ip_internal, network_clients.ip_internal),
                        hostname = coalesce(EXCLUDED.hostname, network_clients.hostname), ssid = EXCLUDED.ssid,
                        ap = EXCLUDED.ap, is_wired = EXCLUDED.is_wired, vendor = coalesce(EXCLUDED.vendor, network_clients.vendor),
                        network = EXCLUDED.network, rssi = EXCLUDED.rssi, last_seen = EXCLUDED.last_seen""",
                    (client_id, poll_device_id, c.mac, c.ip, c.hostname, c.ssid, ap_names.get(c.ap_mac), c.is_wired,
                     c.vendor, c.network, c.rssi, c.last_seen or now, c.last_seen or now))

    # ------------------------------------------------------------------ Site Manager (cloud)
    async def refresh_site_manager_key(self, conn) -> None:
        """The key saved in the portal (System Settings -> UniFi Site Manager) replaces the one from .env; asked every
        cycle so a change applies without a restart."""
        from app import sitemanager_key
        from app.drivers import unifi
        if not hasattr(self, "_env_sm_key"):
            self._env_sm_key = self.s.unifi_site_manager_api_key
        key = await sitemanager_key.saved_key(conn) or self._env_sm_key
        unifi.SITE_MANAGER_KEY = key                     # the cloud driver (UnifiCloudDriver) reads it from here
        if key != self.s.unifi_site_manager_api_key:
            log.info("site manager: API key %s", "changed" if key else "removed")
            self.s = self.s.model_copy(update={"unifi_site_manager_api_key": key})
            self._sm_last = 0.0                          # sync at once with the new key

    async def site_manager(self, conn, now: datetime | None = None, force: bool = False, fetch=None) -> dict | None:
        """Every sitemanager_interval_s: sync all consoles of the Site Manager account (if a key is configured)."""
        import time as _time
        from app.poller.sitemanager import SiteManagerSync
        if not self.s.unifi_site_manager_api_key:
            return None
        if not force and _time.monotonic() - self._sm_last < self.s.sitemanager_interval_s:
            return None
        self._sm_last = _time.monotonic()
        try:
            stats = await asyncio.wait_for(SiteManagerSync(self.s, self, fetch).sync(conn, now), 120)
            log.info("site manager: %s", json.dumps(stats))
            return stats
        except Exception as e:  # noqa: BLE001 - the cloud being unreachable must not stop local polling
            log.warning("site manager sync failed: %s: %s", type(e).__name__, e)
            return {"error": f"{type(e).__name__}: {e}"}

    async def client_names(self, conn, now: datetime | None = None, force: bool = False, fetch=None) -> dict | None:
        """Every clients_interval_s: the client list (names, MAC, IP) of each Site Manager console that is not polled
        locally, so devices show by name. Fetched in parallel, stored one by one."""
        import time as _time
        from app.poller import clients
        if not self.s.unifi_site_manager_api_key:
            return None
        if not force and _time.monotonic() - self._cl_last < self.s.clients_interval_s:
            return None
        self._cl_last = _time.monotonic()
        now = now or datetime.now(UTC)
        fetch = fetch or clients.fetch_clients_connector
        cur = await conn.execute("""
            SELECT d.id, d.client_id, h.host_id FROM sitemanager_hosts h JOIN devices d ON d.id = h.device_id
            WHERE h.state = 'connected' AND d.is_active
              AND coalesce(d.poll_config->>'driver', '') NOT IN ('unifi', 'unifi_cloud')""")
        targets = await cur.fetchall()
        gate = asyncio.Semaphore(5)

        async def one(host_id):
            async with gate:
                return await asyncio.wait_for(fetch(self.s.unifi_site_manager_api_key, host_id), 45)
        results = await asyncio.gather(*(one(h) for _, _, h in targets), return_exceptions=True)
        out = {}
        for (device_id, client_id, _), res in zip(targets, results):
            if isinstance(res, BaseException):
                out[device_id] = f"{type(res).__name__}: {res}"[:200]
            else:
                out[device_id] = await clients.store(conn, client_id, device_id, res, now)
        log.info("client names: %s", json.dumps(out))
        return out

    async def config_backups(self, conn, now: datetime | None = None, force: bool = False, fetch=None) -> dict | None:
        """Every config_interval_s: each connected console's configuration (secrets redacted); a section is stored again
        only when it changed, with what changed."""
        import time as _time
        from app.poller import config_backup
        if not self.s.unifi_site_manager_api_key:
            return None
        if not force and _time.monotonic() - self._cfg_last < self.s.config_interval_s:
            return None
        self._cfg_last = _time.monotonic()
        now = now or datetime.now(UTC)
        fetch = fetch or config_backup.fetch_config
        cur = await conn.execute("SELECT host_id, client_id, device_id FROM sitemanager_hosts WHERE state = 'connected'")
        targets = await cur.fetchall()
        gate = asyncio.Semaphore(3)

        async def one(host_id):
            async with gate:
                return await asyncio.wait_for(fetch(self.s.unifi_site_manager_api_key, host_id), 120)
        results = await asyncio.gather(*(one(h) for h, _, _ in targets), return_exceptions=True)
        out = {}
        for (host_id, client_id, device_id), res in zip(targets, results):
            if isinstance(res, BaseException):
                out[host_id] = f"{type(res).__name__}: {res}"[:200]
            elif res:
                out[host_id] = await config_backup.store(conn, host_id, client_id, device_id, res, now)
        log.info("config backups (sections changed per console): %s", json.dumps(out))
        return out

    async def firewall_backups(self, conn, now: datetime | None = None, force: bool = False,
                               lister=None, downloader=None) -> dict | None:
        """Every fw_backup_interval_s: for each console reachable on the local network (local driver, pinned certificate),
        download the auto-backup files it made that are not stored yet. Kept: every file of the last fw_backup_keep_days
        and never fewer than the newest fw_backup_keep (the console itself keeps only its last few)."""
        import time as _time
        from pathlib import Path

        from app.poller import fw_backup
        now = now or datetime.now(UTC)
        due_weekly = self._weekly_due(now)
        if not force and not due_weekly and _time.monotonic() - self._fwb_last < self.s.fw_backup_interval_s:
            return None
        self._fwb_last = _time.monotonic()
        lister, downloader = lister or fw_backup.list_backups, downloader or fw_backup.download
        root = Path(self.s.fw_backup_dir)
        cur = await conn.execute("""
            SELECT d.id, d.client_id, c.slug, d.poll_config, k.secret_enc FROM devices d JOIN clients c ON c.id = d.client_id
            JOIN device_credentials k ON k.device_id = d.id WHERE d.is_active AND d.poll_config->>'driver' = 'unifi'""")
        out = {}
        for device_id, client_id, slug, cfg, enc in await cur.fetchall():
            try:
                secret = decrypt_secret(enc) if enc else None
                listed = await asyncio.wait_for(lister(cfg, secret), 60)
                have = {r[0] for r in await (await conn.execute(
                    "SELECT filename FROM firewall_backups WHERE device_id = %s", (device_id,))).fetchall()}
                cutoff = now - timedelta(days=self.s.fw_backup_keep_days)
                ordered = sorted(listed, key=lambda b: fw_backup.taken_at(b) or now)
                wanted = [b for i, b in enumerate(ordered)
                          if i >= len(ordered) - self.s.fw_backup_keep or (fw_backup.taken_at(b) or now) >= cutoff]
                new = [b for b in wanted if b["filename"] not in have]       # files outside the retention are never copied
                for b in new:
                    data = await asyncio.wait_for(downloader(cfg, secret, b["filename"]), 600)
                    path, sha = await asyncio.to_thread(fw_backup.store_file, root, slug, device_id, b["filename"], data)
                    await conn.execute("""INSERT INTO firewall_backups (client_id, device_id, filename, taken_at, version, size, sha256, path)
                                          VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING""",
                                       (client_id, device_id, b["filename"], fw_backup.taken_at(b), b.get("version"), len(data),
                                        sha, str(path)))
                old = await (await conn.execute("""SELECT id, path FROM (
                                                       SELECT id, path, taken_at, row_number() OVER (ORDER BY taken_at DESC NULLS LAST) AS n
                                                       FROM firewall_backups WHERE device_id = %s) x
                                                   WHERE n > %s AND (taken_at IS NULL OR taken_at < %s)""",
                                                (device_id, self.s.fw_backup_keep, cutoff))).fetchall()
                for bid, p in old:
                    Path(p).unlink(missing_ok=True)
                    await conn.execute("DELETE FROM firewall_backups WHERE id = %s", (bid,))
                out[device_id] = f"{len(new)} new"
            except Exception as e:  # noqa: BLE001 - one console must not stop the others
                out[device_id] = f"{type(e).__name__}: {e}"[:200]
        log.info("firewall backups: %s", json.dumps(out))
        return out

    def _weekly_due(self, now: datetime) -> bool:
        """True once per week after the configured weekly time ("sun 01:30 Asia/Hong_Kong")."""
        from zoneinfo import ZoneInfo
        try:
            day, hhmm, tz = self.s.fw_backup_weekly.split()
            wd = ("mon", "tue", "wed", "thu", "fri", "sat", "sun").index(day.lower()[:3])
            h, m = (int(x) for x in hhmm.split(":"))
            z = ZoneInfo(tz)
        except (ValueError, KeyError):
            return False
        local = now.astimezone(z)
        slot = (local - timedelta(days=(local.weekday() - wd) % 7)).replace(hour=h, minute=m, second=0, microsecond=0)
        if slot > local:
            slot -= timedelta(days=7)
        if getattr(self, "_fwb_weekly_done", None) == slot:
            return False
        if getattr(self, "_fwb_weekly_done", None) is None:      # just started: count the last slot as done
            self._fwb_weekly_done = slot
            return False
        self._fwb_weekly_done = slot
        return True

    async def prune(self, conn, now: datetime | None = None) -> None:
        """Hourly: AP Wi-Fi history older than 7 days (only the alert windows and recent trends use it)."""
        import time as _time
        if _time.monotonic() - getattr(self, "_prune_last", 0.0) < 3600:
            return
        self._prune_last = _time.monotonic()
        now = now or datetime.now(UTC)
        await conn.execute("DELETE FROM ap_metrics WHERE ts < %s", (now - timedelta(days=7),))
        # config versions: one year, but the current version of every section is always kept
        await conn.execute("""DELETE FROM config_snapshots s WHERE s.taken_at < %s AND s.id <> (
                                  SELECT x.id FROM config_snapshots x WHERE x.host_id = s.host_id AND x.section = s.section
                                  ORDER BY x.taken_at DESC LIMIT 1)""", (now - timedelta(days=365),))

    async def protect_activity(self, conn, now: datetime | None = None, force: bool = False, fetch=None) -> dict | None:
        """Every protect_interval_s: the CCTV access log (UniFi Protect sign-ins, recordings viewed, settings opened) of
        every connected Site Manager console. Consoles without Protect are skipped and retried next time, so a site
        that installs Protect later is picked up by itself. First run per console: the last 30 days."""
        import time as _time
        from app.poller import protect
        if not self.s.unifi_site_manager_api_key:
            return None
        if not force and _time.monotonic() - self._pr_last < self.s.protect_interval_s:
            return None
        self._pr_last = _time.monotonic()
        now = now or datetime.now(UTC)
        fetch = fetch or protect.fetch_activity
        cur = await conn.execute("""
            SELECT h.host_id, h.client_id, h.device_id, (SELECT max(a.ts) FROM protect_activity a WHERE a.host_id = h.host_id)
            FROM sitemanager_hosts h WHERE h.state = 'connected'""")
        targets = await cur.fetchall()
        until_ms = int(now.timestamp() * 1000)
        gate = asyncio.Semaphore(5)

        async def one(host_id, last):
            # sessions are reported with their end later: look 2 days back on every run
            since = (last - timedelta(days=2)) if last else now - timedelta(days=30)
            async with gate:
                return await asyncio.wait_for(fetch(self.s.unifi_site_manager_api_key, host_id,
                                                    int(since.timestamp() * 1000), until_ms), 60)
        results = await asyncio.gather(*(one(h, last) for h, _, _, last in targets), return_exceptions=True)
        out = {}
        for (host_id, client_id, device_id, _), res in zip(targets, results):
            version = None
            if isinstance(res, protect.NoProtect):
                status = str(res)
            elif isinstance(res, BaseException):
                status = f"error: {type(res).__name__}: {res}"[:200]
            else:
                version, events = res
                n = await protect.store(conn, host_id, client_id, device_id, events)
                status = "ok"
                out[host_id] = n
            await conn.execute("""
                INSERT INTO protect_consoles (host_id, client_id, status, version, last_sync) VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (host_id) DO UPDATE SET client_id = EXCLUDED.client_id, status = EXCLUDED.status,
                    version = coalesce(EXCLUDED.version, protect_consoles.version), last_sync = EXCLUDED.last_sync""",
                (host_id, client_id, status, version, now))
        # same retention as the client's logs
        await conn.execute("""DELETE FROM protect_activity a USING clients c
                              WHERE c.id = a.client_id AND a.ts < %s - make_interval(days => c.retention_days)""", (now,))
        log.info("protect activity: %s", json.dumps(out))
        return out

    async def firewall_snapshots(self, conn, now: datetime | None = None, force: bool = False,
                                 cloud=None, local=None) -> dict | None:
        """Every firewall_interval_s: each gateway's firewall policies and zones (local API, else Site Manager connector)."""
        import time as _time
        from app.poller import firewall
        if not force and _time.monotonic() - self._fw_last < self.s.firewall_interval_s:
            return None
        self._fw_last = _time.monotonic()
        now = now or datetime.now(UTC)
        cloud, local = cloud or firewall.fetch_connector, local or firewall.fetch_local
        cur = await conn.execute("""
            SELECT d.id, d.client_id, d.poll_config, c.secret_enc, h.host_id
            FROM devices d LEFT JOIN device_credentials c ON c.device_id = d.id
            LEFT JOIN sitemanager_hosts h ON h.device_id = d.id AND h.state = 'connected'
            WHERE d.is_active AND (d.poll_config->>'driver' = 'unifi' OR h.host_id IS NOT NULL)""")
        targets = await cur.fetchall()
        gate = asyncio.Semaphore(5)                  # fetch in parallel (slow consoles), store one by one (one connection)

        async def fetch(cfg, secret_enc, host_id):
            async with gate:
                if (cfg or {}).get("driver") == "unifi":
                    return await asyncio.wait_for(local(cfg, decrypt_secret(secret_enc) if secret_enc else None), 45)
                if self.s.unifi_site_manager_api_key:
                    return await asyncio.wait_for(cloud(self.s.unifi_site_manager_api_key, host_id), 45)
                return None
        results = await asyncio.gather(*(fetch(cfg, sec, host) for _, _, cfg, sec, host in targets), return_exceptions=True)
        out = {}
        for (device_id, client_id, *_), res in zip(targets, results):
            if res is None:
                continue
            if isinstance(res, BaseException):       # one console failing must not stop the others
                out[device_id] = f"{type(res).__name__}: {res}"[:200]
                continue
            pol, zones = res
            out[device_id] = await firewall.store(conn, client_id, device_id, pol, zones, now)
        log.info("firewall snapshots: %s", json.dumps(out))
        return out

    # ------------------------------------------------------------------ traffic flows
    async def poll_flows(self, conn, now: datetime | None = None) -> dict[int, str]:
        """Collect traffic-flow records into raw_logs (transport 'api'); the parser turns them into events.
        Windows are contiguous (cursor, until], so nothing is fetched twice or skipped."""
        now = now or datetime.now(UTC)
        cur = await conn.execute("""
            SELECT d.id, d.client_id, d.poll_config, c.secret_enc, h.host_id,
                   host(coalesce(d.syslog_source_ip, d.alt_source_ips[1])) AS src
            FROM devices d LEFT JOIN device_credentials c ON c.device_id = d.id
            LEFT JOIN sitemanager_hosts h ON h.device_id = d.id AND h.state = 'connected'
            WHERE d.is_active AND (d.poll_config->>'collect_flows')::boolean
              AND (d.poll_config->>'driver' = 'unifi' OR h.host_id IS NOT NULL)""")
        import time as _time
        results = {}
        plans = []                                     # (row, cloud, since_ms, until_ms)
        cloud_paused = _time.monotonic() < self._cloud_pause_until
        for row in await cur.fetchall():
            device_id, client_id, cfg, secret_enc, host_id, src = row
            cloud = cfg.get("driver") != "unifi"           # through Site Manager instead of the local API
            if cloud and (not self.s.unifi_site_manager_api_key or cloud_paused):
                continue
            first, backfill, win = ((self.cfg.cloud_flow_first, self.cfg.cloud_flow_backfill, self.cfg.cloud_flow_window) if cloud
                                    else (self.cfg.flow_first, self.cfg.flow_backfill, self.cfg.flow_window))
            until = now - self.cfg.flow_lag
            cursor = cfg.get("flow_cursor_ms")
            since = datetime.fromtimestamp(cursor / 1000, UTC) if cursor else until - first
            since = max(since, until - backfill)
            until = min(until, since + win)
            if until <= since:
                continue
            plans.append((row, cloud, int(since.timestamp() * 1000), int(until.timestamp() * 1000)))
        gate = asyncio.Semaphore(4)                    # consoles fetched in parallel, stored one by one

        async def fetch(row, cloud, since_ms, until_ms):
            _, _, cfg, secret_enc, host_id, _ = row
            async with gate:
                if cloud:
                    return await asyncio.wait_for(
                        self.cloud_flow_fetch(self.s.unifi_site_manager_api_key, host_id, since_ms, until_ms), self.cfg.flow_timeout)
                return await asyncio.wait_for(
                    self.flow_fetch(cfg, decrypt_secret(secret_enc) if secret_enc else None, since_ms, until_ms),
                    self.cfg.flow_timeout)
        fetched = await asyncio.gather(*(fetch(*pl) for pl in plans), return_exceptions=True)
        for (row, cloud, since_ms, until_ms), flows in zip(plans, fetched):
            device_id, client_id, cfg, secret_enc, host_id, src = row
            if isinstance(flows, BaseException):
                results[device_id] = f"flows error: {flows or 'timeout'}"
                log.warning("flows device %s: %s", device_id, results[device_id])
                if cloud and "429" in str(flows):
                    self._cloud_pause_until = _time.monotonic() + 300     # Site Manager rate limit: pause cloud calls
                continue
            source_ip = (src or "0.0.0.0") if cloud else (to_ip(urlparse(cfg.get("base_url", "")).hostname) or "0.0.0.0")
            seen: set = set()
            rows = []
            for f in sorted(flows, key=lambda f: f["time"]):
                if f.get("id") in seen:
                    continue
                seen.add(f.get("id"))
                rows.append((now, client_id, device_id, source_ip, "api", json.dumps(f, separators=(",", ":"))))
            async with conn.transaction():
                if rows:
                    async with conn.cursor() as c:
                        async with c.copy("COPY raw_logs (ts_received, client_id, device_id, source_ip, transport, raw) "
                                          "FROM STDIN") as cp:
                            for r in rows:
                                await cp.write_row(r)
                await conn.execute("UPDATE devices SET poll_config = poll_config || %s WHERE id = %s",
                                   (Jsonb({"flow_cursor_ms": until_ms}), device_id))
            results[device_id] = f"{len(rows)} flows"
        return results

    async def backfill_flows(self, conn, device_id: int, since: datetime, until: datetime | None = None) -> int:
        """One-off: fetch flow records older than what regular collection already has (the controller keeps roughly a
        day). Stops just before the oldest flow already stored, so nothing is fetched twice. Returns records stored."""
        cur = await conn.execute("""SELECT d.client_id, d.poll_config, c.secret_enc FROM devices d
                                    LEFT JOIN device_credentials c ON c.device_id = d.id WHERE d.id = %s""", (device_id,))
        row = await cur.fetchone()
        if row is None or row[1].get("driver") != "unifi":
            raise PollError("not a UniFi API device")
        client_id, cfg, secret_enc = row
        cur = await conn.execute("SELECT min(ts) FROM events WHERE device_id = %s AND event_class = 'api:traffic-flow'",
                                 (device_id,))
        oldest = (await cur.fetchone())[0]
        stop = min(x for x in (until, oldest - timedelta(milliseconds=1) if oldest else None,
                               datetime.now(UTC) - self.cfg.flow_lag) if x is not None)
        secret = decrypt_secret(secret_enc) if secret_enc else None
        source_ip = to_ip(urlparse(cfg.get("base_url", "")).hostname) or "0.0.0.0"
        stored, start = 0, since
        while start < stop:
            end = min(start + self.cfg.flow_window, stop)
            flows = await asyncio.wait_for(self.flow_fetch(cfg, secret, int(start.timestamp() * 1000), int(end.timestamp() * 1000)),
                                           self.cfg.flow_timeout)
            now = datetime.now(UTC)
            seen: set = set()
            rows = []
            for f in sorted(flows, key=lambda f: f["time"]):
                if f.get("id") not in seen:
                    seen.add(f.get("id"))
                    rows.append((now, client_id, device_id, source_ip, "api", json.dumps(f, separators=(",", ":"))))
            if rows:
                async with conn.transaction():
                    async with conn.cursor() as c:
                        async with c.copy("COPY raw_logs (ts_received, client_id, device_id, source_ip, transport, raw) "
                                          "FROM STDIN") as cp:
                            for r in rows:
                                await cp.write_row(r)
            stored += len(rows)
            log.info("backfill device %s: %s .. %s -> %d flows", device_id, start.isoformat(), end.isoformat(), len(rows))
            start = end
        return stored

    async def _interval(self, conn, table: str, device_id: int, client_id: int, name: str, state: str, now,
                        label=None, ifname=None, ip=None, peer=None, reason=None) -> None:
        """Open/close state intervals for WAN ports (wan_state) and IPsec tunnels (vpn_tunnel_state)."""
        key = "wan_name" if table == "wan_state" else "tunnel_name"
        cur = await conn.execute(f"SELECT id, state, started_at FROM {table} WHERE device_id = %s AND {key} = %s AND ended_at IS NULL",
                                 (device_id, name))
        row = await cur.fetchone()
        if row and row[1] == state:
            if table == "wan_state":
                await conn.execute("UPDATE wan_state SET ip = coalesce(%s, ip), label = coalesce(%s, label), ifname = coalesce(%s, ifname) "
                                   "WHERE id = %s", (ip, label, ifname, row[0]))
            return
        at = max(now, row[2]) if row else now
        if row:
            await conn.execute(f"UPDATE {table} SET ended_at = %s WHERE id = %s", (at, row[0]))
        if table == "wan_state":
            await conn.execute("INSERT INTO wan_state (client_id, device_id, wan_name, label, ifname, ip, state, started_at, reason) "
                               "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                               (client_id, device_id, name, label, ifname, ip, state, at, reason))
        else:
            await conn.execute("INSERT INTO vpn_tunnel_state (client_id, device_id, tunnel_name, peer, state, started_at, reason) "
                               "VALUES (%s, %s, %s, %s, %s, %s, %s)", (client_id, device_id, name, peer, state, at, reason))

    # ------------------------------------------------------------------ device state
    async def evaluate_states(self, conn, now: datetime | None = None) -> None:
        now = now or datetime.now(UTC)
        cur = await conn.execute("""
            SELECT d.id, d.client_id, d.last_log_at, d.silent_after_minutes,
                   (SELECT i.connected FROM device_inventory i WHERE i.device_id = d.id AND i.seen_at >= %s
                    ORDER BY i.seen_at DESC LIMIT 1) AS polled_connected,
                   (SELECT i.seen_at FROM device_inventory i WHERE i.device_id = d.id ORDER BY i.seen_at DESC LIMIT 1) AS polled_at,
                   EXISTS (SELECT 1 FROM maintenance_windows m WHERE m.client_id = d.client_id
                           AND (m.device_id IS NULL OR m.device_id = d.id) AND m.starts_at <= %s AND m.ends_at > %s) AS in_mw,
                   (SELECT bool_or(h.state = 'connected') FROM sitemanager_hosts h
                     WHERE h.device_id = d.id AND h.last_sync >= %s) AS sm_connected
            FROM devices d WHERE d.is_active""", (now - self.cfg.inventory_fresh, now, now, now - self.cfg.sm_fresh))
        for device_id, client_id, last_log, quiet_min, polled_connected, polled_at, in_mw, sm_connected in await cur.fetchall():
            silent_after = timedelta(minutes=quiet_min) if quiet_min else self.cfg.silent_after
            if in_mw:
                state, reason, since = "maintenance", "maintenance window", now
            elif polled_connected is not None:
                state = "up" if polled_connected else "down"
                reason = "controller: connected" if polled_connected else "controller: disconnected"
                since = now
            elif last_log is not None:
                silent = now - last_log
                if silent <= silent_after:
                    state, reason, since = "up", "syslog active", last_log
                elif sm_connected:
                    # quiet, but UniFi Site Manager sees the console online: a log gap, not an outage
                    # (the "Log source silent" rule reports the gap)
                    state, reason, since = "up", "Site Manager: connected (no syslog)", now
                else:
                    state, reason = "down", f"no syslog for {int(silent.total_seconds() // 60)} min"
                    since = last_log  # it went quiet at its last line
            else:
                continue
            await self._transition(conn, device_id, client_id, state, reason, since)

    async def _transition(self, conn, device_id, client_id, state, reason, since) -> None:
        async with conn.transaction():
            cur = await conn.execute(
                "SELECT id, state, started_at FROM device_state WHERE device_id = %s AND ended_at IS NULL FOR UPDATE",
                (device_id,))
            row = await cur.fetchone()
            if row and row[1] == state:
                return
            at = max(since, row[2]) if row else since
            if row:
                await conn.execute("UPDATE device_state SET ended_at = %s WHERE id = %s", (at, row[0]))
            await conn.execute(
                "INSERT INTO device_state (client_id, device_id, state, started_at, reason) VALUES (%s, %s, %s, %s, %s)",
                (client_id, device_id, state, at, reason))

    # ------------------------------------------------------------------ loop
    async def run(self, stop: asyncio.Event) -> None:
        conn = None
        while not stop.is_set():
            try:
                conn = conn or await self.connect()
                await self.refresh_site_manager_key(conn)
                results = await self.poll_all(conn)
                await self.evaluate_states(conn)
                flows = await self.poll_flows(conn)
                log.info("poll cycle: %s flows: %s", json.dumps(results), json.dumps(flows))
                await self.site_manager(conn)
                await self.firewall_snapshots(conn)
                await self.client_names(conn)
                await self.protect_activity(conn)
                await self.config_backups(conn)
                await self.firewall_backups(conn)
                await self.prune(conn)
            except Exception as e:  # noqa: BLE001
                log.warning("poll cycle failed (%s: %s)", type(e).__name__, e)
                if conn is not None:
                    await conn.close()
                conn = None
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.cfg.interval)
            except TimeoutError:
                pass
