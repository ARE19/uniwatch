"""Event Monitor engine (FortiAnalyzer "event handlers").

Each evaluation, every enabled rule produces findings (client, entity key, title, message).
- A finding with no unresolved alert for (rule, client, key) opens a new alert and notifies once.
- A finding that matches an unresolved alert only bumps last_seen/count: no repeat notification (dedup).
- Stateful rules auto-resolve alerts whose condition is gone; a re-opened alert is notified again only if
  the last notification for that key is older than the rule's throttle window (throttle).
- Event rules (config change, WAN change) consume new rows once via a cursor; each row is its own alert."""

import json
import logging
import smtplib
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage

import httpx
from psycopg.types.json import Jsonb
from sqlalchemy import text

from app import db
from app.config import Settings, get_settings
from app.drivers.base import decrypt_secret
from app.incidents import create_incident

log = logging.getLogger("alerts")
STATEFUL = {"device_offline", "vpn_tunnel_down", "vpn_flapping", "failed_logins", "outdated_firmware",
            "log_source_silent", "event_match", "storage_quota", "wan_down", "internet_down", "isp_degraded",
            "server_health", "vpn_disconnect", "ap_offline", "wifi_quality", "poe_issue"}


@dataclass
class Finding:
    client_id: int
    key: str
    title: str
    message: str = ""
    device_id: int | None = None
    details: dict = field(default_factory=dict)


def _in(rule, alias: str = "") -> str:
    """Client filter for a rule: one client, a company's sites, or TRUE for a global (all-clients) rule."""
    col = f"{alias + '.' if alias else ''}client_id"
    if rule.get("company_id"):
        ids = [int(i) for i in rule.get("company_ids") or []]
        return f"{col} = ANY(ARRAY[{','.join(map(str, ids))}]::integer[])" if ids else "FALSE"
    return f"{col} = :rc" if rule["client_id"] else "TRUE"


async def _rows(s, sql: str, **p) -> list[dict]:
    return [dict(r._mapping) for r in (await s.execute(text(sql), p)).all()]


# ---------------------------------------------------------------- rule evaluators
async def device_offline(s, rule, now):
    mins = int(rule["params"].get("minutes", 5))
    rows = await _rows(s, f"""
        SELECT st.client_id, st.device_id, d.name, st.started_at, st.reason FROM device_state st
        JOIN devices d ON d.id = st.device_id
        WHERE st.ended_at IS NULL AND st.state = 'down' AND st.started_at <= :t AND d.is_active AND {_in(rule, 'st')}""",
        t=now - timedelta(minutes=mins), rc=rule["client_id"])
    return [Finding(r["client_id"], f"device:{r['device_id']}", f"{r['name']} is offline",
                    f"Down since {r['started_at']:%Y-%m-%d %H:%M} UTC ({r['reason']}).", r["device_id"],
                    {"since": r["started_at"].isoformat()}) for r in rows]


async def vpn_tunnel_down(s, rule, now):
    mins = int(rule["params"].get("minutes", 5))
    rows = await _rows(s, f"""
        SELECT t.client_id, t.device_id, d.name, t.tunnel_name, t.peer, t.started_at FROM vpn_tunnel_state t
        JOIN devices d ON d.id = t.device_id
        WHERE t.ended_at IS NULL AND t.state = 'down' AND t.started_at <= :t AND {_in(rule, 't')}""",
        t=now - timedelta(minutes=mins), rc=rule["client_id"])
    return [Finding(r["client_id"], f"tunnel:{r['device_id']}:{r['tunnel_name']}",
                    f"VPN tunnel {r['tunnel_name']} on {r['name']} is down",
                    f"Peer {r['peer'] or '?'}; down since {r['started_at']:%Y-%m-%d %H:%M:%S} UTC.", r["device_id"])
            for r in rows]


async def vpn_flapping(s, rule, now):
    drops, win = int(rule["params"].get("drops", 10)), int(rule["params"].get("window_minutes", 60))
    rows = await _rows(s, f"""
        SELECT t.client_id, t.device_id, d.name, t.tunnel_name, max(t.peer) AS peer, count(*) AS n
        FROM vpn_tunnel_state t JOIN devices d ON d.id = t.device_id
        WHERE t.state = 'down' AND t.started_at >= :t AND {_in(rule, 't')}
        GROUP BY 1, 2, 3, 4 HAVING count(*) >= :drops""", t=now - timedelta(minutes=win), drops=drops, rc=rule["client_id"])
    return [Finding(r["client_id"], f"tunnel:{r['device_id']}:{r['tunnel_name']}",
                    f"VPN tunnel {r['tunnel_name']} on {r['name']} is flapping",
                    f"{r['n']} drops in the last {win} minutes (peer {r['peer'] or '?'}).", r["device_id"], {"drops": r["n"]})
            for r in rows]


# VPN handshake failures: the visitor never reached a username/password check (no valid certificate / IKE proposal).
# In practice these are internet scanners probing the VPN port (verified 2026-10-10: Linode, Google Cloud, Censys ranges
# across 13 sites), so they are kept apart from real login failures.
HANDSHAKE_ACTIONS = ("vpn-tls-error", "vpn-ike-no-proposal")


async def failed_logins(s, rule, now):
    """Failures from one source address. params.actions limits to those actions (the VPN scan rule),
    params.exclude_actions leaves them out (the failed-login rule leaves out handshake failures)."""
    cnt, win = int(rule["params"].get("count", 10)), int(rule["params"].get("window_minutes", 15))
    only, skip = rule["params"].get("actions") or [], rule["params"].get("exclude_actions") or []
    rows = await _rows(s, f"""
        SELECT client_id, host(src_ip) AS ip, max(src_country) AS country, count(*) AS n,
               array_agg(DISTINCT action) AS actions
        FROM events WHERE ts >= :t AND outcome = 'failure' AND category IN ('vpn', 'auth') AND src_ip IS NOT NULL AND {_in(rule)}
          AND (cardinality(CAST(:only AS text[])) = 0 OR action = ANY(CAST(:only AS text[])))
          AND (action IS NULL OR NOT action = ANY(CAST(:skip AS text[])))
        GROUP BY 1, 2 HAVING count(*) >= :cnt""", t=now - timedelta(minutes=win), cnt=cnt, rc=rule["client_id"],
        only=list(only), skip=list(skip))
    scan = bool(only) and set(only) <= set(HANDSHAKE_ACTIONS)
    what = "VPN port scan (handshake failures) from" if scan else "Repeated failed logins from"
    return [Finding(r["client_id"], f"src:{r['ip']}", f"{what} {r['ip']}" + (f" ({r['country']})" if r["country"] else ""),
                    f"{r['n']} failures in {win} minutes ({', '.join(a for a in r['actions'] if a)}).", None,
                    {"source_ip": r["ip"], "count": r["n"]}) for r in rows]


async def outdated_firmware(s, rule, now):
    rows = await _rows(s, f"""SELECT client_id, id, name, firmware, firmware_latest FROM devices
                              WHERE is_active AND upgradable AND {_in(rule)}""", rc=rule["client_id"])
    return [Finding(r["client_id"], f"device:{r['id']}", f"Firmware update available for {r['name']}",
                    f"Running {r['firmware']}" + (f"; {r['firmware_latest']} available." if r["firmware_latest"] else "."), r["id"])
            for r in rows]


async def log_source_silent(s, rule, now):
    mins = int(rule["params"].get("minutes", 30))
    rows = await _rows(s, f"""
        SELECT d.client_id, d.id, d.name, d.last_log_at FROM devices d
        WHERE d.is_active AND d.syslog_source_ip IS NOT NULL AND {_in(rule, 'd')}
          AND coalesce(d.last_log_at, d.created_at) < :now - make_interval(mins => coalesce(d.silent_after_minutes, :mins))
          AND NOT EXISTS (SELECT 1 FROM maintenance_windows m WHERE m.client_id = d.client_id
                          AND (m.device_id IS NULL OR m.device_id = d.id) AND m.starts_at <= :now AND m.ends_at > :now)""",
        mins=mins, now=now, rc=rule["client_id"])
    return [Finding(r["client_id"], f"device:{r['id']}", f"{r['name']} has stopped sending logs" if r["last_log_at"]
                    else f"{r['name']} has never sent logs",
                    f"Last log: {r['last_log_at']:%Y-%m-%d %H:%M} UTC." if r["last_log_at"] else
                    "Registered as a syslog source but nothing has been received.", r["id"]) for r in rows]


async def event_match(s, rule, now):
    p = rule["params"]
    cnt, win = int(p.get("count", 1)), int(p.get("window_minutes", 15))
    where, params = [f"ts >= :t", _in(rule)], {"t": now - timedelta(minutes=win), "cnt": cnt, "rc": rule["client_id"]}
    for k in ("category", "action", "outcome", "severity"):
        if p.get(k):
            where.append(f"{k} = :{k}")
            params[k] = p[k]
    if p.get("q"):
        where.append("message ILIKE :q")
        params["q"] = f"%{p['q']}%"
    rows = await _rows(s, f"SELECT client_id, count(*) AS n FROM events WHERE {' AND '.join(where)} GROUP BY 1 HAVING count(*) >= :cnt", **params)
    return [Finding(r["client_id"], "match", rule["name"], f"{r['n']} matching events in {win} minutes.", None,
                    {"count": r["n"]}) for r in rows]


async def _cursor(s, name: str) -> int:
    await s.execute(text("INSERT INTO tracker_cursors (name, last_event_id) VALUES (:n, 0) ON CONFLICT DO NOTHING"), {"n": name})
    return (await s.execute(text("SELECT last_event_id FROM tracker_cursors WHERE name = :n"), {"n": name})).scalar()


async def config_change(s, rule, now):
    name = f"alerts:config:{rule['id']}"
    last = await _cursor(s, name)
    if last == 0:  # first run: start from now, do not alert on history
        last = (await s.execute(text("SELECT coalesce(max(id), 0) FROM config_changes"))).scalar()
    rows = await _rows(s, f"""SELECT cc.id, cc.client_id, cc.device_id, cc.ts, cc.admin_user, host(cc.source_ip) AS ip, cc.summary, d.name
                              FROM config_changes cc JOIN devices d ON d.id = cc.device_id
                              WHERE cc.id > :last AND {_in(rule, 'cc')} ORDER BY cc.id""", last=last, rc=rule["client_id"])
    top = max([r["id"] for r in rows] + [last])
    await s.execute(text("UPDATE tracker_cursors SET last_event_id = :v, updated_at = now() WHERE name = :n"), {"v": top, "n": name})
    return [Finding(r["client_id"], f"config:{r['id']}", f"Configuration changed on {r['name']}",
                    f"{r['admin_user'] or 'unknown admin'} from {r['ip'] or '?'}: {r['summary']}", r["device_id"],
                    {"config_change_id": r["id"]}) for r in rows]


async def wan_failover(s, rule, now):
    """WAN address change on a gateway between consecutive polls. (No real UniFi failover log line has been
    seen yet, so this uses the poller's verified wan_ip field instead of guessing a log format.)"""
    rows = await _rows(s, f"""
        SELECT client_id, device_id, name, cur_ip, prev_ip, ts FROM (
            SELECT m.client_id, m.device_id, d.name, m.ts, host(m.wan_ip) AS cur_ip,
                   host(lag(m.wan_ip) OVER (PARTITION BY m.device_id ORDER BY m.ts)) AS prev_ip
            FROM device_metrics m JOIN devices d ON d.id = m.device_id
            WHERE m.wan_ip IS NOT NULL AND m.ts >= :t AND {_in(rule, 'm')}) x
        WHERE prev_ip IS NOT NULL AND cur_ip <> prev_ip""", t=now - timedelta(minutes=30), rc=rule["client_id"])
    return [Finding(r["client_id"], f"wan:{r['device_id']}:{r['ts'].isoformat()}", f"WAN address changed on {r['name']}",
                    f"{r['prev_ip']} → {r['cur_ip']} at {r['ts']:%Y-%m-%d %H:%M} UTC (possible WAN failover).", r["device_id"],
                    {"from": r["prev_ip"], "to": r["cur_ip"]}) for r in rows]


async def ioc_match(s, rule, now):
    name = f"alerts:ioc:{rule['id']}"
    last = await _cursor(s, name)
    if last == 0:
        last = (await s.execute(text("SELECT coalesce(max(id), 0) FROM events WHERE action = 'ioc-match' AND ts > :t"),
                                {"t": now - timedelta(days=1)})).scalar()
    # Internet scanners reaching the WAN from a listed address are background noise: an inbound flow from a listed
    # source only alerts when the session moved data (e.g. through a port forward). Hits stay searchable in Log View.
    rows = await _rows(s, f"""SELECT e.id, e.client_id, e.device_id, e.extra->>'value' AS value, e.extra->'feeds' AS feeds, e.message,
                                     e.extra->>'side' = 'src' AND o.extra->>'direction' = 'incoming'
                                       AND coalesce(o.bytes_in, 0) + coalesce(o.bytes_out, 0) < :min_b AS probe
                              FROM events e LEFT JOIN events o ON o.ts = e.ts AND o.id = (e.extra->>'matched_event_id')::bigint
                              WHERE e.action = 'ioc-match' AND e.id > :last AND e.ts > :t AND {_in(rule, 'e')} ORDER BY e.id""",
                       last=last, t=now - timedelta(hours=int(rule["params"].get("max_age_hours", 24))), rc=rule["client_id"],
                       min_b=int(float(rule["params"].get("inbound_min_kb", 20)) * 1024))
    top = max([r["id"] for r in rows] + [last])
    rows = [r for r in rows if not r["probe"]]
    await s.execute(text("UPDATE tracker_cursors SET last_event_id = :v, updated_at = now() WHERE name = :n"), {"v": top, "n": name})
    out, keys = [], set()
    for r in rows:  # repeated hits on the same indicator collapse into one alert (count goes up)
        k = (r["client_id"], r["value"])
        if k in keys:
            continue
        keys.add(k)
        out.append(Finding(r["client_id"], f"ioc:{r['value']}", f"Traffic with known-bad address {r['value']}",
                           r["message"], r["device_id"], {"feeds": r["feeds"], "event_id": r["id"]}))
    return out


async def storage_quota(s, rule, now):
    from app.forwarder import storage_usage
    warn = float(rule["params"].get("warn_pct", 80))
    out = []
    for u in await storage_usage(s):
        if u["used_pct"] is None or u["used_pct"] < warn or (rule["client_id"] and u["id"] != rule["client_id"])                 or (rule.get("company_id") and u["id"] not in (rule.get("company_ids") or [])):
            continue
        out.append(Finding(u["id"], "quota", f"{u['name']} is at {u['used_pct']:.0f} % of its storage quota",
                           f"Estimated {u['est_bytes'] / 1024 ** 3:.2f} GB of {u['quota_gb']} GB.", None,
                           {"used_pct": round(u["used_pct"], 1)}))
    return out


async def wan_down(s, rule, now):
    """A WAN port that has been up before (so unused ports never alert) and is now down."""
    mins = int(rule["params"].get("minutes", 2))
    rows = await _rows(s, f"""
        SELECT w.client_id, w.device_id, d.name, w.wan_name, w.label, w.ifname, host(w.ip) AS ip, w.started_at FROM wan_state w
        JOIN devices d ON d.id = w.device_id
        WHERE w.ended_at IS NULL AND w.state = 'down' AND w.wan_name <> 'internet' AND w.started_at <= :t AND {_in(rule, 'w')}
          AND EXISTS (SELECT 1 FROM wan_state p WHERE p.device_id = w.device_id AND p.wan_name = w.wan_name AND p.state = 'up')""",
        t=now - timedelta(minutes=mins), rc=rule["client_id"])
    return [Finding(r["client_id"], f"wan:{r['device_id']}:{r['wan_name']}",
                    f"{r['label'] or r['wan_name']} ({r['wan_name']}) is down on {r['name']}",
                    f"Interface {r['ifname'] or '?'} (last IP {r['ip'] or '?'}) down since {r['started_at']:%Y-%m-%d %H:%M} UTC.",
                    r["device_id"]) for r in rows]


async def internet_down(s, rule, now):
    mins = int(rule["params"].get("minutes", 2))
    rows = await _rows(s, f"""
        SELECT w.client_id, w.device_id, d.name, w.started_at FROM wan_state w JOIN devices d ON d.id = w.device_id
        WHERE w.ended_at IS NULL AND w.state = 'down' AND w.wan_name = 'internet' AND w.started_at <= :t AND {_in(rule, 'w')}""",
        t=now - timedelta(minutes=mins), rc=rule["client_id"])
    return [Finding(r["client_id"], f"internet:{r['device_id']}", f"Internet is down at {r['name']}",
                    f"The gateway reports no internet since {r['started_at']:%Y-%m-%d %H:%M} UTC.", r["device_id"]) for r in rows]


async def isp_degraded(s, rule, now):
    """Site Manager internet health: the last N 5-minute periods all with packet loss >= X % or latency >= Y ms."""
    prm = rule["params"]
    loss, lat, n = float(prm.get("loss_pct", 5)), float(prm.get("latency_ms", 150)), int(prm.get("periods", 3))
    rows = await _rows(s, f"""
        WITH recent AS (
            SELECT m.client_id, m.device_id, m.ts, m.packet_loss, m.avg_latency,
                   row_number() OVER (PARTITION BY m.device_id ORDER BY m.ts DESC) AS rn
            FROM isp_metrics m WHERE m.period_s = 300 AND m.ts > :since AND {_in(rule, 'm')})
        SELECT r.client_id, r.device_id, d.name, max(r.packet_loss) AS loss, round(avg(r.avg_latency)) AS lat, min(r.ts) AS first
        FROM recent r JOIN devices d ON d.id = r.device_id WHERE r.rn <= :n
        GROUP BY 1, 2, 3
        HAVING count(*) = :n AND bool_and(coalesce(r.packet_loss, 0) >= :loss OR coalesce(r.avg_latency, 0) >= :lat)""",
        since=now - timedelta(minutes=5 * n + 20), n=n, loss=loss, lat=lat, rc=rule["client_id"])
    return [Finding(r["client_id"], f"isp:{r['device_id']}", f"Internet degraded at {r['name']}",
                    f"Packet loss up to {r['loss']:g} %, average latency {r['lat']:g} ms over the last {n} five-minute periods "
                    f"(since {r['first']:%H:%M} UTC, from UniFi Site Manager).", r["device_id"]) for r in rows]


async def server_health(s, rule, now):
    """The log server watching itself (the 2026-10-07 parser stall went unnoticed for 18 hours): no logs arriving, parser
    stopped or behind, disk filling up, no successful backup, most consoles failing to poll. Filed under the platform
    client (PLATFORM_CLIENT_SLUG, default nwhk); every finding resolves by itself when the condition clears."""
    import os
    st = get_settings()
    prm = rule["params"]
    cid = (await s.execute(text("SELECT id FROM clients WHERE slug = :s"), {"s": st.platform_client_slug})).scalar()
    if cid is None:
        return []
    out: list[Finding] = []
    win = now - timedelta(minutes=int(prm.get("stall_minutes", 10)))
    rec, par = (await s.execute(text("""
        SELECT sum(received) FILTER (WHERE component = 'receiver'), sum(coalesce(parsed, 0) + coalesce(failed, 0)) FILTER (WHERE component = 'parser')
        FROM ingest_stats WHERE ts > :w"""), {"w": win})).one()
    if not rec:
        out.append(Finding(cid, "health:nologs", "Log server: no logs received",
                           f"No log lines reached the receiver in the last {prm.get('stall_minutes', 10)} minutes (all sites)."))
    elif not par:
        out.append(Finding(cid, "health:parser", "Log server: parser has stopped",
                           f"{int(rec):,} lines received but none parsed in the last {prm.get('stall_minutes', 10)} minutes."))
    waiting, oldest = (await s.execute(text("""
        SELECT count(*), min(ts_received) FROM raw_logs WHERE NOT parsed AND ts_received > :d"""), {"d": now - timedelta(days=1)})).one()
    backlog = int(prm.get("backlog", 200000))
    if waiting and (waiting > backlog or (oldest and now - oldest > timedelta(minutes=int(prm.get("stall_minutes", 10)) * 3))):
        out.append(Finding(cid, "health:backlog", "Log server: parser is falling behind",
                           f"{int(waiting):,} lines waiting; the oldest arrived {oldest:%H:%M} UTC."))
    try:
        sv = os.statvfs(st.reports_dir)
        used = (1 - sv.f_bavail / sv.f_blocks) * 100 if sv.f_blocks else 0
        if used >= float(prm.get("disk_pct", 85)):
            out.append(Finding(cid, "health:disk", f"Log server: data disk {used:.0f} % full",
                               f"{sv.f_bavail * sv.f_frsize / 1e9:,.0f} GB free on the data disk."))
    except OSError:
        pass
    hours = int(prm.get("backup_hours", 26))
    ok = (await s.execute(text("""SELECT max(ts) FROM audit_log WHERE action = 'db_backup' AND success"""))).scalar()
    first = (await s.execute(text("SELECT min(ts) FROM audit_log"))).scalar()
    if (ok is None or now - ok > timedelta(hours=hours)) and first is not None and now - first > timedelta(hours=hours):
        out.append(Finding(cid, "health:backup", "Log server: no successful backup",
                           f"No successful database backup in the last {hours} hours"
                           + (f" (last: {ok:%Y-%m-%d %H:%M} UTC)." if ok else ".")))
    polled = await _rows(s, """SELECT name, poll_status FROM devices WHERE is_active AND poll_config ? 'driver'
                               AND last_poll_at > :w""", w=now - timedelta(minutes=10))
    failing = [d["name"] for d in polled if (d["poll_status"] or "") != "ok"]
    if len(polled) >= 3 and len(failing) / len(polled) * 100 >= float(prm.get("poll_fail_pct", 50)):
        out.append(Finding(cid, "health:poll", "Log server: console polling failing",
                           f"{len(failing)} of {len(polled)} consoles fail to poll: {', '.join(failing[:8])}."))
    return out


async def unifi_event(s, rule, now):
    """UniFi's own alerts, relayed the moment they arrive: CEF events from the gateways (e.g. 524 Site-to-Site VPN Tunnel
    Disconnected, 105 Temporary Internet Failover), selected by event ID. One alert per occurrence, so a 27-second tunnel
    drop is reported like UniFi reports it; meant for rare, important events."""
    ids = [int(x) for x in (rule["params"].get("event_ids") or []) if str(x).isdigit()]
    if not ids:
        return []
    name = f"alerts:unifi:{rule['id']}"
    last = await _cursor(s, name)
    if last == 0:                                      # first run: start from now, do not replay history
        last = (await s.execute(text("SELECT coalesce(max(id), 0) FROM events WHERE ts > :t"),
                                {"t": now - timedelta(minutes=10)})).scalar()
    rows = await _rows(s, f"""SELECT id, ts, client_id, device_id, event_class, event_name, message, extra FROM events
                              WHERE id > :last AND ts > :t AND event_class = ANY(:cls) AND {_in(rule)} ORDER BY id""",
                       last=last, t=now - timedelta(hours=6), cls=[f"cef:{i}" for i in ids], rc=rule["client_id"])
    top = max([r["id"] for r in rows] + [last])
    await s.execute(text("UPDATE tracker_cursors SET last_event_id = :v, updated_at = now() WHERE name = :n"), {"v": top, "n": name})
    out = []
    for r in rows:
        x = r["extra"] or {}
        subject = x.get("vpn_name") or x.get("wan_name") or x.get("device_name")
        keep = {k: x.get(k) for k in ("vpn_name", "vpn_type", "wan_id", "wan_name", "wan_isp", "wan_subnet", "vpn_local_ip",
                                      "vpn_remote_gateway", "failover_wan_id", "failover_wan_name", "failover_wan_isp",
                                      "failover_wan_subnet", "device_name", "device_ip", "device_model", "unifi_category") if x.get(k)}
        out.append(Finding(r["client_id"], f"unifi:{r['id']}",
                           f"{r['event_name']}" + (f": {subject}" if subject else ""), r["message"] or r["event_name"],
                           r["device_id"], {**keep, "event": r["event_class"], "event_name": r["event_name"],
                                            "event_time": r["ts"].isoformat()}))
    return out


async def vpn_disconnect(s, rule, now):
    """Site-to-site VPN down for at least min_seconds (default 60), from the gateway's own disconnect event (UniFi CEF 524).
    The reconnect time comes from the console's live tunnel status (vpn_tunnel_info, polled every minute: established after
    the drop) or the gateway logging the reconnect (IKE SA established / EVT_VPN ClientConnected for the same peer).
    Shorter drops are ignored. An outage that lasted long enough is reported even if it ended between two evaluations
    (alert, then the "resolved" e-mail on the next run); an ongoing one stays open until the tunnel is back."""
    min_s = int(rule["params"].get("min_seconds", 60))
    rows = await _rows(s, f"""
        SELECT DISTINCT ON (e.device_id, e.extra->>'vpn_name') e.id, e.ts, e.client_id, e.device_id, e.event_name, e.message, e.extra
        FROM events e WHERE e.event_class = 'cef:524' AND e.ts > :t AND {_in(rule, 'e')}
        ORDER BY e.device_id, e.extra->>'vpn_name', e.ts DESC""", t=now - timedelta(hours=int(rule["params"].get("hours", 24))),
        rc=rule["client_id"])
    out = []
    for r in rows:
        x = r["extra"] or {}
        vpn, peer = x.get("vpn_name"), x.get("vpn_remote_gateway")
        back = (await s.execute(text("""
            SELECT least(
                (SELECT min(i.established_at) FROM vpn_tunnel_info i WHERE i.device_id = :d AND i.tunnel_name = :tn
                   AND i.status = 'established' AND i.established_at >= :at - interval '5 seconds' AND i.updated_at > :at),
                (SELECT min(u.ts) FROM events u WHERE u.device_id = :d AND u.ts > :at AND u.ts < :at + interval '1 day'
                   AND u.action IN ('vpn-tunnel-up', 'vpn-client-connected') AND :peer <> '' AND u.message LIKE '%' || :peer || '%'))"""),
            {"d": r["device_id"], "tn": f"ipsec:{vpn}", "at": r["ts"], "peer": peer or ""})).scalar()
        if ((back or now) - r["ts"]).total_seconds() < min_s:
            continue                                   # a short drop (or not yet long enough)
        if back is not None:
            reported = (await s.execute(text("""SELECT 1 FROM alerts WHERE rule_id = :r AND details->>'event_id' = :e LIMIT 1"""),
                                        {"r": rule["id"], "e": str(r["id"])})).first()
            if reported:
                continue                               # reported and back up -> the alert resolves
        keep = {k: x.get(k) for k in ("vpn_name", "vpn_type", "wan_id", "vpn_local_ip", "vpn_remote_gateway", "device_name")
                if x.get(k)}
        down = ((back or now) - r["ts"]).total_seconds()
        out.append(Finding(r["client_id"], f"s2s:{r['device_id']}:{vpn}", f"{r['event_name']}: {vpn}",
                           (r["message"] or r["event_name"]) + (f" Down for {int(down // 60)} min {int(down % 60)} s; back up at "
                                                                f"{back:%H:%M:%S} UTC." if back else ""),
                           r["device_id"], {**keep, "event": "cef:524", "event_id": str(r["id"]), "event_name": r["event_name"],
                                            "event_time": r["ts"].isoformat()}))
    return out


# ---------------------------------------------------------------------------------------------- access points / PoE
RADIO = {"ng": "2.4 GHz", "na": "5 GHz", "6e": "6 GHz"}
FRESH = "i.seen_at > :now - interval '10 minutes'"          # the console answered recently


def _uplink(extra: dict) -> str:
    up = (extra or {}).get("uplink") or {}
    return f"{up['device']} port {up['port']}" if up.get("device") and up.get("port") else (up.get("device") or "")


async def ap_offline(s, rule, now):
    """An access point the controller reports as disconnected for at least `minutes` (from its disconnected_at).
    APs offline longer than `ignore_after_days` are taken as removed hardware not yet removed from UniFi."""
    mins, days = int(rule["params"].get("minutes", 5)), int(rule["params"].get("ignore_after_days", 7))
    rows = await _rows(s, f"""
        SELECT d.client_id, i.poll_device_id, i.mac::text AS mac, i.name, i.model, i.extra,
               to_timestamp((i.extra->>'disconnected_at')::bigint) AS since
        FROM device_inventory i JOIN devices d ON d.id = i.poll_device_id
        WHERE i.type = 'uap' AND i.connected = false AND d.is_active AND {FRESH} AND {_in(rule, 'd')}
          AND i.extra ? 'disconnected_at'
          AND to_timestamp((i.extra->>'disconnected_at')::bigint) BETWEEN :now - make_interval(days => :days)
                                                                        AND :now - make_interval(mins => :mins)""",
        now=now, mins=mins, days=days, rc=rule["client_id"])
    return [Finding(r["client_id"], f"ap:{r['poll_device_id']}:{r['mac']}", f"Access point {r['name'] or r['mac']} is offline",
                    f"{r['name'] or r['mac']} ({r['model'] or 'AP'}) disconnected at {r['since']:%Y-%m-%d %H:%M} UTC"
                    + (f"; it connects to {_uplink(r['extra'])}." if _uplink(r["extra"]) else "."), r["poll_device_id"],
                    {"ap": r["name"], "ap_mac": r["mac"], "model": r["model"], "uplink": _uplink(r["extra"]),
                     "since": r["since"].isoformat()}) for r in rows]


async def wifi_quality(s, rule, now):
    """Per access point over the last `minutes` (every reading in the window, at least 3): channel utilisation at or
    above utilisation_pct (busy channel / interference), Wi-Fi experience below experience_pct while clients are
    connected, or at least weak_clients clients weaker than weak_dbm."""
    p = rule["params"]
    mins = int(p.get("minutes", 15))
    rows = await _rows(s, f"""
        SELECT m.client_id, m.poll_device_id, m.mac::text AS mac, max(m.name) AS name, count(*) AS n,
               min(m.cu_max) AS cu, mode() WITHIN GROUP (ORDER BY m.cu_radio) AS radio,
               max(coalesce(m.exp_min, 100)) AS exp_best, min(m.exp_min) AS exp_worst,
               count(*) FILTER (WHERE m.exp_min IS NOT NULL) AS exp_n,
               min((SELECT count(*) FROM unnest(m.signals) v WHERE v < :dbm)) AS weak,
               min((SELECT min(v) FROM unnest(m.signals) v)) AS weakest
        FROM ap_metrics m JOIN devices d ON d.id = m.poll_device_id
        WHERE m.ts > :t AND d.is_active AND {_in(rule, 'm')}
        GROUP BY 1, 2, 3 HAVING count(*) >= 3""", t=now - timedelta(minutes=mins), dbm=int(p.get("weak_dbm", -75)),
        rc=rule["client_id"])
    out = []
    for r in rows:
        name, key = r["name"] or r["mac"], f"{r['poll_device_id']}:{r['mac']}"
        base = {"ap": name, "ap_mac": r["mac"]}
        if r["cu"] is not None and r["cu"] >= int(p.get("utilisation_pct", 80)):
            band = RADIO.get(r["radio"], r["radio"] or "")
            out.append(Finding(r["client_id"], f"wifi-busy:{key}", f"High Wi-Fi channel utilisation on {name}",
                               f"The {band} channel of {name} has been at least {r['cu']} % busy for {mins} minutes "
                               "(interference from nearby networks or heavy use).", r["poll_device_id"],
                               {**base, "utilisation_pct": r["cu"], "band": band}))
        if r["exp_n"] == r["n"] and r["exp_best"] < int(p.get("experience_pct", 60)):
            out.append(Finding(r["client_id"], f"wifi-exp:{key}", f"Poor Wi-Fi experience on {name}",
                               f"UniFi's Wi-Fi experience score on {name} has stayed at or below {r['exp_best']} % for {mins} "
                               "minutes.", r["poll_device_id"], {**base, "experience_pct": r["exp_best"]}))
        if r["weak"] is not None and r["weak"] >= int(p.get("weak_clients", 2)):
            out.append(Finding(r["client_id"], f"wifi-weak:{key}", f"Clients with weak Wi-Fi signal on {name}",
                               f"{r['weak']} clients on {name} have had a signal weaker than {int(p.get('weak_dbm', -75))} dBm for "
                               f"{mins} minutes (weakest {r['weakest']} dBm): too far from the AP, or an AP is missing.",
                               r["poll_device_id"], {**base, "weak_clients": r["weak"], "weakest_dbm": r["weakest"]}))
    return out


async def poe_issue(s, rule, now):
    """PoE from the controller: an AP whose switch port reports PoE other than COMPATIBLE (UniFi: limited power),
    a switch using budget_pct of its PoE budget, or a port with PoE on and link up but PoE not good."""
    pct = float(rule["params"].get("budget_pct", 90))
    rows = await _rows(s, f"""
        SELECT d.client_id, i.poll_device_id, i.mac::text AS mac, i.name, i.type, i.extra
        FROM device_inventory i JOIN devices d ON d.id = i.poll_device_id
        WHERE d.is_active AND i.connected AND {FRESH} AND {_in(rule, 'd')}
          AND (i.extra->'uplink' ? 'poe' OR i.extra ? 'poe_budget' OR i.extra ? 'poe_faults')""", now=now, rc=rule["client_id"])
    out = []
    for r in rows:
        x, name, key = r["extra"] or {}, r["name"] or r["mac"], f"{r['poll_device_id']}:{r['mac']}"
        poe = (x.get("uplink") or {}).get("poe")
        if r["type"] == "uap" and poe and poe not in ("COMPATIBLE", "UNKNOWN"):
            out.append(Finding(r["client_id"], f"poe-ap:{key}", f"Access point {name} on insufficient PoE",
                               f"UniFi reports the PoE of {name}'s switch port ({_uplink(x)}) as {poe}: the AP may run with "
                               "limited power (reduced radios / speed). Use a PoE+ port or injector.", r["poll_device_id"],
                               {"ap": name, "uplink": _uplink(x), "poe": poe}))
        b = x.get("poe_budget") or {}
        if b.get("max_w") and 100 * float(b.get("used_w") or 0) / float(b["max_w"]) >= pct:
            used = 100 * float(b["used_w"]) / float(b["max_w"])
            out.append(Finding(r["client_id"], f"poe-budget:{key}", f"PoE budget nearly used on {name}",
                               f"{name} supplies {b['used_w']:.1f} W of its {b['max_w']:.0f} W PoE budget ({used:.0f} %); "
                               "another device may not get power.", r["poll_device_id"],
                               {"switch": name, "used_w": b["used_w"], "max_w": b["max_w"]}))
        if x.get("poe_faults"):
            ports = ", ".join(str(p) for p in x["poe_faults"])
            out.append(Finding(r["client_id"], f"poe-fault:{key}", f"PoE fault on {name}",
                               f"Port(s) {ports} of {name} have PoE on and a link up, but UniFi reports the PoE as not good.",
                               r["poll_device_id"], {"switch": name, "ports": x["poe_faults"]}))
    return out


EVALUATORS = {"device_offline": device_offline, "vpn_tunnel_down": vpn_tunnel_down, "vpn_flapping": vpn_flapping,
              "failed_logins": failed_logins, "config_change": config_change, "wan_failover": wan_failover,
              "outdated_firmware": outdated_firmware, "log_source_silent": log_source_silent, "event_match": event_match,
              "ioc_match": ioc_match, "storage_quota": storage_quota,
              "wan_down": wan_down, "internet_down": internet_down, "isp_degraded": isp_degraded,
              "server_health": server_health, "unifi_event": unifi_event, "vpn_disconnect": vpn_disconnect,
              "ap_offline": ap_offline, "wifi_quality": wifi_quality, "poe_issue": poe_issue}


# ---------------------------------------------------------------- delivery
def build_email(st: Settings, to: list[str], subject: str, body: str, html: str | None = None,
                cc: list[str] | None = None) -> EmailMessage:
    """Plain text plus (when given) the HTML version with the logo attached inline (cid), so it shows without
    "download pictures" prompts."""
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = st.smtp_from or st.smtp_user, ", ".join(to), subject
    if cc:
        msg["Cc"] = ", ".join(cc)                      # send_message() delivers to To and Cc
    msg.set_content(body)
    if html:
        from app import brand
        from app.alerts.notice import LOGO_CID
        msg.add_alternative(html, subtype="html")
        msg.get_payload()[1].add_related(brand.asset("logo-email.png").read_bytes(), "image", "png",
                                         cid=f"<{LOGO_CID}>", filename="logo.png", disposition="inline")
    return msg


def _send_email(st: Settings, to: list[str], subject: str, body: str, html: str | None = None,
                cc: list[str] | None = None) -> None:
    msg = build_email(st, to, subject, body, html, cc)
    with smtplib.SMTP(st.smtp_host, st.smtp_port, timeout=30) as smtp:
        if st.smtp_starttls:
            smtp.starttls(context=ssl.create_default_context())
        if st.smtp_user:
            smtp.login(st.smtp_user, st.smtp_password)
        smtp.send_message(msg)


async def deliver(channel: dict, alert: dict, kind: str, st: Settings) -> str:
    cfg = decrypt_secret(channel["config_enc"]) or {}
    from app import mail
    st = await mail.effective(st)                      # Admin -> Mail settings (subject prefix, SMTP), else .env
    from app.alerts.notice import render, render_html
    link = f"{st.public_url.rstrip('/')}/event-monitor/alerts/{alert['id']}" if st.public_url and alert.get("id") else ""
    subject, body = render(alert, kind, st.alert_subject_prefix, link)
    if channel["type"] == "email":
        if not st.smtp_host:
            return "not sent: SMTP is not configured"
        import asyncio
        if cfg.get("cc"):
            await asyncio.to_thread(_send_email, st, cfg.get("to", []), subject, body, render_html(alert, kind, link),
                                    cfg["cc"])
        else:
            await asyncio.to_thread(_send_email, st, cfg.get("to", []), subject, body, render_html(alert, kind, link))
        return "sent"
    payload = {"teams": {"@type": "MessageCard", "@context": "https://schema.org/extensions", "summary": subject,
                         "title": subject, "text": body.replace("\n", "<br>"),
                         "themeColor": {"critical": "D03B3B", "high": "EC835A", "medium": "FAB219"}.get(alert["severity"], "898781"),
                         **({"potentialAction": [{"@type": "OpenUri", "name": "Open in log server",
                                                  "targets": [{"os": "default", "uri": link}]}]} if link else {})},
               "slack": {"text": f"*{subject}*\n{body}"},
               "webhook": {"kind": kind, "alert": {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in alert.items()
                                                     if k != "notice"}, "subject": subject, "text": body}
               }[channel["type"]]
    async with httpx.AsyncClient(timeout=15) as http:
        r = await http.post(cfg["url"], json=payload)
    return "sent" if r.status_code < 300 else f"failed: HTTP {r.status_code}"


# ---------------------------------------------------------------- engine
class AlertEngine:
    def __init__(self, settings: Settings | None = None, deliver_fn=deliver):
        self.s = settings or get_settings()
        self.deliver = deliver_fn

    async def evaluate(self, now: datetime | None = None) -> dict:
        now = now or datetime.now(UTC)
        stats = {"opened": 0, "resolved": 0, "notified": 0}
        async with db.sessionmaker()() as s:
            rules = await _rows(s, """SELECT r.*, (SELECT array_agg(c.id) FROM clients c WHERE c.company_id = r.company_id) AS company_ids
                                      FROM alert_rules r WHERE r.enabled ORDER BY r.id""")
            for rule in rules:
                try:
                    findings = await EVALUATORS[rule["rule_type"]](s, rule, now)
                except Exception:  # noqa: BLE001 — one bad rule must not stop the others
                    log.exception("rule %s (%s) failed", rule["id"], rule["rule_type"])
                    await s.rollback()
                    continue
                seen: set[tuple[int, str]] = set()
                for f in findings:
                    seen.add((f.client_id, f.key))
                    row = (await s.execute(text("""
                        UPDATE alerts SET last_seen = :now, count = count + 1, message = :msg
                        WHERE rule_id = :r AND client_id = :c AND dedup_key = :k AND status <> 'resolved' RETURNING id"""),
                        {"now": now, "msg": f.message, "r": rule["id"], "c": f.client_id, "k": f.key})).first()
                    if row:
                        continue
                    aid = (await s.execute(text("""
                        INSERT INTO alerts (rule_id, client_id, device_id, dedup_key, severity, title, message, first_seen, last_seen, details)
                        VALUES (:r, :c, :d, :k, :sev, :t, :m, :now, :now, :det) RETURNING id"""),
                        {"r": rule["id"], "c": f.client_id, "d": f.device_id, "k": f.key, "sev": rule["severity"],
                         "t": f.title, "m": f.message, "now": now, "det": Jsonb(f.details)})).scalar()
                    stats["opened"] += 1
                    if rule.get("auto_incident"):
                        await create_incident(s, f.client_id, f.title, rule["severity"], "event-monitor", f.message, aid)
                        stats["incidents"] = stats.get("incidents", 0) + 1
                    if await self._throttled(s, rule, f, now):
                        continue
                    stats["notified"] += await self._notify(s, rule, aid, "open")
                if rule["rule_type"] in STATEFUL:
                    active = await _rows(s, "SELECT id, client_id, dedup_key FROM alerts WHERE rule_id = :r AND status <> 'resolved'",
                                         r=rule["id"])
                    for a in active:
                        if (a["client_id"], a["dedup_key"]) not in seen:
                            await s.execute(text("UPDATE alerts SET status = 'resolved', resolved_at = :now WHERE id = :i"),
                                            {"now": now, "i": a["id"]})
                            stats["resolved"] += 1
                            if rule["notify_resolve"]:
                                stats["notified"] += await self._notify(s, rule, a["id"], "resolve")
                await s.commit()
        return stats

    async def _throttled(self, s, rule, f: Finding, now) -> bool:
        if rule["throttle_minutes"] <= 0:
            return False
        last = (await s.execute(text("""
            SELECT max(n.sent_at) FROM notifications n JOIN alerts a ON a.id = n.alert_id
            WHERE a.rule_id = :r AND a.client_id = :c AND a.dedup_key = :k AND n.kind = 'open'"""),
            {"r": rule["id"], "c": f.client_id, "k": f.key})).scalar()
        return last is not None and now - last < timedelta(minutes=rule["throttle_minutes"])

    async def _notify(self, s, rule, alert_id: int, kind: str) -> int:
        alert = (await _rows(s, """SELECT a.*, c.name AS client, c.timezone AS client_tz, r.rule_type FROM alerts a JOIN clients c ON c.id = a.client_id
                                   JOIN alert_rules r ON r.id = a.rule_id WHERE a.id = :i""", i=alert_id))[0]
        from app.alerts.notice import build_notice
        try:
            alert["notice"] = await build_notice(s, alert)
        except Exception:  # noqa: BLE001 - a lookup problem must not stop the notification (plain format then)
            log.exception("alert %s: building the notification details failed", alert_id)
        # The rule's attached channels plus its own e-mail recipients (a channel owned by the rule).
        channels = await _rows(s, """SELECT * FROM notification_channels WHERE enabled
                                     AND (id = ANY(:ids) OR owner_rule_id = :r)
                                     AND (client_id IS NULL OR client_id = :c)
                                     AND (company_id IS NULL OR company_id = (SELECT company_id FROM clients WHERE id = :c))""",
                               ids=list(rule["channel_ids"] or []), r=rule["id"], c=alert["client_id"])
        sent = 0
        for ch in channels:
            try:
                status = await self.deliver(ch, alert, kind, self.s)
            except Exception as e:  # noqa: BLE001
                status = f"failed: {type(e).__name__}: {e}"[:300]
            await s.execute(text("INSERT INTO notifications (alert_id, channel_id, kind, status) VALUES (:a, :c, :k, :s)"),
                            {"a": alert_id, "c": ch["id"], "k": kind, "s": status})
            if status == "sent":
                sent += 1
        if not channels:  # still record that the alert was "raised" so throttling works without channels
            await s.execute(text("INSERT INTO notifications (alert_id, channel_id, kind, status) VALUES (:a, NULL, :k, 'no channels')"),
                            {"a": alert_id, "k": kind})
        if sent and kind == "open":
            await s.execute(text("UPDATE alerts SET notified_at = now() WHERE id = :i"), {"i": alert_id})
        return sent
