"""VPN state tracking from normalised events.

Tunnels (site-to-site / gateway VPN clients): events move a tunnel between up and down; each state is
an interval row in vpn_tunnel_state. Duplicate signals (e.g. UniFi logs both 'Link UP' and
'ClientConnected') are idempotent. If the device stops logging, the open interval is closed at its
last log and an 'unknown' interval opened (a log gap is not counted as up or down).

User sessions (remote-access VPN): connect/disconnect actions are paired per device + user into
vpn_sessions. A disconnect with no connect becomes a closed session with unknown start; a session
with no activity for `orphan_after` is marked orphaned and ended at its last activity.

Events are consumed in id order from a cursor (tracker_cursors), so the tracker resumes exactly where
it stopped. Events older than a tunnel's current interval are ignored, which also makes a parser
replay (same events, new ids) harmless."""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import psycopg

from app.config import Settings

log = logging.getLogger("tracker")
CURSOR = "vpn"

TUNNEL_UP = {"vpn-client-connected", "link-up", "vpn-tunnel-up"}
TUNNEL_DOWN = {"vpn-client-disconnected", "vpn-client-failed", "link-down", "lost-carrier", "vpn-tunnel-down"}
TUNNEL_CONNECTING = {"vpn-tunnel-connecting"}   # opens a 'down' interval only if the tunnel has no state yet
TUNNEL_DPD = {"vpn-ipsec-dpd-timeout"}           # no peer in the line: applies when exactly one IPsec tunnel is up
DUPLICATE_WITHIN = timedelta(seconds=10)         # the same user signal from two log sources (CEF + daemon line)
SESSION_START = {"vpn-user-connect"}
SESSION_END = {"vpn-user-disconnect"}

BATCH_SQL = """
    SELECT e.id, e.ts, e.client_id, e.device_id, e.action, e.interface, host(e.dst_ip) AS peer_ip, e.dst_port,
           e.user_name, host(e.src_ip) AS src_ip, e.bytes_in, e.bytes_out, e.extra
    FROM events e
    WHERE e.category = 'vpn' AND e.id > %s AND e.ts > %s
    ORDER BY e.id
    LIMIT %s
"""


@dataclass
class TrackerConfig:
    gap_after: timedelta = timedelta(minutes=15)      # device silent this long -> tunnel state unknown
    orphan_after: timedelta = timedelta(hours=24)     # open session silent this long -> orphaned
    lookback: timedelta = timedelta(days=7)           # never process events older than this
    batch: int = 1000


class VpnTracker:
    def __init__(self, settings: Settings, cfg: TrackerConfig | None = None):
        self.s = settings
        self.cfg = cfg or TrackerConfig()

    async def connect(self) -> psycopg.AsyncConnection:
        return await psycopg.AsyncConnection.connect(self.s.db_conninfo(), connect_timeout=5)

    # ------------------------------------------------------------------ main step
    async def run_once(self, conn: psycopg.AsyncConnection, now: datetime | None = None) -> int:
        now = now or datetime.now(UTC)
        async with conn.transaction():
            cur = await conn.execute(
                "INSERT INTO tracker_cursors (name) VALUES (%s) ON CONFLICT (name) DO NOTHING", (CURSOR,))
            cur = await conn.execute("SELECT last_event_id FROM tracker_cursors WHERE name = %s FOR UPDATE", (CURSOR,))
            (last_id,) = await cur.fetchone()
            cur = await conn.execute(BATCH_SQL, (last_id, now - self.cfg.lookback, self.cfg.batch))
            rows = await cur.fetchall()
            cols = [d.name for d in cur.description]
            for r in rows:
                ev = dict(zip(cols, r))
                await self._dispatch(conn, ev)
            if rows:
                await conn.execute("UPDATE tracker_cursors SET last_event_id = %s, updated_at = now() WHERE name = %s",
                                   (rows[-1][0], CURSOR))
        return len(rows)

    async def _dispatch(self, conn, ev) -> None:
        if ev["action"] in TUNNEL_DPD:
            await self._dpd_event(conn, ev)
        elif ev["action"] in TUNNEL_UP or ev["action"] in TUNNEL_DOWN or ev["action"] in TUNNEL_CONNECTING \
                or ev["interface"] or (ev["extra"] or {}).get("vpn_path"):
            await self._tunnel_event(conn, ev)
        if ev["action"] in SESSION_START or ev["action"] in SESSION_END:
            await self._session_event(conn, ev)

    async def _dpd_event(self, conn, ev) -> None:
        cur = await conn.execute("""SELECT tunnel_name FROM vpn_tunnel_state WHERE device_id = %s AND ended_at IS NULL
                                    AND state = 'up' AND tunnel_name LIKE 'IPsec %%'""", (ev["device_id"],))
        up = await cur.fetchall()
        if len(up) == 1:   # unambiguous; with several IPsec tunnels up the timeout cannot be attributed
            await self._tunnel_event(conn, {**ev, "interface": up[0][0], "action": "vpn-tunnel-down", "peer_ip": None})

    async def rebuild_client(self, conn: psycopg.AsyncConnection, client_id: int) -> int:
        """Re-derive one client's tunnel intervals and user sessions from its events, in time order (e.g. after an
        import of older logs). Poller-owned IPsec state ('ipsec:*') and tunnel aliases are left alone."""
        async with conn.transaction():
            await conn.execute("DELETE FROM vpn_sessions WHERE client_id = %s", (client_id,))
            await conn.execute("DELETE FROM vpn_tunnel_state WHERE client_id = %s AND tunnel_name NOT LIKE 'ipsec:%%'", (client_id,))
            cur = await conn.execute(BATCH_SQL.replace("e.id > %s AND e.ts > %s", "e.client_id = %s")
                                     .replace("ORDER BY e.id", "ORDER BY e.ts, e.id").replace("LIMIT %s", ""), (client_id,))
            cols = [d.name for d in cur.description]
            n = 0
            for r in await cur.fetchall():
                await self._dispatch(conn, dict(zip(cols, r)))
                n += 1
        return n

    async def housekeeping(self, conn: psycopg.AsyncConnection, now: datetime | None = None) -> None:
        """Log gaps -> unknown tunnel state; idle open sessions -> orphaned."""
        now = now or datetime.now(UTC)
        async with conn.transaction():
            cur = await conn.execute("""
                SELECT t.id, t.client_id, t.device_id, t.tunnel_name, t.peer, d.last_log_at
                FROM vpn_tunnel_state t JOIN devices d ON d.id = t.device_id
                WHERE t.ended_at IS NULL AND t.state <> 'unknown'
                  AND (d.last_log_at IS NULL OR d.last_log_at < %s)""", (now - self.cfg.gap_after,))
            for tid, cid, did, name, peer, last_log in await cur.fetchall():
                at = max(last_log or now, await self._started(conn, tid))
                await conn.execute("UPDATE vpn_tunnel_state SET ended_at = %s WHERE id = %s", (at, tid))
                await conn.execute(
                    "INSERT INTO vpn_tunnel_state (client_id, device_id, tunnel_name, peer, state, started_at, reason) "
                    "VALUES (%s, %s, %s, %s, 'unknown', %s, 'log-gap')", (cid, did, name, peer, at))
            await conn.execute("""
                UPDATE vpn_sessions SET status = 'orphaned', ended_at = last_seen_at, close_reason = 'no-disconnect-logged'
                WHERE status = 'open' AND last_seen_at < %s""", (now - self.cfg.orphan_after,))

    # ------------------------------------------------------------------ tunnels
    async def _started(self, conn, tid) -> datetime:
        cur = await conn.execute("SELECT started_at FROM vpn_tunnel_state WHERE id = %s", (tid,))
        return (await cur.fetchone())[0]

    async def _tunnel_name(self, conn, ev) -> str | None:
        path = (ev["extra"] or {}).get("vpn_path")
        iface = ev["interface"]
        if iface and path:
            await conn.execute(
                "INSERT INTO vpn_tunnel_aliases (device_id, alias, tunnel_name) VALUES (%s, %s, %s) "
                "ON CONFLICT (device_id, alias) DO UPDATE SET tunnel_name = EXCLUDED.tunnel_name",
                (ev["device_id"], path, iface))
            return iface
        if iface:
            return iface
        if path:
            cur = await conn.execute("SELECT tunnel_name FROM vpn_tunnel_aliases WHERE device_id = %s AND alias = %s",
                                     (ev["device_id"], path))
            row = await cur.fetchone()
            return row[0] if row else path
        return None

    async def _tunnel_event(self, conn, ev) -> None:
        name = await self._tunnel_name(conn, ev)
        if name is None:
            return
        new_state = ("up" if ev["action"] in TUNNEL_UP else "down" if ev["action"] in TUNNEL_DOWN
                     else "connecting" if ev["action"] in TUNNEL_CONNECTING else None)
        peer = f"{ev['peer_ip']}:{ev['dst_port']}" if ev["peer_ip"] and ev["dst_port"] else ev["peer_ip"]
        cur = await conn.execute(
            "SELECT id, state, started_at, peer FROM vpn_tunnel_state WHERE device_id = %s AND tunnel_name = %s AND ended_at IS NULL",
            (ev["device_id"], name))
        open_row = await cur.fetchone()
        if open_row and peer and open_row[3] != peer:
            await conn.execute("UPDATE vpn_tunnel_state SET peer = %s WHERE id = %s", (peer, open_row[0]))
        if new_state is None:
            return
        if new_state == "connecting":
            if open_row:
                return          # re-initiation of a known tunnel (rekey/reauth) says nothing new
            new_state = "down"  # first sight of a tunnel that is trying to connect
        if open_row:
            oid, ostate, ostarted, opeer = open_row
            if ev["ts"] < ostarted or ostate == new_state:
                return  # stale (out of order / replay) or a duplicate signal for the same state
            await conn.execute("UPDATE vpn_tunnel_state SET ended_at = %s WHERE id = %s", (ev["ts"], oid))
            peer = peer or opeer
        await conn.execute(
            "INSERT INTO vpn_tunnel_state (client_id, device_id, tunnel_name, peer, state, started_at, reason, event_id) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (ev["client_id"], ev["device_id"], name, peer, new_state, ev["ts"], ev["action"], ev["id"]))

    # ------------------------------------------------------------------ user sessions
    async def _session_event(self, conn, ev) -> None:
        extra = ev["extra"] or {}
        user, src = ev["user_name"], ev["src_ip"]
        cur = await conn.execute(
            "SELECT id, started_at FROM vpn_sessions WHERE device_id = %s AND user_name IS NOT DISTINCT FROM %s "
            "AND status = 'open' ORDER BY last_seen_at DESC LIMIT 1", (ev["device_id"], user))
        open_row = await cur.fetchone()
        # The same signal from a second log source (e.g. CEF 520 and the daemon's WireGuard line): ignore.
        cur = await conn.execute(
            "SELECT 1 FROM vpn_sessions WHERE device_id = %s AND user_name IS NOT DISTINCT FROM %s AND "
            "((%s AND started_at BETWEEN %s AND %s) OR (NOT %s AND ended_at BETWEEN %s AND %s)) LIMIT 1",
            (ev["device_id"], user, ev["action"] in SESSION_START, ev["ts"] - DUPLICATE_WITHIN, ev["ts"] + DUPLICATE_WITHIN,
             ev["action"] in SESSION_START, ev["ts"] - DUPLICATE_WITHIN, ev["ts"] + DUPLICATE_WITHIN))
        if await cur.fetchone():
            return
        if ev["action"] in SESSION_START:
            if open_row:
                # A new connect while one is open: the previous disconnect was lost.
                await conn.execute(
                    "UPDATE vpn_sessions SET status = 'closed', ended_at = %s, close_reason = 'superseded-by-new-connect' "
                    "WHERE id = %s", (ev["ts"], open_row[0]))
            await conn.execute(
                "INSERT INTO vpn_sessions (client_id, device_id, user_name, source_ip, assigned_ip, vpn_type, started_at, "
                "last_seen_at, status, start_event_id) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'open', %s)",
                (ev["client_id"], ev["device_id"], user, src, extra.get("assigned_ip"), extra.get("vpn_type"),
                 ev["ts"], ev["ts"], ev["id"]))
            return
        if open_row:
            await conn.execute(
                "UPDATE vpn_sessions SET status = 'closed', ended_at = %s, last_seen_at = %s, close_reason = 'disconnect', "
                "bytes_in = coalesce(%s, bytes_in), bytes_out = coalesce(%s, bytes_out), end_event_id = %s WHERE id = %s",
                (ev["ts"], ev["ts"], ev["bytes_in"], ev["bytes_out"], ev["id"], open_row[0]))
        else:
            # No connect seen: the start is known only if the disconnect reports the session duration.
            dur = extra.get("duration_s")
            started = ev["ts"] - timedelta(seconds=int(dur)) if isinstance(dur, int) else None
            await conn.execute(
                "INSERT INTO vpn_sessions (client_id, device_id, user_name, source_ip, assigned_ip, vpn_type, started_at, "
                "ended_at, last_seen_at, status, close_reason, bytes_in, bytes_out, end_event_id) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'closed', 'disconnect-without-connect', %s, %s, %s)",
                (ev["client_id"], ev["device_id"], user, src, extra.get("assigned_ip"), extra.get("vpn_type"),
                 started, ev["ts"], ev["ts"], ev["bytes_in"], ev["bytes_out"], ev["id"]))
