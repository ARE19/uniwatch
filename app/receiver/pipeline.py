"""Accepted messages -> bounded in-memory queue -> batched COPY into raw_logs.

The network handlers call ``submit()`` synchronously and it never blocks or awaits: when the
database is slow or down, messages queue up to ``receiver_queue_max`` and beyond that are counted
as dropped, so the listeners keep draining their sockets."""

import asyncio
import json
import logging
import time
from collections import Counter, deque
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import psycopg

from app.config import Settings
from app.receiver.framing import clean
from app.receiver.ratelimit import TokenBuckets

log = logging.getLogger("receiver")
SAMPLE_MAX = 2000


@dataclass(frozen=True)
class DeviceRef:
    device_id: int
    client_id: int
    api_flows: bool = False       # traffic flows already collected from the controller API: NetFlow would double them


class Pipeline:
    def __init__(self, settings: Settings):
        self.s = settings
        self.queue: deque[tuple] = deque()
        self.devices: dict[str, DeviceRef] = {}
        self.unknown: dict[str, list] = {}  # ip -> [count, first, last, sample, transport]
        self.rate = TokenBuckets(settings.receiver_rate_per_source, settings.receiver_burst_per_source)
        self.stats: Counter[str] = Counter()
        self.last_db_ok = 0.0
        self._reported: Counter[str] = Counter()  # stats at the last ingest_stats write
        self._conn: psycopg.AsyncConnection | None = None
        self._stop = asyncio.Event()
        self._lock = asyncio.Lock()  # one connection; serialise every DB operation on it
        self.devices_loaded = asyncio.Event()

    # ---------------------------------------------------------------- intake (sync, hot path)
    def submit(self, ip: str, transport: str, payload: bytes, truncated: bool = False) -> None:
        self.stats["received"] += 1
        if not self.rate.allow(ip, time.monotonic()):
            self.stats["rate_limited"] += 1
            return
        text, cut = clean(payload, self.s.receiver_max_message_bytes)
        if not text:
            self.stats["empty"] += 1
            return
        truncated = truncated or cut
        if truncated:
            self.stats["truncated"] += 1
        now = datetime.now(UTC)
        dev = self.devices.get(ip)
        if dev is None:
            self.stats["unknown"] += 1
            u = self.unknown.get(ip)
            if u is None:
                self.unknown[ip] = [1, now, now, text[:SAMPLE_MAX], transport]
            else:
                u[0] += 1
                u[2], u[3], u[4] = now, text[:SAMPLE_MAX], transport
            return
        if len(self.queue) >= self.s.receiver_queue_max:
            self.stats["dropped_queue_full"] += 1
            return
        self.queue.append((now, dev.client_id, dev.device_id, ip, transport, text, truncated))

    # ---------------------------------------------------------------- database
    async def _db(self) -> psycopg.AsyncConnection:
        if self._conn is None or self._conn.closed:
            self._conn = await psycopg.AsyncConnection.connect(self.s.db_conninfo(), autocommit=False, connect_timeout=5)
        return self._conn

    async def _drop_conn(self) -> None:
        if self._conn is not None:
            try:
                await self._conn.close()
            except Exception:  # noqa: BLE001
                pass
        self._conn = None

    async def refresh_devices(self) -> None:
        async with self._lock:
            conn = await self._db()
            async with conn.cursor() as cur:
                # Primary source IP plus any additional ones (second WAN etc.).
                await cur.execute(
                    "SELECT host(ip), d.id, d.client_id, coalesce((d.poll_config->>'collect_flows')::boolean, false) "
                    "FROM devices d, unnest(array_prepend(d.syslog_source_ip, d.alt_source_ips)) AS ip "
                    "WHERE d.is_active AND ip IS NOT NULL"
                )
                rows = await cur.fetchall()
            await conn.commit()
        self.devices = {ip: DeviceRef(did, cid, api) for ip, did, cid, api in rows}
        self.devices_loaded.set()
        self.last_db_ok = time.monotonic()

    async def flush_once(self) -> int:
        """COPY up to batch_max queued rows. On failure the rows go back to the front of the queue."""
        async with self._lock:
            return await self._flush_locked()

    async def _flush_locked(self) -> int:
        if not self.queue:
            return 0
        batch = [self.queue.popleft() for _ in range(min(len(self.queue), self.s.receiver_batch_max))]
        committed = False
        try:
            conn = await self._db()
            async with conn.cursor() as cur:
                async with cur.copy(
                    "COPY raw_logs (ts_received, client_id, device_id, source_ip, transport, raw, truncated) FROM STDIN"
                ) as cp:
                    for row in batch:
                        await cp.write_row(row)
                latest: dict[int, datetime] = {}
                for row in batch:
                    if row[2] not in latest or row[0] > latest[row[2]]:
                        latest[row[2]] = row[0]
                await cur.executemany(
                    "UPDATE devices SET last_log_at = %s WHERE id = %s AND (last_log_at IS NULL OR last_log_at < %s)",
                    [(ts, did, ts) for did, ts in latest.items()],
                )
            await conn.commit()
            committed = True
        except BaseException as e:  # never lose the batch: DB error *or* task cancellation
            if not committed:
                self.queue.extendleft(reversed(batch))
            if not isinstance(e, Exception):
                self._conn = None  # cancelled mid-transaction: abandon the connection
                raise
            self.stats["db_errors"] += 1
            log.warning("flush failed (%s: %s); %d rows kept in queue", type(e).__name__, e, len(self.queue))
            await self._drop_conn()
            raise
        self.stats["stored"] += len(batch)
        self.last_db_ok = time.monotonic()
        return len(batch)

    async def flush_unknown(self) -> None:
        if not self.unknown:
            return
        async with self._lock:
            await self._flush_unknown_locked()

    async def _flush_unknown_locked(self) -> None:
        # Drop IPs that became known devices since the lines arrived (registered within the refresh interval).
        pending = {ip: v for ip, v in self.unknown.items() if ip not in self.devices}
        self.unknown = {}
        if not pending:
            return
        try:
            conn = await self._db()
            async with conn.cursor() as cur:
                await cur.executemany(
                    """
                    INSERT INTO unknown_sources (source_ip, first_seen, last_seen, count, sample, last_transport)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (source_ip) DO UPDATE SET
                        last_seen = GREATEST(unknown_sources.last_seen, EXCLUDED.last_seen),
                        count = unknown_sources.count + EXCLUDED.count,
                        sample = EXCLUDED.sample,
                        last_transport = EXCLUDED.last_transport
                    """,
                    [(ip, first, last, n, sample, tr) for ip, (n, first, last, sample, tr) in pending.items()],
                )
            await conn.commit()
            self.last_db_ok = time.monotonic()
        except BaseException as e:  # noqa: BLE001
            # Merge back so counts are not lost.
            for ip, v in pending.items():
                cur_v = self.unknown.get(ip)
                if cur_v is None:
                    self.unknown[ip] = v
                else:
                    cur_v[0] += v[0]
                    cur_v[1] = min(cur_v[1], v[1])
            if not isinstance(e, Exception):
                self._conn = None
                raise
            self.stats["db_errors"] += 1
            log.warning("unknown-source upsert failed (%s: %s)", type(e).__name__, e)
            await self._drop_conn()

    # ---------------------------------------------------------------- loops
    async def run(self) -> None:
        tasks = [
            asyncio.create_task(self._flush_loop(), name="flush"),
            asyncio.create_task(self._periodic(self.s.receiver_device_refresh_seconds, self._refresh_safe), name="devices"),
            asyncio.create_task(self._periodic(5.0, self.flush_unknown), name="unknown"),
            asyncio.create_task(self._periodic(60.0, self._report), name="stats"),
        ]
        await self._stop.wait()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _refresh_safe(self) -> None:
        try:
            await self.refresh_devices()
        except Exception as e:  # noqa: BLE001
            log.warning("device refresh failed (%s: %s); keeping %d cached mappings", type(e).__name__, e, len(self.devices))
            await self._drop_conn()

    async def _periodic(self, every: float, fn) -> None:
        while True:
            await fn()
            await asyncio.sleep(every)

    async def _flush_loop(self) -> None:
        backoff = 0.0
        while True:
            try:
                while await self.flush_once() >= self.s.receiver_batch_max:
                    pass  # keep draining a backlog without sleeping
                backoff = 0.0
            except Exception:  # noqa: BLE001
                backoff = min(30.0, backoff * 2 or 1.0)
            self._heartbeat()
            await asyncio.sleep(self.s.receiver_flush_seconds + backoff)

    def _heartbeat(self) -> None:
        # Healthy = loop alive and the database answered within the last minute.
        if time.monotonic() - self.last_db_ok < 60:
            try:
                Path(self.s.receiver_heartbeat_file).write_text(str(time.time()))
            except OSError:
                pass

    async def _report(self) -> None:
        self.rate.prune(time.monotonic())
        delta = self.stats - self._reported  # Counter subtraction keeps positives only
        try:
            async with self._lock:
                conn = await self._db()
                await conn.execute(
                    """INSERT INTO ingest_stats (ts, component, received, stored, unknown, rate_limited, dropped, queue_depth)
                       VALUES (date_trunc('minute', now()), 'receiver', %s, %s, %s, %s, %s, %s)
                       ON CONFLICT (component, ts) DO UPDATE SET
                         received = ingest_stats.received + EXCLUDED.received, stored = ingest_stats.stored + EXCLUDED.stored,
                         unknown = ingest_stats.unknown + EXCLUDED.unknown,
                         rate_limited = ingest_stats.rate_limited + EXCLUDED.rate_limited,
                         dropped = ingest_stats.dropped + EXCLUDED.dropped, queue_depth = EXCLUDED.queue_depth""",
                    (delta["received"], delta["stored"], delta["unknown"], delta["rate_limited"],
                     delta["dropped_queue_full"], len(self.queue)),
                )
                await conn.commit()
            self._reported = Counter(self.stats)
        except Exception as e:  # noqa: BLE001 — stats are best-effort
            log.warning("ingest_stats write failed (%s: %s)", type(e).__name__, e)
            await self._drop_conn()
        log.info(json.dumps({"stats": dict(self.stats), "queue": len(self.queue), "devices": len(self.devices),
                             "unknown_pending": len(self.unknown)}))

    def request_stop(self) -> None:
        self._stop.set()

    async def drain(self, timeout: float = 20.0) -> None:
        """Final flush on shutdown, after the background loops have stopped."""
        deadline = time.monotonic() + timeout
        while self.queue and time.monotonic() < deadline:
            try:
                await self.flush_once()
            except Exception:  # noqa: BLE001
                await asyncio.sleep(1)
        await self.flush_unknown()
        if self.queue:
            log.error("shutdown with %d unflushed messages", len(self.queue))
        await self._drop_conn()
