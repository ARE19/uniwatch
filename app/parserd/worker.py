"""Parser workers: raw_logs (parsed = false) -> events.

Work is claimed with SELECT ... FOR UPDATE SKIP LOCKED, so any number of workers (threads,
containers) can run side by side. Each batch is one transaction: events are inserted and the raw
rows are marked parsed together, so a crash never loses or duplicates work.
A line that cannot be parsed keeps its raw text, gets parse_error set, and is counted as failed."""

import asyncio
import logging
import time
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb

from app.config import Settings
from app.enrich.geoip import GeoIP
from app.parsers.model import Event, ParseError
from app.parsers.vendors import module_for

log = logging.getLogger("parser")

# The claim is limited to recent lines (a constant lower bound, executed unprepared so only those chunks are planned
# and locked). Unbounded, every batch took a lock on EVERY chunk of raw_logs, and TimescaleDB's compression of a
# 2-day-old chunk (which needs an exclusive lock) and the parser blocked each other: parsing stood still for 14
# minutes on 2026-10-13 until the compression job failed with a deadlock.
CLAIM_SQL = """
    SELECT r.id, r.ts_received, r.client_id, r.device_id, r.raw, d.vendor, c.timezone
    FROM raw_logs r
    JOIN devices d ON d.id = r.device_id
    JOIN clients c ON c.id = r.client_id
    WHERE NOT r.parsed AND r.ts_received >= %s
    ORDER BY r.ts_received
    LIMIT %s
    FOR UPDATE OF r SKIP LOCKED
"""
# Older unparsed lines (imported history, or a backlog after a long stop): looked for only now and then, and never
# waiting for a lock: lock_timeout is kept BELOW the server's deadlock_timeout (1 s), otherwise the deadlock detector
# cancels the compression job instead of this query giving way.
CLAIM_OLD_SQL = """
    SELECT r.id, r.ts_received, r.client_id, r.device_id, r.raw, d.vendor, c.timezone
    FROM raw_logs r
    JOIN devices d ON d.id = r.device_id
    JOIN clients c ON c.id = r.client_id
    WHERE NOT r.parsed AND r.ts_received < %s
    ORDER BY r.ts_received
    LIMIT %s
    FOR UPDATE OF r SKIP LOCKED
"""
EVENT_COLUMNS = (
    "ts", "client_id", "device_id", "raw_id", "raw_ts", "vendor", "category", "severity", "severity_raw",
    "event_class", "event_name", "action", "outcome", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "src_mac", "dst_mac", "user_name", "rule", "interface", "bytes_in", "bytes_out", "host", "process", "message",
    "src_country", "dst_country", "src_asn", "dst_asn", "extra",
)
COPY_SQL = f"COPY events ({', '.join(EVENT_COLUMNS)}) FROM STDIN"
# The explicit time bounds let TimescaleDB plan only the batch's chunks. Joined on the unnest() alone, the update
# planned every chunk and touched compressed ones (imported history), which hits the decompression limit and stalls
# parsing. Executed unprepared, so the bounds are always planned as constants (a generic plan keeps every chunk).
MARK_SQL = """
    UPDATE raw_logs SET parsed = true, parse_error = u.err
    FROM unnest(%s::bigint[], %s::timestamptz[], %s::text[]) AS u(id, ts, err)
    WHERE raw_logs.id = u.id AND raw_logs.ts_received = u.ts
      AND raw_logs.ts_received >= %s AND raw_logs.ts_received <= %s
"""
CONFIG_SQL = """
    INSERT INTO config_changes (ts, client_id, device_id, raw_id, raw_ts, admin_user, source_ip, action, summary, details)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""
STATS_SQL = """
    INSERT INTO ingest_stats (ts, component, parsed, failed, lag_avg_ms, lag_max_ms)
    VALUES (%s, 'parser', %s, %s, %s, %s)
    ON CONFLICT (component, ts) DO UPDATE SET
        parsed = coalesce(ingest_stats.parsed, 0) + EXCLUDED.parsed,
        failed = coalesce(ingest_stats.failed, 0) + EXCLUDED.failed,
        lag_avg_ms = EXCLUDED.lag_avg_ms,
        lag_max_ms = GREATEST(ingest_stats.lag_max_ms, EXCLUDED.lag_max_ms)
"""
# A device clock this far from the receive time is not trusted for the event timestamp.
MAX_CLOCK_SKEW = timedelta(days=30)


def enrich(ev: Event, geo: GeoIP | None) -> None:
    if geo is None or not geo.available:
        return
    for side in ("src", "dst"):
        ip = getattr(ev, f"{side}_ip")
        if ip and (g := geo.lookup(ip)):
            setattr(ev, f"{side}_country", g.country)
            setattr(ev, f"{side}_asn", g.asn)
            if g.as_org:
                ev.extra[f"{side}_as_org"] = g.as_org


def to_row(ev: Event, raw_id: int, raw_ts: datetime, client_id: int, device_id: int) -> tuple:
    if abs(ev.ts - raw_ts) > MAX_CLOCK_SKEW:
        ev.extra["ts_device"] = ev.ts.isoformat()
        ev.ts = raw_ts
    values = {
        **{c: getattr(ev, c, None) for c in EVENT_COLUMNS},
        "client_id": client_id, "device_id": device_id, "raw_id": raw_id, "raw_ts": raw_ts,
        "extra": Jsonb(ev.extra),
    }
    return tuple(values[c] for c in EVENT_COLUMNS)


class ParserWorker:
    def __init__(self, settings: Settings, geo: GeoIP | None = None, batch_size: int = 1000,
                 claim_window: timedelta = timedelta(hours=36), old_backlog_every: float = 0.0):
        self.s = settings
        self.geo = geo
        self.batch_size = batch_size
        self.claim_window = claim_window            # shorter than the 2 days after which raw_logs chunks are compressed
        self.old_backlog_every = old_backlog_every  # seconds between looks for older unparsed lines (0 = every time)
        self._old_last = float("-inf")
        self.conn: psycopg.AsyncConnection | None = None
        self.stats: Counter[str] = Counter()
        self._minute: dict = {"parsed": 0, "failed": 0, "lag_sum": 0, "lag_max": 0}
        self._stop = asyncio.Event()
        self.heartbeat_file = Path("/tmp/parser-heartbeat")

    async def _db(self) -> psycopg.AsyncConnection:
        if self.conn is None or self.conn.closed:
            self.conn = await psycopg.AsyncConnection.connect(self.s.db_conninfo(), connect_timeout=5)
        return self.conn

    async def run_once(self, now: datetime | None = None) -> int:
        """Parse one batch of recent lines; when caught up, also (now and then) a batch of older ones.
        Returns the number of raw rows processed."""
        edge = datetime.now(UTC) - self.claim_window
        n = await self._batch(CLAIM_SQL, edge, now)
        if n < self.batch_size and time.monotonic() - self._old_last >= self.old_backlog_every:
            self._old_last = time.monotonic()
            try:
                old = await self._batch(CLAIM_OLD_SQL, edge, now, lock_timeout="500ms")
                if old >= self.batch_size:
                    self._old_last = float("-inf")     # a backlog of old lines (an import): keep going without the pause
                n += old
            except psycopg.errors.LockNotAvailable:
                log.info("older unparsed lines: chunk busy (maintenance), trying again later")
        return n

    async def _batch(self, claim_sql: str, edge: datetime, now: datetime | None, lock_timeout: str | None = None) -> int:
        conn = await self._db()
        async with conn.transaction():
            async with conn.cursor() as cur:
                if lock_timeout:
                    await cur.execute(f"SET LOCAL lock_timeout = '{lock_timeout}'")
                await cur.execute(claim_sql, (edge, self.batch_size), prepare=False)
                rows = await cur.fetchall()
                if not rows:
                    return 0
                now = now or datetime.now(UTC)
                event_rows, config_rows, ids, tss, errs = [], [], [], [], []
                for raw_id, raw_ts, client_id, device_id, raw, vendor, tz in rows:
                    err = None
                    try:
                        ev = module_for(vendor).parse(raw, tz, now)
                        enrich(ev, self.geo)
                        event_rows.append(to_row(ev, raw_id, raw_ts, client_id, device_id))
                        if ev.config_change:
                            c = ev.config_change
                            config_rows.append((ev.ts, client_id, device_id, raw_id, raw_ts, c.get("admin_user"),
                                                c.get("source_ip"), c.get("action", "modify"), c.get("summary", ""),
                                                Jsonb(c.get("details") or {})))
                    except ParseError as e:
                        err = str(e)[:500]
                    except Exception as e:  # noqa: BLE001 — a parser bug must not stop ingestion
                        err = f"internal parser error: {type(e).__name__}: {e}"[:500]
                        log.exception("parser crashed on raw %s", raw_id)
                    ids.append(raw_id)
                    tss.append(raw_ts)
                    errs.append(err)
                    lag = int((now - raw_ts).total_seconds() * 1000)
                    self._minute["lag_sum"] += lag
                    self._minute["lag_max"] = max(self._minute["lag_max"], lag)
                if event_rows:
                    async with cur.copy(COPY_SQL) as cp:
                        for r in event_rows:
                            await cp.write_row(r)
                if config_rows:
                    await cur.executemany(CONFIG_SQL, config_rows)
                await cur.execute(MARK_SQL, (ids, tss, errs, min(tss), max(tss)), prepare=False)
        failed = sum(1 for e in errs if e)
        self.stats["parsed"] += len(rows) - failed
        self.stats["failed"] += failed
        self._minute["parsed"] += len(rows) - failed
        self._minute["failed"] += failed
        return len(rows)

    async def flush_stats(self) -> None:
        m, self._minute = self._minute, {"parsed": 0, "failed": 0, "lag_sum": 0, "lag_max": 0}
        n = m["parsed"] + m["failed"]
        minute = datetime.now(UTC).replace(second=0, microsecond=0)
        conn = await self._db()
        async with conn.transaction():
            await conn.execute(STATS_SQL, (minute, m["parsed"], m["failed"], m["lag_sum"] // n if n else 0, m["lag_max"]))

    async def run(self) -> None:
        last_stats = time.monotonic()
        backoff = 0.0
        while not self._stop.is_set():
            try:
                n = await self.run_once()
                if time.monotonic() - last_stats >= 60:
                    await self.flush_stats()
                    last_stats = time.monotonic()
                    log.info("parsed=%d failed=%d", self.stats["parsed"], self.stats["failed"])
                self.heartbeat_file.write_text(str(time.time()))
                backoff = 0.0
                if n < self.batch_size:
                    await asyncio.wait_for(self._stop.wait(), timeout=1.0)
            except TimeoutError:
                pass
            except Exception as e:  # noqa: BLE001
                backoff = min(30.0, backoff * 2 or 1.0)
                log.warning("batch failed (%s: %s); retrying in %.0fs", type(e).__name__, e, backoff)
                if self.conn is not None:
                    await self.conn.close()
                self.conn = None
                await asyncio.sleep(backoff)

    def stop(self) -> None:
        self._stop.set()
