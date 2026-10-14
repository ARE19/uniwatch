"""Import log files copied from a device (e.g. a UniFi console's /var/log) as raw lines of that device.

Each line becomes a raw_logs row with transport 'import' and ts_received = the line's own timestamp, so imported
history sorts and ages (retention) like live logs; the normal parser workers then turn it into events.
- .zst / .gz / plain files; exact duplicate lines across files are stored once (syslog-ng writes some messages
  to several files, e.g. charon to daemon.log and auth.log)
- a file already imported for the device (same SHA-256) is skipped, so re-running is safe
- --skip REGEX drops noise lines (e.g. driver chatter)"""

import gzip
import hashlib
import io
import os
import re
from datetime import UTC, datetime

import psycopg
import zstandard
from psycopg.types.json import Jsonb

from app.parsers.model import ParseError
from app.parsers.syslog import parse_header


def _open(path: str):
    raw = open(path, "rb")
    if path.endswith(".zst"):
        return io.TextIOWrapper(zstandard.ZstdDecompressor().stream_reader(raw), encoding="utf-8", errors="replace")
    if path.endswith(".gz"):
        return io.TextIOWrapper(gzip.GzipFile(fileobj=raw), encoding="utf-8", errors="replace")
    return io.TextIOWrapper(raw, encoding="utf-8", errors="replace")


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


async def import_files(conninfo: str, client: str, device: str, paths: list[str], skip: list[str], tz: str | None = None) -> dict:
    skip_re = [re.compile(p) for p in skip]
    async with await psycopg.AsyncConnection.connect(conninfo, autocommit=True) as conn:
        cur = await conn.execute("""SELECT d.id, d.client_id, host(d.syslog_source_ip), c.timezone FROM devices d
                                    JOIN clients c ON c.id = d.client_id WHERE c.slug = %s AND d.name = %s""", (client, device))
        row = await cur.fetchone()
        if row is None:
            raise SystemExit(f"no device {device!r} for client {client!r}")
        device_id, client_id, source_ip, client_tz = row
        tz = tz or client_tz
        cur = await conn.execute("""SELECT jsonb_object_keys(details->'files') FROM audit_log
                                    WHERE action = 'log_import' AND details->>'device_id' = %s""", (str(device_id),))
        done = {r[0] for r in await cur.fetchall()}

        seen: set[bytes] = set()
        stats = {"files": {}, "lines": 0, "stored": 0, "duplicates": 0, "skipped_noise": 0, "skipped_files": [],
                 "no_timestamp": 0}
        for path in paths:
            digest = _sha256(path)
            name = os.path.basename(path)
            if digest in done:
                stats["skipped_files"].append(name)
                continue
            fallback = datetime.fromtimestamp(os.path.getmtime(path), UTC)
            rows: list[tuple] = []
            with _open(path) as f:
                for line in f:
                    line = line.rstrip("\r\n").replace("\x00", "")   # like the receiver: PostgreSQL text has no NUL
                    if not line.strip():
                        continue
                    stats["lines"] += 1
                    if any(r.search(line) for r in skip_re):
                        stats["skipped_noise"] += 1
                        continue
                    key = hashlib.blake2b(line.encode(), digest_size=16).digest()
                    if key in seen:
                        stats["duplicates"] += 1
                        continue
                    seen.add(key)
                    try:
                        ts = parse_header(line, tz).ts
                    except ParseError:
                        ts = fallback
                        stats["no_timestamp"] += 1
                    rows.append((ts, client_id, device_id, source_ip, "import", line[:16384], len(line) > 16384))
            # One file = one transaction, recorded as imported in the same transaction: a failure leaves nothing
            # half-stored, and a re-run skips exactly the files that completed.
            async with conn.transaction():
                stored = await _copy(conn, rows)
                await conn.execute("INSERT INTO audit_log (username, action, target, client_id, details) "
                                   "VALUES ('cli', 'log_import', %s, %s, %s)",
                                   (device, client_id, Jsonb({"device_id": str(device_id),
                                                              "files": {digest: {"name": name, "stored": stored}}})))
            stats["stored"] += stored
            stats["files"][digest] = {"name": name, "stored": stored}
        return stats


async def _copy(conn, rows) -> int:
    if not rows:
        return 0
    async with conn.cursor() as c:
        async with c.copy("COPY raw_logs (ts_received, client_id, device_id, source_ip, transport, raw, truncated) FROM STDIN") as cp:
            for r in rows:
                await cp.write_row(r)
    return len(rows)
