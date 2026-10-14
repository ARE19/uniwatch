"""Parser service and replay command.

    python -m app.parserd                       # run the worker (container default)
    python -m app.parserd replay --client nwhk --since 2026-10-06T00:00:00+08:00 [--until ...] [--device NAME] [--failed-only]
    python -m app.parserd vpn-rebuild           # recompute VPN tunnel/session state from events
    python -m app.parserd vpn-rebuild --client cts-kl   # only that client, in time order (keeps aliases/poller state)
    python -m app.parserd import-files --client cts-kl --device CTS-KL [--skip REGEX ...] FILE...

Replay marks raw lines unparsed again and deletes the events/config changes made from them, so the
running workers re-parse them with the current parser code."""

import argparse
import asyncio
import logging
import signal
import sys
from datetime import datetime

import psycopg
from psycopg.types.json import Jsonb

from app.config import get_settings
from app.enrich import geoip
from app.parserd.worker import ParserWorker
from app.tracker.vpn import VpnTracker

log = logging.getLogger("parser")


async def serve() -> None:
    s = get_settings()
    await asyncio.to_thread(geoip.update)  # no-op when files are fresh; never raises
    worker = ParserWorker(s, geoip.GeoIP(), old_backlog_every=300.0)
    if not worker.geo.available:
        log.warning("no GeoIP database available; events will not be enriched")
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, worker.stop)

    async def refresh_geo():
        while True:
            await asyncio.sleep(86400)
            if await asyncio.to_thread(geoip.update):
                worker.geo = geoip.GeoIP()

    tracker = VpnTracker(s)

    async def track():
        """VPN tunnel/session state machine, fed from parsed events."""
        conn, last_house, backoff = None, 0.0, 0.0
        while not worker._stop.is_set():
            try:
                conn = conn or await tracker.connect()
                n = await tracker.run_once(conn)
                if loop.time() - last_house > 60:
                    await tracker.housekeeping(conn)
                    last_house = loop.time()
                backoff = 0.0
                if n < tracker.cfg.batch:
                    await asyncio.sleep(2)
            except Exception as e:  # noqa: BLE001
                backoff = min(30.0, backoff * 2 or 1.0)
                log.warning("vpn tracker failed (%s: %s); retry in %.0fs", type(e).__name__, e, backoff)
                if conn is not None:
                    await conn.close()
                conn = None
                await asyncio.sleep(backoff)

    tasks = [asyncio.create_task(refresh_geo()), asyncio.create_task(track())]
    await worker.run()
    for t in tasks:
        t.cancel()


async def replay(args) -> int:
    s = get_settings()
    since = datetime.fromisoformat(args.since)
    until = datetime.fromisoformat(args.until) if args.until else datetime.now(since.tzinfo)
    if since.tzinfo is None or until.tzinfo is None:
        print("--since/--until need a UTC offset, e.g. 2026-10-06T00:00:00+08:00", file=sys.stderr)
        return 2
    async with await psycopg.AsyncConnection.connect(s.db_conninfo()) as conn:
        async with conn.transaction():
            cur = await conn.execute("SELECT id FROM clients WHERE slug = %s", (args.client,))
            row = await cur.fetchone()
            if row is None:
                print(f"no such client: {args.client}", file=sys.stderr)
                return 1
            client_id = row[0]
            device_filter, params = "", [client_id, since, until]
            if args.device:
                cur = await conn.execute("SELECT id FROM devices WHERE client_id = %s AND name = %s", (client_id, args.device))
                d = await cur.fetchone()
                if d is None:
                    print(f"no such device: {args.device}", file=sys.stderr)
                    return 1
                device_filter, params = " AND device_id = %s", [*params, d[0]]
            scope = f"client_id = %s AND {{ts}} >= %s AND {{ts}} < %s{device_filter}"
            failed_only = " AND parse_error IS NOT NULL" if args.failed_only else ""
            deleted = 0
            if not args.failed_only:
                cur = await conn.execute(f"DELETE FROM config_changes WHERE {scope.format(ts='raw_ts')}", params)
                cur = await conn.execute(f"DELETE FROM events WHERE {scope.format(ts='raw_ts')}", params)
                deleted = cur.rowcount
            cur = await conn.execute(
                f"UPDATE raw_logs SET parsed = false, parse_error = NULL WHERE {scope.format(ts='ts_received')}{failed_only}",
                params)
            requeued = cur.rowcount
            await conn.execute(
                "INSERT INTO audit_log (username, action, client_id, details) VALUES ('cli', 'parser_replay', %s, %s)",
                (client_id, Jsonb({"since": since.isoformat(), "until": until.isoformat(),
                                                      "device": args.device, "failed_only": args.failed_only,
                                                      "events_deleted": deleted, "requeued": requeued})))
    print(f"replay: {requeued} raw lines re-queued, {deleted} events deleted; workers will re-parse them")
    return 0


async def vpn_rebuild_client(slug: str) -> int:
    s = get_settings()
    async with await psycopg.AsyncConnection.connect(s.db_conninfo()) as conn:
        cur = await conn.execute("SELECT id FROM clients WHERE slug = %s", (slug,))
        row = await cur.fetchone()
        if row is None:
            raise SystemExit(f"no client {slug!r}")
        n = await VpnTracker(s).rebuild_client(conn, row[0])
        await conn.execute("INSERT INTO audit_log (username, action, client_id, details) VALUES ('cli', 'vpn_rebuild', %s, %s)",
                           (row[0], Jsonb({"client": slug, "events": n})))
        await conn.commit()
    print(f"vpn state for {slug} rebuilt from {n} events")
    return 0


async def import_files(args) -> int:
    from app.parserd.importer import import_files as run
    st = await run(get_settings().db_conninfo(), args.client, args.device, args.files, args.skip or [])
    print(f"import: {st['lines']} lines read, {st['stored']} stored, {st['duplicates']} duplicates, "
          f"{st['skipped_noise']} noise lines skipped, {st['no_timestamp']} without timestamp; "
          f"files already imported: {st['skipped_files'] or 'none'}")
    if st["stored"] and not args.no_refresh:
        await refresh_insights_after_import(args.client)
    return 0


async def refresh_insights_after_import(slug: str, wait_minutes: int = 60) -> None:
    """Insight summaries (continuous aggregates) only re-scan the last 3 days on their own, so imported history is
    summarised explicitly: wait until the workers have parsed the client's lines, then refresh over the imported span."""
    import time as _time
    s = get_settings()
    deadline = _time.monotonic() + wait_minutes * 60
    async with await psycopg.AsyncConnection.connect(s.db_conninfo(), autocommit=True) as conn:
        while True:
            cur = await conn.execute("""SELECT count(*) FILTER (WHERE NOT r.parsed), min(r.ts_received) FROM raw_logs r
                                        JOIN clients c ON c.id = r.client_id WHERE c.slug = %s AND r.transport = 'import'""", (slug,))
            pending, oldest = await cur.fetchone()
            if not pending or _time.monotonic() > deadline:
                break
            print(f"waiting for the parser: {pending} imported lines left")
            await asyncio.sleep(15)
    if oldest is not None:
        await refresh_aggregates(oldest)


async def refresh_aggregates(since) -> None:
    """Recompute every continuous aggregate from `since` (owner role: it owns the aggregates)."""
    from psycopg.conninfo import make_conninfo
    s = get_settings()
    owner = make_conninfo(host=s.db_host, port=s.db_port, dbname=s.db_name, user=s.db_owner_user, password=s.db_owner_password)
    async with await psycopg.AsyncConnection.connect(owner, autocommit=True) as conn:
        cur = await conn.execute("SELECT view_name FROM timescaledb_information.continuous_aggregates")
        for (view,) in await cur.fetchall():
            # whole buckets only: start a day before the first imported line so its bucket is included
            await conn.execute(f"CALL refresh_continuous_aggregate('{view}', CAST(%s AS timestamptz) - interval '1 day', "
                               "now() - interval '1 hour')", (since,))
            print(f"insights summary refreshed: {view}")


async def vpn_rebuild() -> int:
    """VPN tunnel/session state is derived from events: drop it and let the tracker rebuild from the cursor at 0."""
    s = get_settings()
    async with await psycopg.AsyncConnection.connect(s.db_conninfo()) as conn:
        async with conn.transaction():
            for t in ("vpn_tunnel_state", "vpn_tunnel_aliases", "vpn_sessions"):
                await conn.execute(f"DELETE FROM {t}")
            await conn.execute("UPDATE tracker_cursors SET last_event_id = 0 WHERE name = 'vpn'")
            await conn.execute("INSERT INTO audit_log (username, action) VALUES ('cli', 'vpn_rebuild')")
    print("vpn state cleared; the tracker rebuilds it from events (last 7 days) within a minute")
    return 0


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    p = argparse.ArgumentParser(prog="app.parserd")
    sub = p.add_subparsers(dest="cmd")
    r = sub.add_parser("replay")
    r.add_argument("--client", required=True)
    r.add_argument("--since", required=True, help="ISO time, e.g. 2026-10-06T00:00:00+08:00")
    r.add_argument("--until")
    r.add_argument("--device")
    r.add_argument("--failed-only", action="store_true")
    vr = sub.add_parser("vpn-rebuild")
    vr.add_argument("--client", help="only this client (slug), in time order")
    im = sub.add_parser("import-files", help="import log files copied from a device")
    im.add_argument("--client", required=True)
    im.add_argument("--device", required=True)
    im.add_argument("--skip", action="append", help="regex of lines to leave out (repeatable)")
    im.add_argument("--no-refresh", action="store_true", help="do not wait for parsing / refresh Insights summaries")
    im.add_argument("files", nargs="+")
    args = p.parse_args()
    if args.cmd == "import-files":
        return asyncio.run(import_files(args))
    if args.cmd == "replay":
        return asyncio.run(replay(args))
    if args.cmd == "vpn-rebuild":
        return asyncio.run(vpn_rebuild_client(args.client) if args.client else vpn_rebuild())
    asyncio.run(serve())
    return 0


if __name__ == "__main__":
    sys.exit(main())
