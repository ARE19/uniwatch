"""Poller service and setup commands.

    python -m app.poller                                    # run (container default)
    python -m app.poller set-unifi --device NW-HK --client nwhk --url https://192.168.1.1 [--site default] < api.key
    python -m app.poller poll-once --device NW-HK --client nwhk   # test a configuration, prints a summary

The API key is read from stdin so it never appears in shell history or the process list. It is stored
encrypted with SECRET_KEY and never shown again."""

import argparse
import asyncio
import logging
import signal
import sys

import psycopg
from psycopg.types.json import Jsonb

from app.config import get_settings
from app.drivers import DRIVERS
from app.drivers.base import decrypt_secret, encrypt_secret
from app.poller.service import Poller


async def _device(conn, client: str, device: str) -> tuple[int, dict]:
    cur = await conn.execute(
        "SELECT d.id, d.poll_config FROM devices d JOIN clients c ON c.id = d.client_id WHERE c.slug = %s AND d.name = %s",
        (client, device))
    row = await cur.fetchone()
    if row is None:
        raise SystemExit(f"no device {device!r} for client {client!r}")
    return row


async def set_unifi(a) -> int:
    key = sys.stdin.readline().strip()
    if not key:
        raise SystemExit("API key expected on stdin")
    async with await psycopg.AsyncConnection.connect(get_settings().db_conninfo()) as conn:
        async with conn.transaction():
            device_id, cfg = await _device(conn, a.client, a.device)
            new_cfg = {"driver": "unifi", "base_url": a.url.rstrip("/"), "site": a.site}
            await conn.execute("UPDATE devices SET poll_config = %s WHERE id = %s", (Jsonb(new_cfg), device_id))
            await conn.execute(
                "INSERT INTO device_credentials (device_id, secret_enc) VALUES (%s, %s) ON CONFLICT (device_id) "
                "DO UPDATE SET secret_enc = EXCLUDED.secret_enc, updated_at = now()",
                (device_id, encrypt_secret({"api_key": key})))
            await conn.execute("INSERT INTO audit_log (username, action, target, details) VALUES ('cli', 'poller_configure', %s, %s)",
                               (a.device, Jsonb({"driver": "unifi", "base_url": new_cfg["base_url"], "site": a.site})))
    print(f"UniFi polling configured for {a.device}; the certificate is pinned on the first successful poll")
    return 0


async def set_flows(a) -> int:
    on = a.state == "on"
    async with await psycopg.AsyncConnection.connect(get_settings().db_conninfo()) as conn:
        async with conn.transaction():
            device_id, cfg = await _device(conn, a.client, a.device)
            if cfg.get("driver") != "unifi":
                raise SystemExit(f"{a.device} is not polled with the UniFi driver")
            await conn.execute("UPDATE devices SET poll_config = (poll_config - 'flow_cursor_ms') || %s WHERE id = %s",
                               (Jsonb({"collect_flows": on}), device_id))
            await conn.execute("INSERT INTO audit_log (username, action, target, details) VALUES ('cli', 'poller_flows', %s, %s)",
                               (a.device, Jsonb({"collect_flows": on})))
    print(f"traffic-flow collection {'enabled' if on else 'disabled'} for {a.device}")
    return 0


async def backfill_flows(a) -> int:
    from datetime import UTC, datetime, timedelta
    since = datetime.now(UTC) - timedelta(hours=a.hours)
    async with await psycopg.AsyncConnection.connect(get_settings().db_conninfo(), autocommit=True) as conn:
        device_id, _ = await _device(conn, a.client, a.device)
        n = await Poller(get_settings()).backfill_flows(conn, device_id, since)
        await conn.execute("INSERT INTO audit_log (username, action, target, details) VALUES ('cli', 'flows_backfill', %s, %s)",
                           (a.device, Jsonb({"hours": a.hours, "stored": n})))
    print(f"backfilled {n} flow records for {a.device}; the parser turns them into events within minutes")
    return 0


async def poll_once(a) -> int:
    async with await psycopg.AsyncConnection.connect(get_settings().db_conninfo()) as conn:
        device_id, cfg = await _device(conn, a.client, a.device)
        cur = await conn.execute("SELECT secret_enc FROM device_credentials WHERE device_id = %s", (device_id,))
        row = await cur.fetchone()
    res = await DRIVERS[cfg["driver"]].poll(cfg, decrypt_secret(row[0]) if row else None)
    print("controller:", res.controller)
    for d in res.devices:
        print(f"  {d.name:<14} {d.model:<10} {d.type:<4} fw {d.firmware:<16} connected={d.connected} cpu={d.cpu_pct} "
              f"mem={d.mem_pct} temp={d.temp_c} uptime={d.uptime_s} clients={d.client_count} upgradable={d.upgradable}")
    print(f"  {len(res.clients)} network clients")
    return 0


async def serve() -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await Poller(get_settings()).run(stop)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per request is noise
    p = argparse.ArgumentParser(prog="app.poller")
    sub = p.add_subparsers(dest="cmd")
    s = sub.add_parser("set-unifi")
    s.add_argument("--client", required=True)
    s.add_argument("--device", required=True)
    s.add_argument("--url", required=True)
    s.add_argument("--site", default="default")
    f = sub.add_parser("set-flows", help="collect traffic-flow records from the controller API")
    f.add_argument("--client", required=True)
    f.add_argument("--device", required=True)
    f.add_argument("state", choices=("on", "off"))
    bf = sub.add_parser("backfill-flows", help="fetch older traffic-flow records still held by the controller")
    bf.add_argument("--client", required=True)
    bf.add_argument("--device", required=True)
    bf.add_argument("--hours", type=int, default=24, help="how far back to ask (the controller keeps about a day)")
    o = sub.add_parser("poll-once")
    o.add_argument("--client", required=True)
    o.add_argument("--device", required=True)
    a = p.parse_args()
    if a.cmd == "set-unifi":
        return asyncio.run(set_unifi(a))
    if a.cmd == "set-flows":
        return asyncio.run(set_flows(a))
    if a.cmd == "backfill-flows":
        return asyncio.run(backfill_flows(a))
    if a.cmd == "poll-once":
        return asyncio.run(poll_once(a))
    asyncio.run(serve())
    return 0


if __name__ == "__main__":
    sys.exit(main())
