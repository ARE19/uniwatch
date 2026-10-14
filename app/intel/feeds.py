"""Threat-intel feeds: download, parse, store; match new events; raise IoC events.

Feed formats (verified against the live feeds 2026-10-06):
  ip_list        one IPv4 address per line, '#' comments      (Feodo Tracker, ET compromised, CINS Army)
  hostfile       '127.0.0.1<TAB>domain', '#' comments           (URLhaus host file)
  spamhaus_json  JSON lines {"cidr": "...", "sblid": ...}, plus a metadata line without "cidr" (Spamhaus DROP v4)

A match creates one extra event (category ids, action ioc-match) next to the original, linked by raw_id and
extra.matched_event_id, so it shows in Log View, Insights and the Event Monitor 'Threat intel match' rule."""

import ipaddress
import json
import logging
import re
from datetime import UTC, datetime, timedelta

import httpx
from psycopg.types.json import Jsonb
from sqlalchemy import text

from app import db

log = logging.getLogger("intel")
UA = "uniwatch/0.1 (+threat-intel feed refresh)"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
CURSOR = "intel:match"


def parse(fmt: str, body: str) -> tuple[list[str], list[str]]:
    """-> (networks as CIDR strings, domains). Invalid lines are skipped, never guessed at."""
    nets: list[str] = []
    domains: list[str] = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if fmt == "ip_list":
            try:
                nets.append(str(ipaddress.ip_network(line.split()[0], strict=False)))
            except ValueError:
                continue
        elif fmt == "hostfile":
            parts = line.split()
            if len(parts) >= 2 and DOMAIN_RE.match(parts[1].lower()):
                domains.append(parts[1].lower())
        elif fmt == "spamhaus_json":
            try:
                cidr = json.loads(line).get("cidr")
                if cidr:
                    nets.append(str(ipaddress.ip_network(cidr, strict=False)))
            except (ValueError, AttributeError):
                continue
    return sorted(set(nets)), sorted(set(domains))


async def refresh(feed_ids: list[int] | None = None, fetch=None, role: str = "app") -> dict:
    """Download and replace indicators for enabled feeds. Returns {feed name: count or error}."""
    out = {}
    async with db.sessionmaker(role)() as s:
        feeds = (await s.execute(text("SELECT id, name, url, format FROM ioc_feeds WHERE enabled"
                                      + (" AND id = ANY(:ids)" if feed_ids else "")), {"ids": feed_ids})).all()
    for f in feeds:
        try:
            if fetch is not None:
                body = await fetch(f.url)
            else:
                async with httpx.AsyncClient(timeout=60, headers={"User-Agent": UA}, follow_redirects=True) as http:
                    r = await http.get(f.url)
                    r.raise_for_status()
                    body = r.text
            nets, domains = parse(f.format, body)
            if not nets and not domains:
                raise ValueError("feed returned no indicators (format changed?)")
            async with db.sessionmaker(role)() as s:
                await s.execute(text("DELETE FROM ioc_networks WHERE feed_id = :f"), {"f": f.id})
                await s.execute(text("DELETE FROM ioc_domains WHERE feed_id = :f"), {"f": f.id})
                if nets:
                    await s.execute(text("INSERT INTO ioc_networks (feed_id, net) SELECT :f, unnest(CAST(:n AS cidr[]))"),
                                    {"f": f.id, "n": nets})
                if domains:
                    await s.execute(text("INSERT INTO ioc_domains (feed_id, domain) SELECT :f, unnest(CAST(:d AS text[]))"),
                                    {"f": f.id, "d": domains})
                await s.execute(text("UPDATE ioc_feeds SET last_fetched = now(), last_count = :n, last_error = NULL WHERE id = :f"),
                                {"n": len(nets) + len(domains), "f": f.id})
                await s.commit()
            out[f.name] = len(nets) + len(domains)
        except Exception as e:  # noqa: BLE001 — keep the previous indicators on failure
            msg = f"{type(e).__name__}: {e}"[:300]
            log.warning("feed %s failed: %s", f.name, msg)
            async with db.sessionmaker(role)() as s:
                await s.execute(text("UPDATE ioc_feeds SET last_error = :e WHERE id = :f"), {"e": msg, "f": f.id})
                await s.commit()
            out[f.name] = msg
    return out


MATCH_SQL = """
    WITH batch AS (
        SELECT * FROM events
        WHERE id > :last AND id <= :hi AND ts > :since AND action IS DISTINCT FROM 'ioc-match'
    )
    SELECT b.id, b.ts, b.client_id, b.device_id, b.raw_id, b.raw_ts, b.vendor, b.category AS orig_category,
           b.action AS orig_action, host(b.src_ip) AS src_ip, b.src_port, host(b.dst_ip) AS dst_ip, b.dst_port,
           b.src_country, b.dst_country, b.src_asn, b.dst_asn, b.src_mac, b.protocol,
           m.side, m.indicator, f.name AS feed
    FROM batch b
    JOIN LATERAL (
        SELECT 'src' AS side, n.net::text AS indicator, n.feed_id FROM ioc_networks n WHERE b.src_ip <<= n.net
        UNION ALL
        SELECT 'dst', n.net::text, n.feed_id FROM ioc_networks n WHERE b.dst_ip <<= n.net
        UNION ALL
        SELECT 'domain', d.domain, d.feed_id FROM ioc_domains d WHERE d.domain = b.extra->>'domain'
    ) m ON true
    JOIN ioc_feeds f ON f.id = m.feed_id
    ORDER BY b.id
"""


async def match_new_events(batch: int = 20000, now: datetime | None = None) -> int:
    """Scan events after the cursor; insert one ioc-match event per (event, side). Returns matches."""
    now = now or datetime.now(UTC)
    async with db.sessionmaker()() as s:
        await s.execute(text("INSERT INTO tracker_cursors (name, last_event_id) VALUES (:n, 0) ON CONFLICT DO NOTHING"), {"n": CURSOR})
        last = (await s.execute(text("SELECT last_event_id FROM tracker_cursors WHERE name = :n FOR UPDATE"), {"n": CURSOR})).scalar()
        # Only events received >30 s ago: ids are allocated before a parser transaction commits, so a younger,
        # not-yet-visible event could otherwise be skipped by the cursor.
        hi = (await s.execute(text("SELECT coalesce(max(id), 0) FROM events WHERE id > :l AND ts > :since AND raw_ts < :settled"),
                              {"l": last, "since": now - timedelta(days=7), "settled": now - timedelta(seconds=30)})).scalar()
        hi = min(hi, last + batch)
        if hi <= last:
            await s.commit()
            return 0
        rows = (await s.execute(text(MATCH_SQL), {"last": last, "hi": hi, "since": now - timedelta(days=7)})).all()
        seen = set()
        n = 0
        for r in rows:
            key = (r.id, r.side)
            if key in seen:
                continue  # several feeds list the same address: one IoC event, feeds listed in extra
            seen.add(key)
            feeds = sorted({x.feed for x in rows if (x.id, x.side) == key})
            what = {"src": r.src_ip, "dst": r.dst_ip, "domain": r.indicator}[r.side]
            await s.execute(text("""
                INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class,
                                    event_name, action, outcome, src_ip, src_port, dst_ip, dst_port, src_country, dst_country,
                                    src_asn, dst_asn, src_mac, protocol, rule, message, extra)
                VALUES (:ts, :c, :d, :rid, :rts, :v, 'ids', 'high', 'intel:ioc', 'Threat intel match', 'ioc-match', NULL,
                        :src, :sp, :dst, :dp, :sc, :dc, :sa, :da, :mac, :proto, :rule, :msg, :extra)"""),
                {"ts": r.ts, "c": r.client_id, "d": r.device_id, "rid": r.raw_id, "rts": r.raw_ts, "v": r.vendor,
                 "src": r.src_ip, "sp": r.src_port, "dst": r.dst_ip, "dp": r.dst_port, "sc": r.src_country, "dc": r.dst_country,
                 "sa": r.src_asn, "da": r.dst_asn, "mac": r.src_mac, "proto": r.protocol, "rule": feeds[0],
                 "msg": f"{'Source' if r.side == 'src' else 'Destination' if r.side == 'dst' else 'Domain'} {what} is on "
                        f"threat list: {', '.join(feeds)} (event {r.orig_category}/{r.orig_action or '-'})",
                 "extra": Jsonb({"matched_event_id": r.id, "side": r.side, "indicator": r.indicator, "value": what,
                                 "feeds": feeds})})
            n += 1
        await s.execute(text("UPDATE tracker_cursors SET last_event_id = :h, updated_at = now() WHERE name = :n"), {"h": hi, "n": CURSOR})
        await s.commit()
    return n
