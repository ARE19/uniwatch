"""UniFi traffic flows from the controller API: parser (real records), poller collection, Websites & apps by volume."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from app.config import get_settings
from app.drivers.base import encrypt_secret
from app.parserd.worker import ParserWorker
from app.parsers.model import ParseError
from app.parsers.vendors import module_for
from app.poller.service import Poller, PollerConfig
from tests.conftest import full_login

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "unifi-api-traffic-flows-2026-10-07.log"
RECORDS = [json.loads(line) for line in SAMPLE.read_text(encoding="utf-8").splitlines() if line.strip()]
unifi = module_for("unifi")


def rec(pred):
    return next(r for r in RECORDS if pred(r))


def parse(r):
    return unifi.parse(json.dumps(r), "Asia/Hong_Kong")


def test_every_sample_record_parses():
    for r in RECORDS:
        ev = parse(r)
        assert ev.event_class == "api:traffic-flow" and ev.ts == datetime.fromtimestamp(r["time"] / 1000, UTC)
        assert ev.extra["flow_id"] == r["id"] and ev.src_ip == r["source"]["ip"]


def test_download_direction_from_windows_update_flow():
    r = rec(lambda r: r["destination"].get("domains") == ["bg.microsoft.map.fastly.net"])
    ev = parse(r)
    assert ev.bytes_in == r["traffic_data"]["bytes_tx"] > 1_000_000          # download to the device
    assert ev.bytes_out == r["traffic_data"]["bytes_rx"] < 200_000
    assert (ev.category, ev.action, ev.outcome, ev.protocol, ev.dst_port) == ("traffic", "flow", "allowed", "tcp", 80)
    assert ev.extra["src_name"] == "DESKTOP-FAND3T9" and ev.extra["network_out"] == "Internet 2"
    assert ev.extra["domain"] == "fastly.net" and ev.extra["direction"] == "outgoing"
    assert ev.message.startswith("DESKTOP-FAND3T9 → bg.microsoft.map.fastly.net:80 HTTP ↓7.")


def test_app_classification_and_gsa_tunnel():
    huntress = parse(rec(lambda r: r["destination"].get("domains") == ["agent.huntress.io"]))
    assert (huntress.rule, huntress.extra["app_category"]) == ("Huntress", "Security")
    gsa = parse(rec(lambda r: "ztna1p-msedge.net" in str(r["destination"].get("domains"))))
    assert gsa.rule == "Microsoft Global Secure Access (tunnel)"


def test_blocked_records():
    ad = parse(rec(lambda r: r["action"] == "blocked" and "traffic_data" not in r))
    assert (ad.category, ad.action, ad.outcome, ad.rule) == ("firewall", "flow-blocked", "blocked", "Ad Blocking")
    assert ad.bytes_in is None and "duration_ms" not in ad.extra and "BLOCKED by Ad Blocking" in ad.message
    fw = parse(rec(lambda r: r["action"] == "blocked" and r["destination"].get("ip") == "76.76.2.2"))
    assert fw.rule == "Firewall" and fw.extra["network_out"] == "LeoUS"


def test_incoming_and_local():
    inc = parse(rec(lambda r: r["direction"] == "incoming"))
    assert inc.src_mac is None and inc.extra["dst_name"] == "NW HK" and inc.dst_ip == "11.162.174.120"
    local = parse(rec(lambda r: r["direction"] == "local" and r["action"] == "allowed"))
    assert local.extra["direction"] == "local"


def test_not_a_flow_record():
    with pytest.raises(ParseError):
        unifi.parse('{"foo": 1}', "UTC")
    with pytest.raises(ParseError):
        unifi.parse("{not json", "UTC")


# ---- poller -> raw_logs -> parser -> views -------------------------------------------------------------
T_MAX = max(r["time"] for r in RECORDS)
NOW = datetime.fromtimestamp(T_MAX / 1000, UTC) + timedelta(minutes=4)


class FakeApi:
    """Answers like the controller: records with since < time <= until (optionally shifted in time)."""
    def __init__(self, shift_ms: int = 0):
        self.calls = []
        self.records = [dict(r, time=r["time"] + shift_ms) for r in RECORDS]

    async def __call__(self, cfg, secret, since_ms, until_ms):
        self.calls.append((since_ms, until_ms))
        assert secret == {"api_key": "k"}
        return [r for r in self.records if since_ms < r["time"] <= until_ms]


@pytest.fixture
def site(owner_engine):
    with owner_engine.begin() as c:
        cid = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Northwind HK','nwhk') RETURNING id")).scalar()
        gw = c.execute(text("""INSERT INTO devices (client_id, name, vendor, syslog_source_ip, poll_config)
                               VALUES (:c, 'NW-HK', 'unifi', '192.168.1.1', CAST(:cfg AS jsonb)) RETURNING id"""),
                       {"c": cid, "cfg": json.dumps({"driver": "unifi", "base_url": "https://192.168.1.1",
                                                     "tls_fingerprint": "ab" * 32, "collect_flows": True})}).scalar()
        c.execute(text("INSERT INTO device_credentials (device_id, secret_enc) VALUES (:d, :s)"),
                  {"d": gw, "s": encrypt_secret({"api_key": "k"})})
    return cid, gw


async def _flows(poller, now):
    conn = await poller.connect()
    try:
        return await poller.poll_flows(conn, now)
    finally:
        await conn.close()


async def test_poller_collects_contiguous_windows_without_duplicates(owner_engine, site):
    cid, gw = site
    api = FakeApi()
    # The first window covers 15 min before NOW - lag; all sample records are within the last 30 min.
    poller = Poller(get_settings(), PollerConfig(flow_first=timedelta(minutes=40), flow_window=timedelta(hours=1)), flow_fetch=api)
    first = await _flows(poller, NOW)
    second = await _flows(poller, NOW + timedelta(minutes=2))
    assert first == {gw: f"{len(RECORDS)} flows"} and second == {gw: "0 flows"}
    assert api.calls[1][0] == api.calls[0][1]                                 # windows are contiguous
    with owner_engine.begin() as c:
        rows = c.execute(text("SELECT transport, host(source_ip), raw FROM raw_logs WHERE device_id = :d"), {"d": gw}).all()
        cursor = c.execute(text("SELECT poll_config->>'flow_cursor_ms' FROM devices WHERE id = :d"), {"d": gw}).scalar()
    assert len(rows) == len(RECORDS) == len({json.loads(r[2])["id"] for r in rows})
    assert {(r[0], r[1]) for r in rows} == {("api", "192.168.1.1")}
    assert int(cursor) == api.calls[1][1]

    assert await ParserWorker(get_settings()).run_once(NOW) == len(RECORDS)
    with owner_engine.begin() as c:
        n, blocked, failed = c.execute(text("""SELECT count(*), count(*) FILTER (WHERE action = 'flow-blocked'),
                                                      (SELECT count(*) FROM raw_logs WHERE parse_error IS NOT NULL)
                                               FROM events WHERE event_class = 'api:traffic-flow'""")).one()
    assert (n, failed) == (len(RECORDS), 0) and blocked >= 3


async def test_flows_disabled_and_api_errors(owner_engine, site):
    cid, gw = site
    with owner_engine.begin() as c:
        c.execute(text("UPDATE devices SET poll_config = poll_config || '{\"collect_flows\": false}' WHERE id = :d"), {"d": gw})
    assert await _flows(Poller(get_settings(), flow_fetch=FakeApi()), NOW) == {}
    with owner_engine.begin() as c:
        c.execute(text("UPDATE devices SET poll_config = poll_config || '{\"collect_flows\": true}' WHERE id = :d"), {"d": gw})

    from app.drivers import PollError

    async def broken(*a):
        raise PollError("API key rejected (HTTP 401)")
    assert await _flows(Poller(get_settings(), flow_fetch=broken), NOW) == {gw: "flows error: API key rejected (HTTP 401)"}
    with owner_engine.begin() as c:   # cursor not advanced: the window is retried next cycle
        assert c.execute(text("SELECT poll_config ? 'flow_cursor_ms' FROM devices WHERE id = :d"), {"d": gw}).scalar() is False


async def test_websites_and_apps_by_volume(client, make_user, owner_engine, site):
    cid, gw = site
    # The views look back from the real clock, so the sample records are shifted to end 4 minutes ago.
    now = datetime.now(UTC)
    api = FakeApi(shift_ms=int((now - timedelta(minutes=4)).timestamp() * 1000) - T_MAX)
    await _flows(Poller(get_settings(), PollerConfig(flow_first=timedelta(minutes=40), flow_window=timedelta(hours=1)),
                        flow_fetch=api), now)
    await ParserWorker(get_settings()).run_once(now)
    await full_login(client, make_user(role="engineer"))
    page = (await client.get("/insights?view=web&range=24h")).text
    assert "From the firewall's own connection records" in page
    assert page.index("Microsoft Global Secure Access (tunnel)") < page.index("Huntress")   # 18 MB beats 27 KB
    assert "fastly.net" in page and "Traffic without a website name, by network owner" in page
    dev = (await client.get("/insights?view=web&range=24h&ip=192.168.1.67")).text
    assert "fastly.net" in dev and "Huntress" not in dev and "12.3 MB" in dev
    d = (await client.get("/api/dashboard?range=24h")).json()
    assert d["apps"][0]["app"] == "Microsoft Global Secure Access (tunnel)" and d["apps"][0]["flow"] is True
    assert d["apps"][0]["bytes"] == sum(r["traffic_data"]["bytes_total"] for r in RECORDS
                                        if "ztna1p-msedge.net" in str(r["destination"].get("domains")))


async def test_backfill_stops_before_collected_flows(owner_engine, site):
    cid, gw = site
    api = FakeApi()
    mid = sorted(r["time"] for r in RECORDS)[len(RECORDS) // 2]
    cfg = PollerConfig(flow_window=timedelta(hours=1))
    poller = Poller(get_settings(), cfg, flow_fetch=api)
    # regular collection already holds the newer half
    conn = await poller.connect()
    try:
        api_new = FakeApi()
        api_new.records = [r for r in api.records if r["time"] > mid]
        newer = Poller(get_settings(), PollerConfig(flow_first=timedelta(minutes=40), flow_window=timedelta(hours=1)), flow_fetch=api_new)
        await newer.poll_flows(conn, NOW)
        await ParserWorker(get_settings()).run_once(NOW)
        n = await poller.backfill_flows(conn, gw, NOW - timedelta(hours=2))
    finally:
        await conn.close()
    assert n == sum(1 for r in RECORDS if r["time"] <= mid)
    with owner_engine.begin() as c:
        ids = c.execute(text("SELECT raw::jsonb->>'id' FROM raw_logs WHERE device_id = :d"), {"d": gw}).scalars().all()
    assert len(ids) == len(set(ids)) == len(RECORDS)                           # nothing twice, nothing missing



async def test_connector_flows_split_full_windows():
    """A query reports at most 10,000 records: a full window is split until each part fits."""
    import httpx as _httpx
    from app.poller.connector import fetch_flows_connector
    calls = []

    def handler(request):
        body = json.loads(request.content)
        a, b = body["timestampFrom"], body["timestampTo"]
        calls.append((a, b))
        n = (b - a) // 1000                              # 1 record per second in this fake console
        recs = [{"id": f"f{t}", "time": t} for t in range(a + 1000, b + 1, 1000)]
        page = recs[body["pageNumber"] * body["pageSize"]:(body["pageNumber"] + 1) * body["pageSize"]]
        return _httpx.Response(200, json={"data": page, "total_element_count": min(n, 10000),
                                          "has_next": (body["pageNumber"] + 1) * body["pageSize"] < len(recs)})
    out = await fetch_flows_connector("k", "host", 0, 30_000_000, transport=_httpx.MockTransport(handler))
    assert len(out) == 30000 and len({r["id"] for r in out}) == 30000      # nothing lost, nothing twice
    assert any(b - a < 30_000_000 for a, b in calls)


async def test_cloud_flows_collected_for_site_manager_console(owner_engine):
    from app.config import get_settings
    from app.poller.service import Poller
    with owner_engine.begin() as c:
        cid = c.execute(text("INSERT INTO clients (name, slug) VALUES ('CTS KL','cts-kl') RETURNING id")).scalar()
        did = c.execute(text("""INSERT INTO devices (client_id, name, vendor, syslog_source_ip, poll_config)
                                VALUES (:c, 'CTS-KL', 'unifi', '11.133.111.195', '{"collect_flows": true}') RETURNING id"""),
                        {"c": cid}).scalar()
        c.execute(text("INSERT INTO sitemanager_hosts (host_id, client_id, device_id, name, state, last_sync) "
                       "VALUES ('kl-host', :c, :d, 'CTS KL', 'connected', now())"), {"c": cid, "d": did})
    seen = []

    async def cloud(key, host, a, b):
        seen.append((host, b - a))
        return [{"id": "x1", "time": b - 1, "action": "allowed", "direction": "outgoing"}]
    p = Poller(get_settings().model_copy(update={"unifi_site_manager_api_key": "k"}), drivers={}, cloud_flow_fetch=cloud)
    conn = await p.connect()
    try:
        res = await p.poll_flows(conn)
    finally:
        await conn.close()
    assert res == {did: "1 flows"} and seen[0][0] == "kl-host" and seen[0][1] == 120000      # 2-minute window
    with owner_engine.connect() as c:
        row = c.execute(text("SELECT transport, host(source_ip) AS ip FROM raw_logs")).one()
        cursor = c.execute(text("SELECT poll_config->>'flow_cursor_ms' FROM devices")).scalar()
    assert (row.transport, row.ip) == ("api", "11.133.111.195") and cursor
