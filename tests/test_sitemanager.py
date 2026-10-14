"""UniFi Site Manager sync on real (trimmed) API responses: linking/creating clients, WAN state, inventory, ISP health,
the Fleet page and the "internet degraded" alert."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from app.alerts.engine import AlertEngine
from app.config import get_settings
from app.poller.service import Poller
from tests.conftest import full_login
from tests.test_alerts import Outbox, only

SAMPLE = json.loads((Path(__file__).resolve().parent.parent / "samples" / "sitemanager-2026-10-08.json").read_text(encoding="utf-8"))


async def fake_fetch(api_key, with_hourly):
    assert api_key == "test-key"
    return {k: SAMPLE[k] for k in ("hosts", "sites", "devices", "isp_5m")} | {"isp_1h": SAMPLE["isp_1h"] if with_hourly else []}


@pytest.fixture
def known(owner_engine):
    with owner_engine.begin() as c:
        hk = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Northwind HK','nwhk') RETURNING id")).scalar()
        sg = c.execute(text("INSERT INTO clients (name, slug, timezone) VALUES ('CTS SG','cts-sg','Asia/Singapore') RETURNING id")).scalar()
        vs = c.execute(text("""INSERT INTO devices (client_id, name, vendor, syslog_source_ip, poll_config)
                               VALUES (:c, 'NW-HK', 'unifi', '192.168.1.1', '{"driver": "unifi"}') RETURNING id"""), {"c": hk}).scalar()
        cts = c.execute(text("""INSERT INTO devices (client_id, name, vendor, syslog_source_ip, alt_source_ips)
                                VALUES (:c, 'CTS-SG', 'unifi', '11.31.33.170', '{11.145.54.44}') RETURNING id"""), {"c": sg}).scalar()
    return {"hk": hk, "sg": sg, "vs": vs, "cts": cts}


async def sync():
    p = Poller(get_settings().model_copy(update={"unifi_site_manager_api_key": "test-key"}), drivers={})
    conn = await p.connect()
    try:
        return await p.site_manager(conn, force=True, fetch=fake_fetch)
    finally:
        await conn.close()


def q(engine, sql, **kw):
    with engine.begin() as c:
        return c.execute(text(sql), kw).all()


async def test_sync_links_creates_and_records(owner_engine, known):
    stats = await sync()
    assert stats["consoles"] == 6 and stats["clients_created"] == 4               # BNB-HK, CTS KL, CTS UK, MGN HK
    hosts = {r.name: (r.client_id, r.device_id) for r in q(owner_engine, "SELECT name, client_id, device_id FROM sitemanager_hosts")}
    assert hosts["NW HK"] == (known["hk"], known["vs"]) and hosts["CTS SG"] == (known["sg"], known["cts"])   # matched, not duplicated
    new = {r.name: r for r in q(owner_engine, "SELECT c.name, c.slug, c.timezone FROM clients c")}
    assert new["CTS UK"].slug == "cts-uk" and new["MGN HK"].slug == "mgn-hk" and len(new) == 6
    # Connected consoles that are not polled locally are switched to the 1-minute cloud poll (which then supplies WAN
    # state and inventory); NW-HK keeps its local driver; a disconnected console (BNB-HK) is left alone.
    drv = {r.id: (r.driver, r.host) for r in q(owner_engine, "SELECT id, poll_config->>'driver' AS driver, poll_config->>'host_id' AS host FROM devices")}
    assert drv[known["cts"]][0] == "unifi_cloud" and drv[known["cts"]][1]
    assert drv[known["vs"]][0] == "unifi" and drv[hosts["BNB-HK"][1]][0] is None
    wans = {(r.device_id, r.wan_name): r.state for r in q(owner_engine, "SELECT device_id, wan_name, state FROM wan_state WHERE ended_at IS NULL")}
    assert not any(d in (known["vs"], known["cts"], hosts["BNB-HK"][1]) for d, _ in wans)
    # inventory: BNB-HK's console reported offline
    acm = q(owner_engine, "SELECT connected FROM device_inventory WHERE poll_device_id = :d AND device_id = :d", d=hosts["BNB-HK"][1])
    assert acm and acm[0].connected is False
    # ISP health: none for NW-HK (its primary-WAN metrics are meaningless), 5-minute + older hourly rows for the others
    m = {(r.device_id, r.period_s): r.n for r in q(owner_engine, "SELECT device_id, period_s, count(*) AS n FROM isp_metrics GROUP BY 1, 2")}
    assert (known["vs"], 300) not in m and m[(known["cts"], 300)] == 6 and m[(known["cts"], 3600)] == 3
    line = q(owner_engine, "SELECT line_down_kbps, isp_name FROM isp_metrics WHERE device_id = :d AND period_s = 300 LIMIT 1", d=known["cts"])
    assert line[0].line_down_kbps == 942000 and line[0].isp_name.startswith("Singtel")
    # new consoles: WAN IPs as additional source addresses (syslog would be recognised), no primary -> no "silent" alerts
    uk = q(owner_engine, "SELECT syslog_source_ip, array(SELECT host(x) FROM unnest(alt_source_ips) x) AS alts FROM devices WHERE name = 'CTS UK'")
    assert uk[0].syslog_source_ip is None and uk[0].alts == ["11.191.15.210"]

    again = await sync()                                                          # idempotent
    assert again["clients_created"] == 0 and again["metrics"] == 0
    assert q(owner_engine, "SELECT count(*) AS n FROM clients")[0].n == 6


async def test_fleet_page(client, make_user, known):
    await sync()
    await full_login(client, make_user(role="engineer"))
    page = (await client.get("/fleet")).text
    assert page.index("BNB-HK") < page.index("CTS SG")                            # problems (console offline) first
    assert "console offline" in page and "Singtel" in page and "942" not in page.split("Fleet summary")[1].split("</section>")[0]
    assert "not in use" in page or "cloud only" in page


async def test_isp_degraded_alert(owner_engine, known):
    await sync()
    only(owner_engine, "isp_degraded")
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    with owner_engine.begin() as c:
        for i in range(3):
            c.execute(text("""INSERT INTO isp_metrics (ts, client_id, device_id, period_s, avg_latency, packet_loss, uptime)
                              VALUES (:t, :c, :d, 300, 20, 12, 100)"""),
                      {"t": now - timedelta(minutes=5 * i), "c": known["sg"], "d": known["cts"]})
    await AlertEngine(deliver_fn=Outbox()).evaluate()
    titles = [r.title for r in q(owner_engine, "SELECT title FROM alerts WHERE status = 'open'")]
    assert titles == ["Internet degraded at CTS-SG"]
    with owner_engine.begin() as c:                      # the condition clears -> the alert resolves itself
        c.execute(text("UPDATE isp_metrics SET packet_loss = 0 WHERE device_id = :d"), {"d": known["cts"]})
    await AlertEngine(deliver_fn=Outbox()).evaluate()
    assert q(owner_engine, "SELECT status FROM alerts")[0].status == "resolved"


async def test_client_names_from_site_manager(owner_engine, known):
    """The console's client list (via the connector) names devices: alias / hostname stored by MAC."""
    import httpx as _httpx
    from app.poller.clients import fetch_clients_connector
    await sync()
    with owner_engine.begin() as c:                    # consoles opted out of the 1-minute poll: the name job covers them
        c.execute(text("""UPDATE devices SET poll_config = '{"cloud_poll": false}' WHERE poll_config->>'driver' = 'unifi_cloud'"""))
    pages = []

    def handler(request):
        path = request.url.path
        if path.endswith("/integration/v1/sites"):
            return _httpx.Response(200, json={"data": [{"id": "s1", "internalReference": "default", "name": "Default"}]})
        off = int(request.url.params["offset"])
        pages.append(off)
        rows = [{"id": "c1", "name": "Eves-iPhone", "macAddress": "C2:0B:3A:FD:B8:D2", "ipAddress": "192.168.2.197", "type": "WIRELESS"},
                {"id": "c2", "name": "CTSLPT-0126-14", "macAddress": "bc:f1:05:df:98:67", "ipAddress": "192.168.2.91", "type": "WIRED"}]
        return _httpx.Response(200, json={"offset": off, "limit": 200, "count": len(rows[off:]), "totalCount": 2, "data": rows[off:]})

    async def fetch(key, host):
        return await fetch_clients_connector(key, host, transport=_httpx.MockTransport(handler))
    p = Poller(get_settings().model_copy(update={"unifi_site_manager_api_key": "test-key"}), drivers={})
    conn = await p.connect()
    try:
        out = await p.client_names(conn, force=True, fetch=fetch)
    finally:
        await conn.close()
    assert out and all(v == 2 for v in out.values()) and known["vs"] not in out          # NW-HK is polled locally
    rows = {r.mac: (r.hostname, r.is_wired) for r in q(owner_engine, "SELECT mac::text AS mac, hostname, is_wired FROM network_clients")}
    assert rows["c2:0b:3a:fd:b8:d2"] == ("Eves-iPhone", False) and rows["bc:f1:05:df:98:67"] == ("CTSLPT-0126-14", True)



async def test_cloud_driver_polls_through_the_connector(monkeypatch):
    """Same calls and parsing as the local driver, sent to the Site Manager connector with the Site Manager key."""
    import httpx as _httpx
    import app.config as cfgmod
    from app.drivers.unifi import UnifiCloudDriver
    from tests.test_poller import AP, STA, SW, UDM, WIFI
    real = cfgmod.get_settings
    monkeypatch.setattr(cfgmod, "get_settings", lambda: real().model_copy(update={"unifi_site_manager_api_key": "sm-key"}))
    seen = []

    def handler(request):
        seen.append((request.url.path, request.headers.get("x-api-key")))
        body = {"stat/device": [UDM, AP, SW], "stat/sta": [STA, WIFI], "stat/sysinfo": [{"version": "10.6.106"}],
                "stat/health": [{"subsystem": "www", "status": "ok", "latency": 7}], "rest/networkconf": []}
        return _httpx.Response(200, json={"data": next(v for k, v in body.items() if request.url.path.endswith(k))})
    res = await UnifiCloudDriver(transport=_httpx.MockTransport(handler)).poll({"driver": "unifi_cloud", "host_id": "HOST1"}, None)
    assert all(p.startswith("/v1/connector/consoles/HOST1/proxy/network/api/s/default/") and k == "sm-key" for p, k in seen)
    assert res.internet_up is True and res.controller["version"] == "10.6.106"
    gw = next(d for d in res.devices if d.is_gateway)
    assert gw.cpu_pct is not None and gw.mem_pct is not None and gw.uptime_s
    assert {c.hostname for c in res.clients} >= {"Watch"}                  # the UniFi alias ("name") comes first


async def test_cloud_rate_limit_pauses_cloud_polls(owner_engine, known):
    from app.drivers.base import PollError

    class Limited:
        name = "unifi_cloud"
        calls = 0

        async def poll(self, config, secret):
            Limited.calls += 1
            raise PollError("rate limited (HTTP 429)")
    with owner_engine.begin() as c:
        c.execute(text("""UPDATE devices SET poll_config = '{"driver": "unifi_cloud", "host_id": "h"}' WHERE id = :d"""), {"d": known["cts"]})
        c.execute(text("UPDATE devices SET poll_config = '{}' WHERE id = :d"), {"d": known["vs"]})
    p = Poller(get_settings(), drivers={"unifi_cloud": Limited()})
    conn = await p.connect()
    try:
        first = await p.poll_all(conn)
        second = await p.poll_all(conn)                       # paused for 5 minutes: not called again
    finally:
        await conn.close()
    assert "429" in first[known["cts"]] and known["cts"] not in second and Limited.calls == 1

