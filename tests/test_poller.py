"""Phase 6: UniFi driver parsing, poller storage, device state (poll + syslog silence + maintenance)."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from app.config import get_settings
from app.drivers.base import DeviceSnapshot, NetClient, PollError, PollResult, decrypt_secret, encrypt_secret
from app.drivers.unifi import parse_clients, parse_devices
from app.poller.service import Poller, PollerConfig

# Shapes below use only field names verified against UniFi Network 10.6.106 (see app/drivers/unifi.py).
UDM = {"mac": "d0:21:f9:27:3b:58", "name": "NW HK", "model": "UDMPROSE", "type": "udm", "ip": "11.162.174.120",
       "version": "5.1.33.34087", "upgradable": False, "state": 1, "system-stats": {"cpu": "42.1", "mem": "67.2"},
       "temperatures": [{"name": "CPU", "value": 61.5}, {"name": "Local", "value": 48.0}], "uptime": 2223579, "num_sta": 47}
AP = {"mac": "d0:21:f9:14:38:b5", "name": "NWHKWAP-01", "model": "UAL6", "type": "uap", "ip": "192.168.1.102",
      "version": "6.7.57.15670", "upgradable": True, "upgrade_to_firmware": "6.7.60.15700", "state": 1,
      "system-stats": {"cpu": "11.1", "mem": "33.0"}, "uptime": 2818203, "num_sta": 11}
SW = {"mac": "aa:bb:cc:3f:3d:21", "name": "NW-HK-SW1", "model": "USL48P", "type": "usw", "ip": "192.168.1.52",
      "version": "7.5.15.17146", "upgradable": False, "state": 0, "system-stats": {}, "uptime": None, "num_sta": 21}
STA = {"mac": "80:5e:c0:f1:35:d5", "ip": "192.168.1.60", "hostname": "SIP-T55A", "essid": None, "ap_mac": None,
       "is_wired": True, "oui": "Yealink", "network": "Default", "last_seen": 1791280000}
WIFI = {"mac": "2e:c8:19:6a:82:cc", "ip": "192.168.1.192", "name": "Watch", "essid": "Example MSP Wifi",
        "ap_mac": "d0:21:f9:14:38:b5", "is_wired": False, "rssi": -78, "last_seen": 1791280000}


def test_parse_devices_and_clients():
    devs = parse_devices([UDM, AP, SW, {"name": "no mac"}], wan_ip="11.162.174.120")
    udm, ap, sw = devs
    assert (udm.is_gateway, udm.cpu_pct, udm.mem_pct, udm.temp_c, udm.wan_ip) == (True, 42.1, 67.2, 61.5, "11.162.174.120")
    assert (ap.upgradable, ap.firmware_latest, ap.temp_c, ap.wan_ip, ap.client_count) == (True, "6.7.60.15700", None, None, 11)
    assert sw.connected is False and sw.cpu_pct is None
    cl = parse_clients([STA, WIFI])
    assert cl[0].hostname == "SIP-T55A" and cl[0].is_wired and cl[1].hostname == "Watch" and cl[1].rssi == -78
    assert cl[1].ap_mac == "d0:21:f9:14:38:b5" and cl[0].last_seen.tzinfo is not None


def test_credentials_encrypted():
    tok = encrypt_secret({"api_key": "abc123"})
    assert "abc123" not in tok and decrypt_secret(tok) == {"api_key": "abc123"} and decrypt_secret("junk") is None


class FakeDriver:
    def __init__(self, result=None, error=None):
        self.result, self.error, self.calls = result, error, []

    async def poll(self, config, secret):
        self.calls.append((config, secret))
        if self.error:
            raise self.error
        return self.result


@pytest.fixture
def site(owner_engine):
    with owner_engine.begin() as c:
        cid = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Northwind HK','nwhk') RETURNING id")).scalar()
        gw = c.execute(text("INSERT INTO devices (client_id, name, vendor, syslog_source_ip, mgmt_ip, poll_config, last_log_at) "
                            "VALUES (:c, 'NW-HK', 'unifi', '192.168.1.1', '192.168.1.1', "
                            "'{\"driver\": \"fake\", \"base_url\": \"https://192.168.1.1\"}', now()) RETURNING id"), {"c": cid}).scalar()
        ap = c.execute(text("INSERT INTO devices (client_id, name, vendor, syslog_source_ip, last_log_at) "
                            "VALUES (:c, 'NWHKWAP-01', 'unifi', '192.168.1.102', now()) RETURNING id"), {"c": cid}).scalar()
        c.execute(text("INSERT INTO device_credentials (device_id, secret_enc) VALUES (:d, :s)"),
                  {"d": gw, "s": encrypt_secret({"api_key": "k"})})
    return cid, gw, ap


def result():
    return PollResult(devices=parse_devices([UDM, AP, SW], "11.162.174.120"), clients=parse_clients([STA, WIFI]),
                      controller={"version": "10.6.106"}, tls_fingerprint="ab" * 32)


async def _cycle(poller, now=None):
    conn = await poller.connect()
    try:
        r = await poller.poll_all(conn, now)
        await poller.evaluate_states(conn, now)
        return r
    finally:
        await conn.close()


async def test_poll_stores_metrics_inventory_clients_and_pins_tls(owner_engine, site):
    cid, gw, ap = site
    fake = FakeDriver(result())
    assert await _cycle(Poller(get_settings(), drivers={"fake": fake})) == {gw: "ok"}
    assert fake.calls[0][1] == {"api_key": "k"}  # secret decrypted for the driver only
    with owner_engine.connect() as c:
        m = {r.device_id: r for r in c.execute(text("SELECT device_id, cpu_pct, temp_c, client_count, host(wan_ip) wan FROM device_metrics"))}
        inv = {r.name: r for r in c.execute(text("SELECT name, device_id, connected FROM device_inventory"))}
        dev = {r.id: r for r in c.execute(text("SELECT id, mac::text, firmware, upgradable, firmware_latest, poll_status, poll_config FROM devices"))}
        nc = {r.hostname: r for r in c.execute(text("SELECT hostname, ssid, ap, host(ip_internal) ip FROM network_clients"))}
    assert m[gw].cpu_pct == pytest.approx(42.1) and m[gw].temp_c == pytest.approx(61.5) and m[gw].wan == "11.162.174.120"
    assert m[ap].client_count == 11 and m[ap].wan is None
    assert inv["NW HK"].device_id == gw and inv["NWHKWAP-01"].device_id == ap
    assert inv["NW-HK-SW1"].device_id is None  # discovered but not registered
    assert dev[gw].mac == "d0:21:f9:27:3b:58" and dev[ap].upgradable is True and dev[ap].firmware_latest == "6.7.60.15700"
    assert dev[gw].poll_status == "ok" and dev[gw].poll_config["tls_fingerprint"] == "ab" * 32
    assert nc["Watch"].ap == "NWHKWAP-01" and nc["Watch"].ssid == "Example MSP Wifi" and nc["SIP-T55A"].ip == "192.168.1.60"


async def test_poll_error_is_recorded_not_raised(owner_engine, site):
    cid, gw, ap = site
    r = await _cycle(Poller(get_settings(), drivers={"fake": FakeDriver(error=PollError("API key rejected (HTTP 401)"))}))
    assert r[gw].startswith("error: API key rejected")
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT poll_status FROM devices WHERE id = :d"), {"d": gw}).scalar().startswith("error")


def states(owner_engine, device_id):
    with owner_engine.connect() as c:
        return [(r.state, r.reason) for r in c.execute(text(
            "SELECT state, reason FROM device_state WHERE device_id = :d ORDER BY started_at, id"), {"d": device_id})]


async def test_simulated_outage_creates_down_interval(owner_engine, site):
    """Acceptance: a controller-reported disconnect produces a down interval, then up again."""
    cid, gw, ap = site
    fake = FakeDriver(result())
    poller = Poller(get_settings(), drivers={"fake": fake})
    t = datetime.now(UTC)
    await _cycle(poller, t)
    down = result()
    next(d for d in down.devices if d.name == "NWHKWAP-01").connected = False
    fake.result = down
    await _cycle(poller, t + timedelta(minutes=1))
    fake.result = result()
    await _cycle(poller, t + timedelta(minutes=4))
    assert states(owner_engine, ap) == [("up", "controller: connected"), ("down", "controller: disconnected"),
                                        ("up", "controller: connected")]
    with owner_engine.connect() as c:
        dur = c.execute(text("SELECT ended_at - started_at FROM device_state WHERE device_id = :d AND state = 'down'"),
                        {"d": ap}).scalar()
    assert dur == timedelta(minutes=3)


async def test_syslog_silence_marks_unpolled_device_down(owner_engine, site):
    cid, gw, ap = site
    with owner_engine.begin() as c:
        c.execute(text("UPDATE devices SET poll_config = '{}' WHERE id = :d"), {"d": gw})  # no poller at all
        c.execute(text("UPDATE devices SET last_log_at = now() - interval '40 minutes' WHERE id = :d"), {"d": ap})
    await _cycle(Poller(get_settings(), PollerConfig(silent_after=timedelta(minutes=15)), drivers={}))
    assert states(owner_engine, ap) == [("down", "no syslog for 40 min")]
    assert states(owner_engine, gw) == [("up", "syslog active")]


async def test_maintenance_window_suppresses_down(owner_engine, site):
    cid, gw, ap = site
    with owner_engine.begin() as c:
        c.execute(text("UPDATE devices SET poll_config = '{}', last_log_at = now() - interval '2 hours'"))
        c.execute(text("INSERT INTO maintenance_windows (client_id, device_id, starts_at, ends_at, reason) "
                       "VALUES (:c, :d, now() - interval '1 hour', now() + interval '1 hour', 'firmware upgrade')"),
                  {"c": cid, "d": ap})
    await _cycle(Poller(get_settings(), drivers={}))
    assert states(owner_engine, ap) == [("maintenance", "maintenance window")]
    assert states(owner_engine, gw)[0][0] == "down"


async def test_stale_controller_evidence_falls_back_to_syslog(owner_engine, site):
    cid, gw, ap = site
    poller = Poller(get_settings(), drivers={"fake": FakeDriver(result())})
    t = datetime.now(UTC)
    await _cycle(poller, t - timedelta(minutes=30))           # last good poll long ago: "connected"
    with owner_engine.begin() as c:                           # ...and the AP has been silent since
        c.execute(text("UPDATE devices SET last_log_at = now() - interval '40 minutes' WHERE id = :d"), {"d": ap})
    poller.drivers = {"fake": FakeDriver(error=PollError("timeout"))}
    await _cycle(poller, t)                                   # controller unreachable now -> syslog decides
    st = states(owner_engine, ap)
    assert st[0] == ("up", "controller: connected")
    assert st[1][0] == "down" and st[1][1] in ("no syslog for 39 min", "no syslog for 40 min")
