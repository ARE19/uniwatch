"""Access point offline, Wi-Fi quality and PoE alerts, from controller fields verified on the fleet 2026-10-10."""

import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from app.drivers.unifi import parse_clients, parse_devices
from tests.test_alerts import Outbox, env, only, run  # noqa: F401  (env is a fixture)

NOW = datetime.now(UTC)
AP = {"mac": "60:22:32:16:06:64", "type": "uap", "name": "CTSKL-AP01 - Workstation", "model": "UAL6", "state": 1,
      "disconnected_at": 1789067571, "num_sta": 1,
      "radio_table_stats": [{"radio": "ng", "channel": 1, "cu_total": 73, "satisfaction": -1, "num_sta": 0},
                            {"radio": "na", "channel": 161, "cu_total": 11, "satisfaction": 85, "num_sta": 1}],
      "uplink": {"uplink_device_name": "CTSKL-SW2", "uplink_remote_port": 14, "uplink_port_poe_compatibility": "COMPATIBLE"}}
SW = {"mac": "58:d6:1f:8a:27:c9", "type": "usw", "name": "CTSKL-SW2", "model": "USL24PB", "state": 1,
      "total_used_power": 29.46, "total_max_power": 95,
      "port_table": [{"port_idx": 3, "up": True, "poe_enable": True, "poe_good": True, "poe_power": "4.50"},
                     {"port_idx": 7, "up": True, "poe_enable": True, "poe_good": False, "poe_power": "0.00"}]}


def test_parse_ap_and_poe_fields():
    ap, sw = parse_devices([AP, SW], None)
    assert ap.extra["radios"][0] == {"radio": "ng", "channel": 1, "cu_total": 73, "satisfaction": -1, "num_sta": 0}
    assert ap.extra["uplink"] == {"device": "CTSKL-SW2", "port": 14, "poe": "COMPATIBLE"} and ap.extra["disconnected_at"] == 1789067571
    assert sw.extra["poe_budget"] == {"used_w": 29.46, "max_w": 95.0} and sw.extra["poe_faults"] == [7]
    c = parse_clients([{"mac": "aa:bb:cc:f5:f6:40", "is_wired": False, "rssi": 30, "signal": -82, "ap_mac": AP["mac"]},
                       {"mac": "aa:bb:cc:13:5e:37", "is_wired": True}])
    assert c[0].signal_dbm == -82 and c[0].rssi == 30 and c[1].signal_dbm is None


def inv(c, gw, mac, name, typ, connected, extra):
    c.execute(text("""INSERT INTO device_inventory (poll_device_id, mac, name, model, type, connected, seen_at, extra)
                      VALUES (:d, :m, :n, 'x', :t, :c, now(), CAST(:x AS jsonb))"""),
              {"d": gw, "m": mac, "n": name, "t": typ, "c": connected, "x": json.dumps(extra)})


async def test_ap_offline_new_only_and_resolves(owner_engine, env):  # noqa: F811
    cid, gw = env
    only(owner_engine, "ap_offline", notify_resolve=True)
    with owner_engine.begin() as c:
        inv(c, gw, "60:22:32:16:06:64", "AP01", "uap", False,
            {"disconnected_at": int((NOW - timedelta(minutes=12)).timestamp()), "uplink": {"device": "SW2", "port": 14}})
        inv(c, gw, "60:22:32:f4:db:c2", "Old AP", "uap", False, {"disconnected_at": 1761630461})   # gone since Oct 2025
        inv(c, gw, "60:22:32:66:87:02", "Blip AP", "uap", False, {"disconnected_at": int((NOW - timedelta(minutes=2)).timestamp())})
    out = Outbox()
    await run(out)
    assert out.sent == [("open", "Access point AP01 is offline")]
    with owner_engine.begin() as c:
        c.execute(text("UPDATE device_inventory SET connected = true WHERE name = 'AP01'"))
    await run(out)
    assert out.sent[-1] == ("resolve", "Access point AP01 is offline")


async def test_wifi_quality_needs_the_whole_window(owner_engine, env):  # noqa: F811
    cid, gw = env
    only(owner_engine, "wifi_quality")
    ins = text("""INSERT INTO ap_metrics (ts, client_id, poll_device_id, mac, name, cu_max, cu_radio, exp_min, clients, signals)
                  VALUES (:ts, :c, :d, :m, :n, :cu, 'ng', :exp, 3, CAST(:sig AS smallint[]))""")
    with owner_engine.begin() as c:
        for i in range(10):        # AP1: busy channel and weak clients for 10 minutes; AP2: one bad minute only
            t = NOW - timedelta(minutes=i)
            c.execute(ins, {"ts": t, "c": cid, "d": gw, "m": "60:22:32:16:06:64", "n": "AP1", "cu": 85 + i % 3, "exp": 55,
                            "sig": "{-82,-78,-60}"})
            c.execute(ins, {"ts": t, "c": cid, "d": gw, "m": "60:22:32:f4:db:c2", "n": "AP2", "cu": 95 if i == 0 else 20,
                            "exp": 99, "sig": "{-50}"})
    out = Outbox()
    await run(out)
    assert sorted(out.sent) == [("open", "Clients with weak Wi-Fi signal on AP1"), ("open", "High Wi-Fi channel utilisation on AP1"),
                                ("open", "Poor Wi-Fi experience on AP1")]


async def test_poe_issue(owner_engine, env):  # noqa: F811
    cid, gw = env
    only(owner_engine, "poe_issue")
    with owner_engine.begin() as c:
        inv(c, gw, "60:22:32:16:06:64", "AP-limited", "uap", True, {"uplink": {"device": "SW1", "port": 5, "poe": "LIMITED"}})
        inv(c, gw, "60:22:32:f4:db:c2", "AP-ok", "uap", True, {"uplink": {"device": "SW1", "port": 6, "poe": "COMPATIBLE"}})
        inv(c, gw, "58:d6:1f:8a:27:c9", "USW Flex", "usw", True, {"poe_budget": {"used_w": 19.0, "max_w": 20}, "poe_faults": [4]})
        inv(c, gw, "58:d6:1f:37:a6:64", "Big SW", "usw", True, {"poe_budget": {"used_w": 52.8, "max_w": 195}})
    out = Outbox()
    await run(out)
    assert sorted(out.sent) == [("open", "Access point AP-limited on insufficient PoE"), ("open", "PoE budget nearly used on USW Flex"),
                                ("open", "PoE fault on USW Flex")]
