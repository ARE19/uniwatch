"""WAN / internet / IPsec: driver parsing (verified field shapes), poller intervals, alerts, dashboard panel."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import text

from app.alerts.engine import AlertEngine
from app.config import get_settings
from app.drivers.unifi import parse_devices, parse_ipsec, parse_wans
from app.poller.service import Poller
from tests.conftest import full_login
from tests.test_alerts import Outbox
from tests.test_poller import UDM, FakeDriver, _cycle, site  # noqa: F401  (fixture)

# Shapes as returned by UniFi Network 10.6.106 / UniFi OS 5.1.33 on 2026-10-07 (trimmed).
GATEWAY = dict(UDM, last_wan_interfaces={"WAN": {"alive": False, "ip": "11.180.249.28"},
                                         "WAN2": {"alive": True, "ip": "11.162.174.120"}},
               wan1={"name": "eth8", "is_uplink": False, "media": "2.5GE"},
               wan2={"name": "eth7", "is_uplink": True, "media": "GE", "latency": 2, "availability": 100})
NETWORKS = [{"purpose": "wan", "name": "Internet 1", "wan_networkgroup": "WAN"},
            {"purpose": "wan", "name": "Internet 2", "wan_networkgroup": "WAN2"},
            {"purpose": "site-vpn", "vpn_type": "ipsec-vpn", "name": "NW_S2S", "ipsec_peer_ip": "11.2.193.76", "enabled": False},
            {"purpose": "remote-user-vpn", "vpn_type": "openvpn-server", "name": "vtsysyslog", "enabled": True}]


def test_parse_wans_and_ipsec():
    w = {x.name: x for x in parse_wans(GATEWAY, NETWORKS)}
    assert (w["WAN2"].alive, w["WAN2"].label, w["WAN2"].ifname, w["WAN2"].is_uplink, w["WAN2"].latency_ms) == (True, "Internet 2", "eth7", True, 2.0)
    assert (w["WAN"].alive, w["WAN"].label, w["WAN"].ip) == (False, "Internet 1", "11.180.249.28")
    t = parse_ipsec(NETWORKS, {"site_to_site_num_active": 0})
    assert [(x.name, x.peer, x.enabled, x.up) for x in t] == [("NW_S2S", "11.2.193.76", False, None)]
    on = [dict(n, enabled=True) if n.get("purpose") == "site-vpn" else n for n in NETWORKS]
    assert parse_ipsec(on, {"site_to_site_num_active": 0})[0].up is False
    assert parse_ipsec(on, {"site_to_site_num_active": 1})[0].up is True
    two = on + [{"purpose": "site-vpn", "vpn_type": "ipsec-vpn", "name": "B", "enabled": True}]
    assert {x.up for x in parse_ipsec(two, {"site_to_site_num_active": 1})} == {None}   # cannot tell which one


def result(wan2_alive=True, internet=True, ipsec_up=True):
    from app.drivers.base import PollResult
    g = dict(GATEWAY, last_wan_interfaces={"WAN": {"alive": False, "ip": "11.180.249.28"},
                                           "WAN2": {"alive": wan2_alive, "ip": "11.162.174.120"}})
    nets = [dict(n, enabled=True) if n.get("purpose") == "site-vpn" else n for n in NETWORKS]
    return PollResult(devices=parse_devices([g], "11.162.174.120"), clients=[], wans=parse_wans(g, nets),
                      internet_up=internet, internet_latency_ms=2.0,
                      ipsec=parse_ipsec(nets, {"site_to_site_num_active": 1 if ipsec_up else 0}))


async def test_wan_and_ipsec_outage_alert_once_and_recover(owner_engine, site):
    cid, gw, ap = site
    fake = FakeDriver(result())
    poller = Poller(get_settings(), drivers={"fake": fake})
    t = datetime.now(UTC) - timedelta(minutes=20)
    await _cycle(poller, t)
    fake.result = result(wan2_alive=False, internet=False, ipsec_up=False)
    await _cycle(poller, t + timedelta(minutes=1))
    with owner_engine.connect() as c:
        rows = {(r.wan_name, r.state) for r in c.execute(text("SELECT wan_name, state FROM wan_state WHERE ended_at IS NULL"))}
        ipsec = c.execute(text("SELECT state, peer FROM vpn_tunnel_state WHERE tunnel_name = 'ipsec:NW_S2S' AND ended_at IS NULL")).one()
    assert rows == {("WAN", "down"), ("WAN2", "down"), ("internet", "down")} and tuple(ipsec) == ("down", "11.2.193.76")
    with owner_engine.begin() as c:
        ch = c.execute(text("INSERT INTO notification_channels (name, type, config_enc) VALUES ('noc', 'email', 'x') RETURNING id")).scalar()
        c.execute(text("UPDATE alert_rules SET enabled = rule_type IN ('wan_down', 'internet_down', 'vpn_tunnel_down'), "
                       "notify_resolve = true, channel_ids = ARRAY[:ch]"), {"ch": ch})
    out = Outbox()
    eng = AlertEngine(deliver_fn=out)
    await eng.evaluate(t + timedelta(minutes=10))
    await eng.evaluate(t + timedelta(minutes=11))                       # still down: no repeats
    assert sorted(x[1] for x in out.sent) == ["Internet 2 (WAN2) is down on NW-HK", "Internet is down at NW-HK",
                                             "VPN tunnel ipsec:NW_S2S on NW-HK is down"]   # unused WAN1 never alerts
    fake.result = result()
    await _cycle(poller, t + timedelta(minutes=12))
    await eng.evaluate(t + timedelta(minutes=13))
    assert sorted(k for k, _ in out.sent) == ["open"] * 3 + ["resolve"] * 3


async def test_dashboard_wan_panel(client, make_user, owner_engine, site):
    cid, gw, ap = site
    await _cycle(Poller(get_settings(), drivers={"fake": FakeDriver(result())}))
    await full_login(client, make_user(role="engineer"))
    d = (await client.get("/api/dashboard?range=1h")).json()
    w = {x["wan_name"]: x for x in d["wan"]}
    assert w["WAN2"]["status"] == "up" and w["WAN2"]["is_uplink"] and w["WAN2"]["label"] == "Internet 2" and w["WAN2"]["latency_ms"] == 2.0
    assert w["WAN"]["status"] == "unused" and "internet" not in w            # WAN ports only, no summary row
    page = (await client.get("/")).text
    assert "WAN &amp; internet" in page and "Site-to-site VPN" in page
    assert "/logs?range=24h&amp;severity=high" in page                         # severity tiles open the matching events
    assert ">Devices silent<" not in page and ">Parse failures<" not in page and ">Unknown senders<" not in page
    tun = {t["label"]: t for t in d["vpn"]}
    assert all(t["ipsec"] for t in tun.values())


def test_ipsec_live_status_from_connection_list():
    """Real CTS KL data: each tunnel's own state, WAN port and since-when come from the v2 connection list."""
    import json as _json
    from pathlib import Path as _P
    smp = _json.loads((_P(__file__).resolve().parent.parent / "samples" / "unifi-site-vpn-2026-10-09.json").read_text())
    t = {x.name: x for x in parse_ipsec(smp["networkconf"], {}, smp["connections"])}
    assert t["CTSKL-PartnerNet"].up is True and t["CTSKL-PartnerNet"].interface == "WAN2" and t["CTSKL-PartnerNet"].peer == "11.229.44.205"
    assert t["CTSKL-PartnerNet"].established_at.timestamp() == 1789771774
    assert t["S2S CTSKL/CTSHK"].up is False and t["S2S CTSKL/CTSHK"].interface == "WAN" and t["S2S CTSKL/CTSHK"].established_at is None


async def test_dashboard_site_to_site_table(client, make_user, owner_engine, site):
    cid, gw, ap = site
    with owner_engine.begin() as c:
        c.execute(text("""INSERT INTO vpn_tunnel_info (device_id, tunnel_name, client_id, vpn_type, interface, local_ip, peer, status,
                          established_at, updated_at) VALUES
                          (:d, 'ipsec:CTSKL-PartnerNet', :c, 'IPsec', 'WAN2', '11.133.111.195', '11.229.44.205', 'established', now() - interval '20 days 6 hours', now()),
                          (:d, 'ipsec:S2S CTSKL/CTSHK', :c, 'IPsec', 'WAN', '11.185.5.147', '11.145.11.27', 'not established', NULL, now())"""),
                  {"d": gw, "c": cid})
    await full_login(client, make_user(role="engineer"))
    d = (await client.get("/api/dashboard?range=24h")).json()
    rows = {t["name"]: t for t in d["s2s"]}
    assert rows["CTSKL-PartnerNet"]["local_ip"] == "11.133.111.195" and rows["CTSKL-PartnerNet"]["interface"] == "WAN2"
    assert 20 * 86400 < rows["CTSKL-PartnerNet"]["uptime_s"] < 21 * 86400
    assert rows["S2S CTSKL/CTSHK"]["status"] == "not established" and rows["S2S CTSKL/CTSHK"]["uptime_s"] is None
    assert list(rows)[0] == "S2S CTSKL/CTSHK"                                      # problems first
    assert "Site-to-site VPN" in (await client.get("/")).text
