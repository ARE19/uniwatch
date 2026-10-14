"""Phase 9 acceptance: simulated events trigger exactly one notification each (dedup + throttle), conditions
auto-resolve, and the Event Monitor UI is staff-only with encrypted channel targets."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from app.alerts.engine import AlertEngine
from tests.conftest import csrf_from, full_login

NOW = datetime.now(UTC)


class Outbox:
    def __init__(self):
        self.sent = []

    async def __call__(self, channel, alert, kind, settings):
        self.sent.append((kind, alert["title"]))
        return "sent"


@pytest.fixture
def env(owner_engine):
    with owner_engine.begin() as c:
        cid = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Northwind HK','nwhk') RETURNING id")).scalar()
        gw = c.execute(text("INSERT INTO devices (client_id, name, vendor, last_log_at) VALUES (:c,'NW-HK','unifi', now()) RETURNING id"),
                       {"c": cid}).scalar()
        ch = c.execute(text("INSERT INTO notification_channels (name, type, config_enc) VALUES ('noc', 'webhook', 'x') RETURNING id")).scalar()
        c.execute(text("UPDATE alert_rules SET channel_ids = ARRAY[:ch]"), {"ch": ch})
    return cid, gw


def only(owner_engine, rule_type, **params):
    with owner_engine.begin() as c:
        c.execute(text("UPDATE alert_rules SET enabled = (rule_type = :t)"), {"t": rule_type})
        for k, v in params.items():
            c.execute(text(f"UPDATE alert_rules SET {k} = :v WHERE rule_type = :t"), {"v": v, "t": rule_type})


async def run(outbox, now=None):
    return await AlertEngine(deliver_fn=outbox).evaluate(now or datetime.now(UTC))


async def test_device_offline_notifies_once_resolves_and_throttles(owner_engine, env):
    cid, gw = env
    only(owner_engine, "device_offline")
    out = Outbox()
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO device_state (client_id, device_id, state, started_at) VALUES (:c, :d, 'down', now() - interval '10 minutes')"),
                  {"c": cid, "d": gw})
    await run(out)
    await run(out)  # still down: deduplicated
    await run(out)
    assert out.sent == [("open", "NW-HK is offline")]
    with owner_engine.begin() as c:
        c.execute(text("UPDATE device_state SET ended_at = now() WHERE ended_at IS NULL"))
        c.execute(text("INSERT INTO device_state (client_id, device_id, state, started_at) VALUES (:c, :d, 'up', now())"), {"c": cid, "d": gw})
    stats = await run(out)
    assert stats["resolved"] == 1 and len(out.sent) == 1          # resolve notices are off by default
    with owner_engine.begin() as c:                               # goes down again within the throttle window
        c.execute(text("UPDATE device_state SET ended_at = now() WHERE ended_at IS NULL"))
        c.execute(text("INSERT INTO device_state (client_id, device_id, state, started_at) VALUES (:c, :d, 'down', now() - interval '6 minutes')"),
                  {"c": cid, "d": gw})
    stats = await run(out)
    assert stats["opened"] == 1 and len(out.sent) == 1             # new alert, but throttled: no second notification
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM alerts")).scalar() == 2


async def test_config_change_each_event_once(owner_engine, env):
    cid, gw = env
    only(owner_engine, "config_change")
    out = Outbox()
    with owner_engine.begin() as c:  # history before the first evaluation is not alerted on
        c.execute(text("INSERT INTO config_changes (ts, client_id, device_id, raw_id, raw_ts, admin_user, action, summary) "
                       "VALUES (now(), :c, :d, 0, now(), 'old', 'modify', 'old change')"), {"c": cid, "d": gw})
    await run(out)
    assert out.sent == []
    with owner_engine.begin() as c:
        for i in range(2):
            c.execute(text("INSERT INTO config_changes (ts, client_id, device_id, raw_id, raw_ts, admin_user, source_ip, action, summary) "
                           "VALUES (now(), :c, :d, 0, now(), 'Unifi Owner', '11.26.85.18', 'modify', :s)"),
                      {"c": cid, "d": gw, "s": f"System / rsyslogd: port: 51{i}"})
    await run(out)
    await run(out)
    assert out.sent == [("open", "Configuration changed on NW-HK")] * 2


async def test_failed_logins_burst_once(owner_engine, env):
    """Real login failures -> 'Repeated failed logins' (high) once; VPN handshake failures from a scanner -> only the
    'VPN port scan' rule (medium)."""
    cid, gw = env
    only(owner_engine, "failed_logins")
    out = Outbox()
    ins = text("INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class, action, outcome, src_ip, src_country) "
               "VALUES (now() - make_interval(secs => :i), :c, :d, 0, now(), 'unifi', :cat, 'high', 'x', :a, 'failure', :ip, :cc)")
    with owner_engine.begin() as c:
        for i in range(12):
            c.execute(ins, {"i": i * 10, "c": cid, "d": gw, "cat": "auth", "a": "login-failed", "ip": "85.217.149.17", "cc": "BG"})
            c.execute(ins, {"i": i * 10, "c": cid, "d": gw, "cat": "vpn", "a": "vpn-tls-error", "ip": "45.79.5.11", "cc": "US"})
    await run(out)
    await run(out)
    assert sorted(out.sent) == [("open", "Repeated failed logins from 85.217.149.17 (BG)"),
                                ("open", "VPN port scan (handshake failures) from 45.79.5.11 (US)")]
    with owner_engine.connect() as c:
        sev = dict(c.execute(text("SELECT title, severity FROM alerts")).all())
    assert sev["Repeated failed logins from 85.217.149.17 (BG)"] == "high"
    assert sev["VPN port scan (handshake failures) from 45.79.5.11 (US)"] == "medium"


async def test_vpn_flapping_and_tunnel_down(owner_engine, env):
    cid, gw = env
    only(owner_engine, "vpn_flapping")
    out = Outbox()
    with owner_engine.begin() as c:
        for i in range(11):
            c.execute(text("INSERT INTO vpn_tunnel_state (client_id, device_id, tunnel_name, peer, state, started_at, ended_at) "
                           "VALUES (:c, :d, 'tunovpnc1', '11.124.200.216:1194', 'down', now() - make_interval(mins => :m), now() - make_interval(mins => :m) + interval '5 seconds')"),
                      {"c": cid, "d": gw, "m": 5 * i + 1})
    await run(out)
    await run(out)
    assert out.sent == [("open", "VPN tunnel tunovpnc1 on NW-HK is flapping")]


async def test_silent_source_firmware_and_wan_change(owner_engine, env):
    cid, gw = env
    out = Outbox()
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO devices (client_id, name, vendor, syslog_source_ip, created_at) VALUES (:c, 'SW1', 'unifi', '192.168.1.52', now() - interval '2 hours')"), {"c": cid})
        c.execute(text("UPDATE devices SET upgradable = true, firmware = '6.7.57', firmware_latest = '6.7.60' WHERE id = :d"), {"d": gw})
        c.execute(text("INSERT INTO device_metrics (ts, client_id, device_id, wan_ip) VALUES (now() - interval '2 minutes', :c, :d, '11.162.174.120'), "
                       "(now() - interval '1 minute', :c, :d, '11.180.249.28')"), {"c": cid, "d": gw})
    for rt in ("log_source_silent", "outdated_firmware", "wan_failover"):
        only(owner_engine, rt)
        await run(out)
        await run(out)
    assert out.sent == [("open", "SW1 has never sent logs"), ("open", "Firmware update available for NW-HK"),
                        ("open", "WAN address changed on NW-HK")]


async def test_client_specific_rule_and_disabled_rules(owner_engine, env):
    cid, gw = env
    out = Outbox()
    with owner_engine.begin() as c:
        other = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Other','other') RETURNING id")).scalar()
        od = c.execute(text("INSERT INTO devices (client_id, name, vendor) VALUES (:c,'other-gw','unifi') RETURNING id"), {"c": other}).scalar()
        c.execute(text("UPDATE alert_rules SET enabled = false"))
        c.execute(text("INSERT INTO alert_rules (client_id, name, rule_type, severity, params, channel_ids) "
                       "SELECT :c, 'Other offline', 'device_offline', 'critical', '{\"minutes\": 1}', channel_ids FROM alert_rules LIMIT 1"),
                  {"c": other})
        for d, c_ in ((gw, cid), (od, other)):
            c.execute(text("INSERT INTO device_state (client_id, device_id, state, started_at) VALUES (:c, :d, 'down', now() - interval '10 minutes')"),
                      {"c": c_, "d": d})
    await run(out)
    assert out.sent == [("open", "other-gw is offline")]


async def test_event_monitor_ui(client, make_user, owner_engine, env, audit_rows):
    cid, gw = env
    only(owner_engine, "device_offline")
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO device_state (client_id, device_id, state, started_at) VALUES (:c, :d, 'down', now() - interval '10 minutes')"),
                  {"c": cid, "d": gw})
    await run(Outbox())
    await full_login(client, make_user(role="admin", username="root-admin"))
    page = await client.get("/event-monitor")
    assert page.status_code == 200 and "NW-HK is offline" in page.text
    token = csrf_from(page.text)
    aid = page.text.split('action="/event-monitor/alerts/')[1].split("/")[0]
    assert (await client.post(f"/event-monitor/alerts/{aid}/ack", data={"csrf_token": token})).status_code == 303
    assert "by root-admin" in (await client.get("/event-monitor")).text
    bad = await client.post("/event-monitor/channels", data={"name": "x", "type": "teams", "target": "http://insecure", "csrf_token": token})
    assert bad.status_code == 400
    ok = await client.post("/event-monitor/channels", data={"name": "Teams NOC", "type": "teams",
                                                            "target": "https://example.webhook.office.com/secret-token", "csrf_token": token})
    assert ok.status_code == 303
    with owner_engine.connect() as c:
        assert "secret-token" not in c.execute(text("SELECT config_enc FROM notification_channels WHERE name = 'Teams NOC'")).scalar()
    rules = (await client.get("/event-monitor?tab=rules")).text
    with owner_engine.connect() as c:
        rid = c.execute(text("SELECT id FROM alert_rules WHERE rule_type = 'device_offline'")).scalar()
    assert f'action="/event-monitor/rules/{rid}"' in rules
    r = await client.post(f"/event-monitor/rules/{rid}", data={"enabled": "on", "minutes": "99999", "severity": "high", "throttle_minutes": "60", "csrf_token": token})
    assert r.status_code == 400
    assert audit_rows("alert_ack") and audit_rows("channel_create")


async def test_client_readonly_has_no_event_monitor(client, make_user, env):
    await full_login(client, make_user(role="client_readonly", username="viewer"))
    assert (await client.get("/event-monitor")).status_code == 403


async def test_per_client_email_routing(client, make_user, owner_engine, env):
    """Client 1 -> x@x.com, client 2 -> y@y.com, NOC (all clients) gets both. One global rule covers everyone."""
    cid, gw = env
    with owner_engine.begin() as c:
        c.execute(text("DELETE FROM notification_channels"))
        c.execute(text("UPDATE alert_rules SET channel_ids = '{}'"))
        c2 = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Client Two','two') RETURNING id")).scalar()
        d2 = c.execute(text("INSERT INTO devices (client_id, name, vendor) VALUES (:c, 'two-gw', 'unifi') RETURNING id"), {"c": c2}).scalar()
    await full_login(client, make_user(role="admin", username="root-admin"))
    token = csrf_from((await client.get("/event-monitor?tab=channels")).text)
    for name, target, client_id in (("Client 1 IT", "x@x.com", str(cid)), ("Client 2 IT", "y@y.com", str(c2)), ("NOC", "noc@msp.test", "")):
        r = await client.post("/event-monitor/channels", data={"name": name, "type": "email", "target": target,
                                                               "client_id": client_id, "all_rules": "1", "csrf_token": token})
        assert r.status_code == 303
    page = (await client.get("/event-monitor?tab=channels")).text
    assert "x@x.com" in page and "y@y.com" in page and "Device offline" in page
    only(owner_engine, "device_offline")
    with owner_engine.begin() as c:
        for c_, d in ((cid, gw), (c2, d2)):
            c.execute(text("INSERT INTO device_state (client_id, device_id, state, started_at) VALUES (:c, :d, 'down', now() - interval '10 minutes')"),
                      {"c": c_, "d": d})
    sent = []

    async def capture(channel, alert, kind, settings):
        from app.drivers.base import decrypt_secret
        sent.append((alert["client"], tuple(decrypt_secret(channel["config_enc"])["to"])))
        return "sent"
    await AlertEngine(deliver_fn=capture).evaluate()
    assert sorted(sent) == [("Client Two", ("noc@msp.test",)), ("Client Two", ("y@y.com",)),
                            ("Northwind HK", ("noc@msp.test",)), ("Northwind HK", ("x@x.com",))]


async def test_quiet_device_uses_its_own_silence_limit(owner_engine, env):
    cid, gw = env
    only(owner_engine, "log_source_silent")
    with owner_engine.begin() as c:
        quiet = c.execute(text("INSERT INTO devices (client_id, name, vendor, syslog_source_ip, last_log_at, silent_after_minutes) "
                               "VALUES (:c, 'NW-HK-SW1', 'unifi', '192.168.1.52', now() - interval '40 minutes', 720) RETURNING id"),
                          {"c": cid}).scalar()
        c.execute(text("INSERT INTO devices (client_id, name, vendor, syslog_source_ip, last_log_at) "
                       "VALUES (:c, 'NWHKWAP-03', 'unifi', '192.168.1.155', now() - interval '40 minutes')"), {"c": cid})
    out = Outbox()
    await run(out)
    titles = [t for _, t in out.sent]
    assert "NWHKWAP-03 has stopped sending logs" in titles and not any("NW-HK-SW1" in t for t in titles)

    from app.config import get_settings
    from app.poller.service import Poller
    p = Poller(get_settings(), drivers={})
    conn = await p.connect()
    try:
        await p.evaluate_states(conn)
    finally:
        await conn.close()
    with owner_engine.begin() as c:
        assert c.execute(text("SELECT state FROM device_state WHERE device_id = :d AND ended_at IS NULL"), {"d": quiet}).scalar() == "up"



async def test_alert_page_comments_and_email_link(client, make_user, owner_engine, env, audit_rows, monkeypatch):
    cid, gw = env
    only(owner_engine, "device_offline")
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO device_state (client_id, device_id, state, started_at) VALUES (:c, :d, 'down', now() - interval '10 minutes')"),
                  {"c": cid, "d": gw})
    from app.alerts import engine as eng
    from app.config import get_settings
    st = get_settings().model_copy(update={"public_url": "https://siem.example.test/"})
    captured = {}

    def fake_send(settings, to, subject, body, html=None):
        captured["body"], captured["html"] = body, html
    monkeypatch.setattr(eng, "_send_email", fake_send)
    st2 = st.model_copy(update={"smtp_host": "smtp.example.test"})
    await AlertEngine(settings=st2, deliver_fn=Outbox()).evaluate()
    with owner_engine.begin() as c:
        aid = c.execute(text("SELECT id FROM alerts")).scalar()
    alert = {"id": aid, "title": "x", "message": "m", "severity": "high", "client": "Northwind HK", "first_seen": NOW}
    status = await eng.deliver({"type": "email", "config_enc": __import__("app.drivers.base", fromlist=["x"]).encrypt_secret({"to": ["a@b.c"]})},
                               alert, "open", st2)
    assert status == "sent" and f"https://siem.example.test/event-monitor/alerts/{aid}" in captured["body"]
    assert "Open in the log server" not in captured["html"] and "Alert Details" in captured["html"]   # no link button

    await full_login(client, make_user(role="engineer", username="eng-a"))
    page = (await client.get(f"/event-monitor/alerts/{aid}")).text
    assert "NW-HK is offline" in page and "Related events" in page and "No comments yet." in page
    token = csrf_from(page)
    r = await client.post(f"/event-monitor/alerts/{aid}/comment", data={"body": "Checked: power cut at site.", "csrf_token": token})
    assert r.status_code == 303
    r = await client.post(f"/event-monitor/alerts/{aid}/ack", data={"csrf_token": token, "next": f"/event-monitor/alerts/{aid}"})
    assert r.headers["location"] == f"/event-monitor/alerts/{aid}"
    page = (await client.get(f"/event-monitor/alerts/{aid}")).text
    assert "Checked: power cut at site." in page and "eng-a" in page and "acknowledged" in page
    assert audit_rows("alert_comment")
    assert (await client.get("/event-monitor/alerts/999999")).status_code == 404


class Rendered:
    """Captures the rendered notification (subject, body) the way e-mail / Teams / Slack receive it."""
    def __init__(self):
        self.out = []

    async def __call__(self, channel, alert, kind, settings):
        from app.alerts.notice import render
        self.out.append(render(alert, kind, settings.alert_subject_prefix))
        return "sent"


async def test_notification_uses_the_noc_unifi_template(owner_engine, env):
    """Same layout as the NOC's UniFi alert e-mails: subject '<prefix>: <what> at <client>', Alert Details,
    Client/Device Details with tunnel name, WAN ISP and remote gateway."""
    cid, gw = env
    only(owner_engine, "vpn_tunnel_down", notify_resolve=True)
    down = datetime(2026, 9, 18, 22, 46, 39, tzinfo=UTC)
    with owner_engine.begin() as c:
        c.execute(text("UPDATE clients SET name = 'CTS KL' WHERE id = :c"), {"c": cid})
        c.execute(text("UPDATE devices SET name = 'CTS-KL', model = 'UDM SE' WHERE id = :d"), {"d": gw})
        c.execute(text("INSERT INTO wan_state (client_id, device_id, wan_name, ip, state, started_at) "
                       "VALUES (:c, :d, 'WAN2', '11.133.111.195', 'up', :t)"), {"c": cid, "d": gw, "t": down - timedelta(days=1)})
        c.execute(text("INSERT INTO vpn_tunnel_state (client_id, device_id, tunnel_name, peer, state, started_at) "
                       "VALUES (:c, :d, 'ipsec:CTSKL-PartnerNet', '11.229.44.205', 'down', :t)"), {"c": cid, "d": gw, "t": down})
    out = Rendered()
    await AlertEngine(deliver_fn=out).evaluate(down + timedelta(minutes=10))
    subject, body = out.out[0]
    assert subject == "UniFi Alert: CTSKL-PartnerNet - Site-to-Site VPN Tunnel Disconnected at CTS KL"
    assert body.startswith("Hello Team,\n\nA UniFi Network alert has been triggered:\n\nAlert Details\n")
    assert "Message: CTSKL-PartnerNet's Site-to-Site VPN tunnel to 11.229.44.205 has disconnected." in body
    assert "Time (UTC): 2026-09-18T22:46:39Z" in body
    details = body.split("Client/Device Details\n")[1]
    assert details.startswith("Client: CTS KL\nDevice: CTS-KL (UDM SE)\nTunnel Name: CTSKL-PartnerNet\n"
                              "WAN ISP: WAN2| 11.133.111.195\nRemote GW: 11.229.44.205")
    with owner_engine.begin() as c:                  # tunnel back up -> "resolved" in the same format
        c.execute(text("UPDATE vpn_tunnel_state SET ended_at = :t"), {"t": down + timedelta(minutes=20)})
        c.execute(text("INSERT INTO vpn_tunnel_state (client_id, device_id, tunnel_name, peer, state, started_at) "
                       "VALUES (:c, :d, 'ipsec:CTSKL-PartnerNet', '11.229.44.205', 'up', :t)"), {"c": cid, "d": gw, "t": down + timedelta(minutes=20)})
    await AlertEngine(deliver_fn=out).evaluate(down + timedelta(minutes=25))
    subject, body = out.out[1]
    assert subject.startswith("UniFi Alert: RESOLVED - CTSKL-PartnerNet") and "has been resolved:" in body and "Resolved (UTC):" in body



async def test_server_health_watches_the_log_server(owner_engine, env, monkeypatch):
    """Parser stopped (lines received, none parsed), backlog, missing backup and a full disk raise platform alerts under
    the platform client; they resolve when the condition clears."""
    import os as _os
    cid, gw = env
    only(owner_engine, "server_health")
    now = datetime.now(UTC)
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO audit_log (ts, username, action, success) VALUES (:t, 'x', 'login', true)"), {"t": now - timedelta(days=3)})
        c.execute(text("INSERT INTO ingest_stats (ts, component, received) VALUES (:t, 'receiver', 500)"), {"t": now - timedelta(minutes=2)})
        c.execute(text("INSERT INTO raw_logs (ts_received, client_id, device_id, source_ip, transport, raw) "
                       "VALUES (:t, :c, :d, '10.0.0.1', 'udp', 'x')"), {"t": now - timedelta(hours=1), "c": cid, "d": gw})

    class Full:
        f_blocks, f_bavail, f_frsize = 100, 5, 4096
    monkeypatch.setattr(_os, "statvfs", lambda p: Full())
    out = Outbox()
    await AlertEngine(deliver_fn=out).evaluate(now)
    titles = sorted(t for _, t in out.sent)
    assert titles == ["Log server: data disk 95 % full", "Log server: no successful backup",
                      "Log server: parser has stopped", "Log server: parser is falling behind"]
    with owner_engine.begin() as c:                         # healthy again
        c.execute(text("INSERT INTO ingest_stats (ts, component, parsed) VALUES (:t, 'parser', 500)"), {"t": now - timedelta(minutes=1)})
        c.execute(text("UPDATE raw_logs SET parsed = true"))
        c.execute(text("INSERT INTO audit_log (ts, username, action, success) VALUES (:t, 'backup', 'db_backup', true)"), {"t": now})

    class Empty:
        f_blocks, f_bavail, f_frsize = 100, 90, 4096
    monkeypatch.setattr(_os, "statvfs", lambda p: Empty())
    await AlertEngine(deliver_fn=out).evaluate(now + timedelta(minutes=1))
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM alerts WHERE status <> 'resolved'")).scalar() == 0



async def test_unifi_alert_relayed_immediately_in_noc_format(owner_engine, env):
    """UniFi's CEF 524 (a 27-second tunnel drop at CTS KL on 2026-10-09) becomes an alert at once, worded like the NOC's
    UniFi e-mails; events not on the list are ignored."""
    import json as _json
    cid, gw = env
    only(owner_engine, "unifi_event")
    now = datetime.now(UTC)
    with owner_engine.begin() as c:
        c.execute(text("""UPDATE alert_rules SET params = '{"event_ids": [524]}' WHERE rule_type = 'unifi_event'"""))
        c.execute(text("UPDATE alert_rules SET enabled = false WHERE name = 'Internet failover (secondary WAN)'"))   # one rule
        c.execute(text("UPDATE clients SET name = 'CTS KL' WHERE id = :c"), {"c": cid})
        filler = c.execute(text("INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class) "
                                "VALUES (now(), :c, :d, 0, now(), 'unifi', 'system', 'low', 'x') RETURNING id"), {"c": cid, "d": gw}).scalar()
        c.execute(text("INSERT INTO tracker_cursors (name, last_event_id) SELECT 'alerts:unifi:' || id, :f FROM alert_rules "
                       "WHERE rule_type = 'unifi_event'"), {"f": filler})     # cursor already past the filler: first run is over
        ins = text("""INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class, event_name,
                      message, extra) VALUES (:t, :c, :d, 0, :t, 'unifi', 'vpn', 'medium', :cls, :name, :msg, CAST(:x AS jsonb))""")
        c.execute(ins, {"t": now - timedelta(seconds=30), "c": cid, "d": gw, "cls": "cef:402", "name": "WiFi Client Roamed",
                        "msg": "phone roamed", "x": "{}"})
        c.execute(ins, {"t": now - timedelta(seconds=20), "c": cid, "d": gw, "cls": "cef:524",
                        "name": "Site-to-Site VPN Tunnel Disconnected",
                        "msg": "CTSKL-PartnerNet's Site-to-Site VPN tunnel to 11.229.44.205 has disconnected.",
                        "x": _json.dumps({"vpn_name": "CTSKL-PartnerNet", "wan_id": "WAN2", "vpn_local_ip": "11.133.111.195",
                                          "vpn_remote_gateway": "11.229.44.205", "vpn_type": "IPSEC_VPN"})})
    out = Rendered()
    await AlertEngine(deliver_fn=out).evaluate(now)
    assert len(out.out) == 1
    subject, body = out.out[0]
    assert subject == "UniFi Alert: CTSKL-PartnerNet -Site-to-Site VPN Tunnel Disconnected at CTS KL"
    assert "Message: CTSKL-PartnerNet's Site-to-Site VPN tunnel to 11.229.44.205 has disconnected." in body
    assert "Tunnel Name: CTSKL-PartnerNet\nWAN ISP: WAN2| 11.133.111.195\nRemote GW: 11.229.44.205" in body
    await AlertEngine(deliver_fn=out).evaluate(now + timedelta(minutes=1))
    assert len(out.out) == 1                                                           # each occurrence once



async def test_vpn_disconnect_alerts_after_a_minute_and_sends_resolved(owner_engine, env):
    """Site-to-site VPN: a 8-second blip is ignored; a 90-second outage that is already over still alerts and then resolves;
    an ongoing outage alerts after a minute and resolves (with its e-mail) when the tunnel is back."""
    import json as _json
    cid, gw = env
    only(owner_engine, "vpn_disconnect", notify_resolve=True, throttle_minutes=0)
    now = datetime.now(UTC).replace(microsecond=0)
    x = {"vpn_name": "CTSKL-PartnerNet", "wan_id": "WAN2", "vpn_local_ip": "11.133.111.195", "vpn_remote_gateway": "11.229.44.205"}
    drop = text("""INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class, event_name,
                   message, extra) VALUES (:t, :c, :d, 0, :t, 'unifi', 'vpn', 'medium', 'cef:524', 'Site-to-Site VPN Tunnel Disconnected',
                   'CTSKL-PartnerNet''s Site-to-Site VPN tunnel to 11.229.44.205 has disconnected.', CAST(:x AS jsonb))""")
    up = text("""INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class, action, message)
                 VALUES (:t, :c, :d, 0, :t, 'unifi', 'vpn', 'low', 'x', 'vpn-tunnel-up', 'IKE_SA established ...11.229.44.205[11.229.44.205]')""")
    out = Outbox()
    # 1) blip of 8 seconds -> nothing
    with owner_engine.begin() as c:
        c.execute(drop, {"t": now - timedelta(minutes=10), "c": cid, "d": gw, "x": _json.dumps(x)})
        c.execute(up, {"t": now - timedelta(minutes=10) + timedelta(seconds=8), "c": cid, "d": gw})
    await AlertEngine(deliver_fn=out).evaluate(now)
    assert out.sent == []
    # 2) a 90-second outage that is already over -> alert now, resolved on the next run
    with owner_engine.begin() as c:
        c.execute(drop, {"t": now - timedelta(minutes=5), "c": cid, "d": gw, "x": _json.dumps(x)})
        c.execute(up, {"t": now - timedelta(minutes=5) + timedelta(seconds=90), "c": cid, "d": gw})
    await AlertEngine(deliver_fn=out).evaluate(now)
    await AlertEngine(deliver_fn=out).evaluate(now + timedelta(minutes=1))
    assert out.sent == [("open", "Site-to-Site VPN Tunnel Disconnected: CTSKL-PartnerNet"),
                        ("resolve", "Site-to-Site VPN Tunnel Disconnected: CTSKL-PartnerNet")]
    # 3) still down: nothing for the first minute, then an alert; resolved when it comes back
    later = now + timedelta(minutes=2)
    with owner_engine.begin() as c:
        c.execute(drop, {"t": later, "c": cid, "d": gw, "x": _json.dumps(x)})
    await AlertEngine(deliver_fn=out).evaluate(later + timedelta(seconds=30))
    assert len(out.sent) == 2
    await AlertEngine(deliver_fn=out).evaluate(later + timedelta(seconds=75))
    assert out.sent[-1] == ("open", "Site-to-Site VPN Tunnel Disconnected: CTSKL-PartnerNet")
    with owner_engine.begin() as c:
        c.execute(up, {"t": later + timedelta(minutes=3), "c": cid, "d": gw})
    await AlertEngine(deliver_fn=out).evaluate(later + timedelta(minutes=4))
    assert out.sent[-1][0] == "resolve" and len(out.sent) == 4


def test_html_email_tables_logo_and_escaping():
    """The HTML alert e-mail: logo inline (cid), details in tables, red header when triggered and green when resolved,
    values escaped; the plain-text part stays for clients that do not show HTML."""
    from app.alerts.engine import build_email
    from app.alerts.notice import render, render_html
    from app.config import get_settings
    alert = {"id": 7, "title": "x", "message": "Tunnel <down> & out", "severity": "high", "client": "CTS KL",
             "first_seen": NOW, "notice": {"headline": "CTSKL-PartnerNet -Site-to-Site VPN Tunnel Disconnected",
                                           "message": "Tunnel <down> & out", "event_time": NOW,
                                           "facts": [("Client", "CTS KL"), ("Remote GW", "11.229.44.205")]}}
    html = render_html(alert, "open", "https://siem.example.test/event-monitor/alerts/7")
    assert "Alert Details" in html and "Client/Device Details" in html and "11.229.44.205" in html
    assert "Tunnel &lt;down&gt; &amp; out" in html and "<down>" not in html
    assert "cid:brand-logo" in html and "background:#1F6FB2" in html and "Alert #7" in html
    kl = render_html({**alert, "client_tz": "Asia/Kuala_Lumpur",
                      "notice": {**alert["notice"], "event_time": datetime(2026, 10, 9, 7, 37, 1, tzinfo=UTC)}}, "open")
    assert "Time (Kuala Lumpur, UTC+08:00)" in kl and "2026-10-09 15:37:01" in kl and "(UTC)" not in kl
    resolved = render_html({**alert, "resolved_at": NOW}, "resolve")
    assert "background:#4EA72E" in resolved and "Resolved (UTC)" in resolved   # no client time zone given: UTC
    subject, body = render(alert, "open", "UniFi Alert")
    msg = build_email(get_settings(), ["noc@example.com"], subject, body, html)
    parts = {p.get_content_type(): p for p in msg.walk()}
    assert "Hello Team," in parts["text/plain"].get_content() and "Alert Details" in parts["text/html"].get_content()
    assert parts["image/png"]["Content-ID"] == "<brand-logo>" and len(parts["image/png"].get_content()) > 1000



async def test_email_channel_with_cc(client, make_user, owner_engine, monkeypatch):
    """An e-mail channel can carry CC addresses: shown in the channel list, sent as a Cc header (delivered to all)."""
    from app.alerts import engine as eng
    from app.config import get_settings
    from app.drivers.base import decrypt_secret
    await full_login(client, make_user(username="root-admin", role="admin"))
    token = csrf_from((await client.get("/event-monitor?tab=channels")).text)
    r = await client.post("/event-monitor/channels", data={"name": "CTS customer", "type": "email", "csrf_token": token,
                                                           "target": "a@client.test b@client.test", "cc": "noc@msp.test"})
    assert r.status_code == 303
    with owner_engine.connect() as c:
        enc = c.execute(text("SELECT config_enc FROM notification_channels WHERE name = 'CTS customer'")).scalar()
    assert decrypt_secret(enc) == {"to": ["a@client.test", "b@client.test"], "cc": ["noc@msp.test"]}
    chan_page = (await client.get("/event-monitor?tab=channels")).text
    assert "cc: noc@msp.test" in chan_page
    assert 'data-dialog="new-channel"' in chan_page and '<dialog id="new-channel"' in chan_page    # form in a pop-up
    inc_page = (await client.get("/incidents")).text
    assert 'data-dialog="new-incident"' in inc_page and '<dialog id="new-incident"' in inc_page
    rules_page = (await client.get("/event-monitor?tab=rules")).text          # recipients visible on every rule's channel list
    assert "CTS customer" in rules_page and "a@client.test, b@client.test · cc: noc@msp.test" in rules_page
    bad = await client.post("/event-monitor/channels", data={"name": "x", "type": "email", "csrf_token": token,
                                                             "target": "a@client.test", "cc": "not-an-address"})
    assert bad.status_code == 400

    msg = eng.build_email(get_settings(), ["a@client.test"], "s", "b", "<p>h</p>", ["noc@msp.test"])
    assert msg["Cc"] == "noc@msp.test" and msg["To"] == "a@client.test"
    sent = {}
    monkeypatch.setattr(eng, "_send_email", lambda st, to, subject, body, html=None, cc=None: sent.update(to=to, cc=cc))
    alert = {"id": 1, "title": "x", "message": "m", "severity": "high", "client": "Northwind HK", "first_seen": NOW}
    await eng.deliver({"type": "email", "config_enc": enc}, alert, "open",
                      get_settings().model_copy(update={"smtp_host": "smtp.example.test"}))
    assert sent == {"to": ["a@client.test", "b@client.test"], "cc": ["noc@msp.test"]}



async def test_edit_channel_recipients(client, make_user, owner_engine, audit_rows):
    """Edit an e-mail channel's name, To and CC; a webhook keeps its URL when the field is left empty."""
    from app.drivers.base import decrypt_secret, encrypt_secret
    with owner_engine.begin() as c:
        mail = c.execute(text("INSERT INTO notification_channels (name, type, config_enc) VALUES ('NOC', 'email', :c) RETURNING id"),
                         {"c": encrypt_secret({"to": ["old@msp.test"]})}).scalar()
        hook = c.execute(text("INSERT INTO notification_channels (name, type, config_enc) VALUES ('Teams', 'teams', :c) RETURNING id"),
                         {"c": encrypt_secret({"url": "https://hooks.example.test/secret-path"})}).scalar()
    await full_login(client, make_user(username="root-admin", role="admin"))
    page = (await client.get("/event-monitor?tab=channels")).text
    assert f'data-dialog="edit-ch-{mail}"' in page and "old@msp.test" in page and "secret-path" not in page
    token = csrf_from(page)
    r = await client.post(f"/event-monitor/channels/{mail}/edit", data={"csrf_token": token, "name": "NOC team",
                                                                       "target": "a@msp.test\nb@msp.test", "cc": "boss@msp.test"})
    assert r.status_code == 303
    r = await client.post(f"/event-monitor/channels/{hook}/edit", data={"csrf_token": token, "name": "Teams NOC", "target": ""})
    assert r.status_code == 303
    bad = await client.post(f"/event-monitor/channels/{mail}/edit", data={"csrf_token": token, "name": "x", "target": "not-an-address"})
    assert bad.status_code == 400
    with owner_engine.connect() as c:
        rows = {r.id: (r.name, decrypt_secret(r.config_enc)) for r in c.execute(text("SELECT id, name, config_enc FROM notification_channels"))}
    assert rows[mail] == ("NOC team", {"to": ["a@msp.test", "b@msp.test"], "cc": ["boss@msp.test"]})
    assert rows[hook] == ("Teams NOC", {"url": "https://hooks.example.test/secret-path"})
    assert audit_rows("channel_edit")[0]["details"]["before"] == {"to": ["old@msp.test"], "cc": []}
