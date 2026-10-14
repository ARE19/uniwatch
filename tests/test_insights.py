"""Phase 7: Insights top-N views over continuous aggregates; scoping and drill-down links."""

import pytest
from sqlalchemy import text

from tests.conftest import full_login
from tests.test_logview import _add


@pytest.fixture
def data(owner_engine):
    with owner_engine.begin() as c:
        out = {}
        for slug in ("acme", "globex"):
            cid = c.execute(text("INSERT INTO clients (name, slug) VALUES (:n, :s) RETURNING id"), {"n": slug.title(), "s": slug}).scalar()
            did = c.execute(text("INSERT INTO devices (client_id, name, vendor) VALUES (:c, :n, 'unifi') RETURNING id"),
                            {"c": cid, "n": f"{slug}-gw"}).scalar()
            out[slug] = (cid, did)
        a, g = out["acme"], out["globex"]
        for _ in range(3):
            _add(c, *a, category="vpn", src="85.217.149.17", action="vpn-tls-error")
        _add(c, *a, category="ids", src="10.172.16.125", dst="192.168.1.50")
        _add(c, *a, category="dns", src="192.168.1.27", action="dns-block", extra='{"domain": "ads.example.com"}')
        _add(c, *g, category="vpn", src="203.0.113.250", action="vpn-tls-error")
        c.execute(text("UPDATE events SET outcome = 'failure' WHERE action = 'vpn-tls-error'"))
        c.execute(text("UPDATE events SET outcome = 'blocked', rule = 'ADVERTISEMENT' WHERE action = 'dns-block'"))
        c.execute(text("UPDATE events SET rule = 'ET SCAN Potential SSH Scan' WHERE category = 'ids'"))
        c.execute(text("UPDATE events SET src_country = 'BG' WHERE host(src_ip) = '85.217.149.17'"))
    return out


@pytest.mark.parametrize("view", ["sources", "destinations", "countries", "threats", "blocked", "dns", "wifi", "admin", "system"])
async def test_every_view_renders(client, make_user, data, view):
    await full_login(client, make_user(role="engineer"))
    r = await client.get(f"/insights?view={view}&range=24h")
    assert r.status_code == 200


async def test_top_sources_and_drilldown(client, make_user, data):
    await full_login(client, make_user(role="engineer"))
    r = (await client.get("/insights?view=sources&range=24h")).text
    assert r.index("85.217.149.17") < r.index("10.172.16.125")  # 3 events beat 1
    assert "/logs?range=24h&amp;ip=85.217.149.17" in r
    b = (await client.get("/insights?view=blocked&range=24h")).text
    assert "vpn-tls-error" in b and "dns-block" in b
    assert "ads.example.com" in (await client.get("/insights?view=dns&range=24h")).text
    assert "ET SCAN Potential SSH Scan" in (await client.get("/insights?view=threats&range=24h")).text
    assert "BG" in (await client.get("/insights?view=countries&range=24h")).text


async def test_client_user_scoped_and_no_drilldown(client, make_user, owner_engine, data):
    viewer = make_user(role="client_readonly", username="viewer")
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO user_clients (user_id, client_id) VALUES (:u, :c)"), {"u": viewer["id"], "c": data["acme"][0]})
    await full_login(client, viewer)
    r = (await client.get("/insights?view=sources&range=24h")).text
    assert "85.217.149.17" in r and "203.0.113.250" not in r
    assert "/logs?" not in r and 'href="/ip/' not in r



async def test_world_map_data(client, make_user, owner_engine):
    import json as _json
    from datetime import UTC, datetime
    from sqlalchemy import text as _text
    with owner_engine.begin() as c:
        cid = c.execute(_text("INSERT INTO clients (name, slug) VALUES ('Map','map') RETURNING id")).scalar()
        dev = c.execute(_text("INSERT INTO devices (client_id, name, vendor) VALUES (:c, 'gw', 'unifi') RETURNING id"), {"c": cid}).scalar()
        for cc, outcome, n in (("CN", "blocked", 3), ("US", "allowed", 1)):
            for _ in range(n):
                c.execute(_text("""INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class,
                                   outcome, src_ip, src_country, dst_ip, dst_country, bytes_out, message)
                                   VALUES (now(), :c, :d, 0, now(), 'unifi', 'firewall', 'low', 'x', :o, '218.92.0.1', :cc,
                                           '192.168.1.5', NULL, 2097152, 'x')"""), {"c": cid, "d": dev, "o": outcome, "cc": cc})
    await full_login(client, make_user(role="engineer", username="mapper"))
    page = (await client.get("/insights?view=countries&range=24h")).text
    assert 'id="worldmap"' in page and "echarts.min.js" in page
    data = _json.loads(page.split('id="worldmap-data">')[1].split("</script>")[0])
    assert data["data"] == [{"name": "CN", "value": 3.0}] and "srccountry%3D__CC__" in data["link"] and data["staff"] is True


async def test_devices_and_usage_view(client, make_user, owner_engine):
    """Per device (by MAC, named from the flow or DHCP): its apps and websites with download / upload, and per website the
    devices using it. NetFlow downloads (no MAC) count for the device whose IP sent in the same hour."""
    import json as _json
    from datetime import UTC, datetime, timedelta
    hour = datetime.now(UTC).replace(minute=0, second=0, microsecond=0) - timedelta(hours=2)
    with owner_engine.begin() as c:
        cid = c.execute(text("INSERT INTO clients (name, slug) VALUES ('CTS KL','cts-kl') RETURNING id")).scalar()
        gw = c.execute(text("INSERT INTO devices (client_id, name, vendor) VALUES (:c,'CTS-KL','unifi') RETURNING id"), {"c": cid}).scalar()
        ins = text("""INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class, action, rule,
                      src_ip, dst_ip, src_mac, bytes_in, bytes_out, message, extra)
                      VALUES (:t, :c, :d, 0, :t, 'unifi', 'traffic', 'low', 'x', :act, :rule, :src, :dst, :mac, :bi, :bo, 'm', CAST(:x AS jsonb))""")
        rows = [  # API flow: laptop -> Microsoft 365 (download 5 MB, upload 1 MB)
            (hour + timedelta(minutes=5), "flow", "Microsoft 365 apps", "192.168.2.56", "52.97.1.1", "a8:72:4d:8f:fe:82", 5_000_000, 1_000_000,
             {"direction": "outgoing", "domain": "office365.com", "src_name": "LAPTOP-26CU0N15"}),
            # NetFlow: phone uploads 100 B to Google, downloads 9 MB (download record has no MAC)
            (hour + timedelta(minutes=6), "netflow", None, "192.168.2.197", "142.250.1.1", "c2:0b:3a:fd:b8:d2", None, 100,
             {"direction": "outgoing", "dst_as_org": "Google LLC"}),
            (hour + timedelta(minutes=7), "netflow", None, "142.250.1.1", "192.168.2.197", None, None, 9_000_000,
             {"direction": "incoming", "src_as_org": "Google LLC"}),
        ]
        for t, act, rule, src, dst, mac, bi, bo, x in rows:
            c.execute(ins, {"t": t, "c": cid, "d": gw, "act": act, "rule": rule, "src": src, "dst": dst, "mac": mac, "bi": bi,
                            "bo": bo, "x": _json.dumps(x)})
        c.execute(text("""INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class, action,
                          src_ip, src_mac, message, extra) VALUES (:t, :c, :d, 0, :t, 'unifi', 'dhcp', 'low', 'x', 'dhcp-ack',
                          '192.168.2.197', 'c2:0b:3a:fd:b8:d2', 'm', '{"hostname": "Eves-iPhone"}')"""),
                  {"t": hour - timedelta(days=1), "c": cid, "d": gw})
    await full_login(client, make_user(role="engineer"))
    page = (await client.get("/insights?view=usage&range=24h")).text
    assert page.index("Eves-iPhone") < page.index("LAPTOP-26CU0N15")                 # 9 MB > 6 MB
    assert "c2:0b:3a:fd:b8:d2" in page and "Google LLC" in page and "office365.com" in page
    assert ">Applications" in page and "Microsoft 365 apps" in page and ">Services" in page
    chart = _json.loads(page.split('id="usage-data">')[1].split("</script>")[0])
    assert {s["name"] for s in chart["series"]} == {"Google LLC", "office365.com"} and len(chart["x"]) >= 24
    one = (await client.get("/insights?view=usage&range=24h&dev=c2:0b:3a:fd:b8:d2")).text
    assert "Eves-iPhone" in one and "Google LLC" in one and "office365.com" not in one.split("Bandwidth over time")[1]
    assert "8.6 MB" in one                                                                 # download attributed by IP (9,000,000 B)
    hist = one.split('id="history"')[1]
    assert "Access history" in one and "142.250.1.1" in hist and "Google LLC" in hist and "srcmac%3Dc2%3A0b%3A3a" in hist
    lap = (await client.get("/insights?view=usage&range=24h&dev=a8:72:4d:8f:fe:82")).text.split('id="history"')[1]
    assert "office365.com" in lap and "Microsoft 365 apps" in lap and "4.8 MB" in lap
    site = (await client.get("/insights?view=usage&range=24h&item=Google+LLC&kind=site")).text
    assert "Devices using Google LLC" in site and "Eves-iPhone" in site and "LAPTOP-26CU0N15" not in site
    chart = _json.loads(site.split('id="usage-data">')[1].split("</script>")[0])
    assert [s["name"] for s in chart["series"]] == ["Download", "Upload"] and sum(chart["series"][0]["data"]) == 9_000_000


async def test_router_mac_is_not_a_device(client, make_user, owner_engine):
    """Users behind a second router (BLU-P6): the UDM sees the router's MAC on everyone's traffic. A MAC with more than
    4 IPs in an hour is treated as a router and the traffic is shown per IP instead of as one huge 'device'."""
    import json as _json
    from datetime import UTC, datetime, timedelta
    hour = datetime.now(UTC).replace(minute=0, second=0, microsecond=0) - timedelta(hours=2)
    with owner_engine.begin() as c:
        cid = c.execute(text("INSERT INTO clients (name, slug) VALUES ('HIP P6','hip') RETURNING id")).scalar()
        gw = c.execute(text("INSERT INTO devices (client_id, name, vendor) VALUES (:c,'BLU-P6-UDM2','unifi') RETURNING id"), {"c": cid}).scalar()
        for i in range(6):
            c.execute(text("""INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class, action,
                              src_ip, dst_ip, dst_mac, bytes_out, message, extra)
                              VALUES (:t, :c, :d, 0, :t, 'unifi', 'traffic', 'low', 'x', 'netflow', '142.250.1.1', :ip,
                                      'd8:b3:70:03:fc:26', :b, 'm', '{"direction": "incoming", "src_as_org": "Google LLC"}')"""),
                      {"t": hour + timedelta(minutes=i), "c": cid, "d": gw, "ip": f"192.168.1.{100 + i}", "b": 1000 * (i + 1)})
    await full_login(client, make_user(role="engineer"))
    page = (await client.get("/insights?view=usage&range=24h")).text
    devices = page.split("<h2>Devices")[1].split("</table>")[0]
    assert "d8:b3:70:03:fc:26" not in devices and devices.count("(no MAC)") == 6
