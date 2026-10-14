"""Log View search bar (field filters), log-type tabs, column chooser; and a CSP guard for templates."""

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from starlette.datastructures import MultiDict

from app.web.logquery import LogQuery
from tests.conftest import full_login


def lq(q: str, **kw) -> LogQuery:
    return LogQuery.from_params(MultiDict([("q", q), *kw.items()]), "UTC")


def test_parse_terms_aliases_and_words():
    x = lq('srcip=192.168.1.0/24 dport=80,443 app="Microsoft Teams" action!=flow remote=*.microsoft.com sent>1000 tls "bad mac"')
    assert [(t.field, t.op, t.values) for t in x.terms] == [
        ("srcip", "=", ["192.168.1.0/24"]), ("dstport", "=", ["80", "443"]), ("app", "=", ["Microsoft Teams"]),
        ("action", "!=", ["flow"]), ("remote", "=", ["*.microsoft.com"]), ("sent", ">", ["1000"])]
    assert x.words == ["tls", "bad mac"] and not x.errors


@pytest.mark.parametrize("q,error", [
    ("foo=1", "Unknown field 'foo'"), ("srcip=999.1.1.1", "not an IP address"), ("dstport=https", "whole number"),
    ("srcip>1.2.3.4", "use = or !="), ("app>3", "is text"), ("user=", "needs a value"),
])
def test_parse_errors(q, error):
    assert any(error in e for e in lq(q).errors)


def test_unmatched_quote_falls_back_to_words():
    x = lq("can't connect")
    assert x.words == ["can't", "connect"] and not x.errors


def test_columns_and_tabs_roundtrip():
    x = LogQuery.from_params(MultiDict([("type", "traffic"), ("cols", "ts,src,bogus,app"), ("q", "app=YouTube")]), "UTC")
    assert x.logtype == "traffic" and x.cols == ["ts", "src", "app"] and x.columns() == ["ts", "src", "app"]
    assert "type=traffic" in x.qs() and "cols=ts%2Csrc%2Capp" in x.qs()
    assert LogQuery.from_params(MultiDict([("type", "evil")]), "UTC").logtype == ""
    assert LogQuery.from_params(MultiDict([("type", "traffic")]), "UTC").columns()[:3] == ["num", "ts", "device"]


def test_templates_have_no_inline_event_handlers():
    """script-src 'self' blocks inline handlers, so they would silently do nothing."""
    root = Path(__file__).resolve().parent.parent / "app" / "templates"
    offenders = [f"{p.name}: {m.group(0)}" for p in root.glob("*.html")
                 for m in re.finditer(r"\son[a-z]+\s*=\s*[\"']", p.read_text(encoding="utf-8"))]
    assert offenders == []


# ---- end to end --------------------------------------------------------------------------------
@pytest.fixture
def events(owner_engine):
    now = datetime.now(UTC)
    with owner_engine.begin() as c:
        cid = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Northwind HK','nwhk') RETURNING id")).scalar()
        dev = c.execute(text("INSERT INTO devices (client_id, name, vendor) VALUES (:c, 'NW-HK', 'unifi') RETURNING id"),
                        {"c": cid}).scalar()
        rows = [  # (minutes ago, category, action, src, sport, dst, dport, rule, bytes_in, bytes_out, message, extra)
            (5, "traffic", "flow", "192.168.1.27", 50000, "142.250.66.78", 443, "YouTube", 9_000_000, 200_000,
             "PC08-L1218 → rr1.googlevideo.com:443 (YouTube) HTTPS", {"fqdn": "rr1.googlevideo.com", "domain": "googlevideo.com",
              "app": "YouTube", "app_category": "Video streaming", "service": "HTTPS", "src_name": "PC08-L1218", "direction": "outgoing"}),
            (6, "traffic", "flow", "192.168.1.54", 50001, "52.112.0.10", 443, "Microsoft Teams", 50_000, 40_000,
             "Sam-Desktop → teams.microsoft.com:443 (Microsoft Teams) HTTPS", {"fqdn": "teams.microsoft.com", "domain": "microsoft.com",
              "app": "Microsoft Teams", "service": "HTTPS", "src_name": "Sam-Desktop", "direction": "outgoing"}),
            (7, "firewall", "flow-blocked", "192.168.1.62", 50002, "76.76.2.2", 53, "Firewall", None, None,
             "PC29-W0612 → 76.76.2.2:53 DNS BLOCKED by Firewall", {"service": "DNS", "src_name": "PC29-W0612", "direction": "outgoing"}),
            (8, "vpn", "vpn-tls-error", "218.92.0.1", 40000, "11.162.174.120", 1194, None, None, None,
             "TLS Error: TLS handshake failed", {}),
            (9, "system", None, None, None, None, None, None, None, None, "kernel: link up", {}),
        ]
        for mins, cat, action, src, sport, dst, dport, rule, bin_, bout, msg, extra in rows:
            c.execute(text("""INSERT INTO events (ts, client_id, device_id, raw_id, raw_ts, vendor, category, severity, event_class,
                              action, src_ip, src_port, dst_ip, dst_port, rule, bytes_in, bytes_out, message, extra, protocol)
                              VALUES (:t, :c, :d, 0, :t, 'unifi', :cat, 'low', 'x', :a, :s, :sp, :ds, :dp, :r, :bi, :bo, :m,
                                      CAST(:x AS jsonb), 'tcp')"""),
                      {"t": now - timedelta(minutes=mins), "c": cid, "d": dev, "cat": cat, "a": action, "s": src, "sp": sport,
                       "ds": dst, "dp": dport, "r": rule, "bi": bin_, "bo": bout, "m": msg, "x": json.dumps(extra)})
    return cid


async def search(client, **params):
    r = await client.get("/logs", params={"range": "1h", **params})
    assert r.status_code == 200
    return r.text


def shown(html: str) -> set[str]:
    return {m for m in ("googlevideo", "teams.microsoft", "76.76.2.2", "TLS Error", "kernel: link up") if m in html}


async def test_field_search_end_to_end(client, make_user, events):
    await full_login(client, make_user(role="engineer"))
    assert shown(await search(client)) == {"googlevideo", "teams.microsoft", "76.76.2.2", "TLS Error", "kernel: link up"}
    assert shown(await search(client, q="srcip=192.168.1.27")) == {"googlevideo"}
    assert shown(await search(client, q="srcip=192.168.1.0/24 dstport=443")) == {"googlevideo", "teams.microsoft"}
    assert shown(await search(client, q="app=youtube")) == {"googlevideo"}
    assert shown(await search(client, q='app="Microsoft Teams"')) == {"teams.microsoft"}
    assert shown(await search(client, q="remote=*.microsoft.com")) == {"teams.microsoft"}
    assert shown(await search(client, q="dstport=53,1194")) == {"76.76.2.2", "TLS Error"}
    assert shown(await search(client, q="rcvd>1000000")) == {"googlevideo"}
    assert shown(await search(client, q="srcname=PC*")) == {"googlevideo", "76.76.2.2"}
    assert "googlevideo" not in shown(await search(client, q="app!=YouTube"))
    assert "kernel: link up" in shown(await search(client, q="app!=YouTube"))   # != keeps rows without the field
    assert shown(await search(client, q="ip=76.76.2.2")) == {"76.76.2.2"}
    assert shown(await search(client, q="TLS handshake")) == {"TLS Error"}
    assert "Unknown field" in await search(client, q="nonsense=1")


async def test_tabs_columns_and_filter_cells(client, make_user, events):
    await full_login(client, make_user(role="engineer"))
    html = await search(client, type="traffic")
    assert shown(html) == {"googlevideo", "teams.microsoft", "76.76.2.2"}
    assert ">Remote name<" in html and ">Application<" in html and ">Sent<" in html
    assert 'data-f="app" data-v="YouTube"' in html and 'data-f="srcip" data-v="192.168.1.27"' in html
    assert "8.6 MB" in html                                    # received bytes, human readable
    assert re.findall(r'<td class="num muted">(\d+)</td>', html) == ["1", "2", "3"]   # row numbers
    assert shown(await search(client, type="security")) == set()
    assert shown(await search(client, type="vpn")) == {"TLS Error"}
    assert shown(await search(client, type="system")) == {"kernel: link up"}
    html = await search(client, type="traffic", cols="ts,app")
    assert re.search(r"<thead>\s*<tr><th class=\"col-ts\">Date/Time</th><th class=\"col-app\">Application</th></tr>", html)


async def test_csv_has_flow_fields(client, make_user, events):
    await full_login(client, make_user(role="engineer"))
    r = await client.get("/logs/export.csv", params={"range": "1h", "q": "app=YouTube"})
    lines = r.text.strip().splitlines()
    assert len(lines) == 2 and "src_name,remote_name,app,service,bytes_sent,bytes_received" in lines[0]
    assert lines[1].endswith("PC08-L1218,rr1.googlevideo.com,YouTube,HTTPS,200000,9000000")


async def test_histogram_and_group_by(client, make_user, events):
    await full_login(client, make_user(role="engineer"))
    html = await search(client)
    assert 'class="card histo"' in html and "5 events" in html
    assert re.search(r'href="/logs\?range=custom&amp;from=\d{4}-\d\d-\d\dT\d\d%3A\d\d%3A\d\d&amp;to=', html)   # bars zoom in
    grouped = await search(client, group="srcip", type="traffic")
    assert "Grouped by Source IP" in grouped and 'href="/ip/192.168.1.27"' in grouped and "show events" in grouped
    assert 'class="logrow"' not in grouped                                     # the grouped view replaces the rows
    drill = re.search(r'href="/logs\?([^"]*q=srcip%3D192\.168\.1\.27[^"]*)"', grouped).group(1).replace("&amp;", "&")
    page = (await client.get("/logs?" + drill)).text
    assert shown(page) == {"googlevideo"} and "Grouped by" not in page
    apps = await search(client, group="app")
    assert "YouTube" in apps and "Microsoft Teams" in apps and "(empty)" in apps
