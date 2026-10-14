"""Event Monitor rules editor: enable, client, severity and e-mail recipients per rule; copies per client; delivery."""

import re

import pytest
from sqlalchemy import text

from app.alerts.engine import AlertEngine
from app.drivers.base import decrypt_secret
from tests.conftest import csrf_from, full_login


@pytest.fixture
def two(owner_engine):
    with owner_engine.begin() as c:
        c.execute(text("DELETE FROM notification_channels"))
        c.execute(text("UPDATE alert_rules SET channel_ids = '{}', enabled = false"))
        acme = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Acme','acme') RETURNING id")).scalar()
        beta = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Beta','beta') RETURNING id")).scalar()
        devs = {cid: c.execute(text("INSERT INTO devices (client_id, name, vendor) VALUES (:c, :n, 'unifi') RETURNING id"),
                               {"c": cid, "n": f"gw-{cid}"}).scalar() for cid in (acme, beta)}
        rule = c.execute(text("SELECT id FROM alert_rules WHERE rule_type = 'device_offline'")).scalar()
    return {"acme": acme, "beta": beta, "devs": devs, "rule": rule}


def form(token, **kw):
    return {"csrf_token": token, "severity": "high", "throttle_minutes": "60", "minutes": "5", **kw}


async def test_rules_list_is_clickable_and_editable(client, make_user, owner_engine, two, audit_rows):
    await full_login(client, make_user(role="engineer"))
    page = (await client.get("/event-monitor?tab=rules")).text
    assert f'<details class="rule-row" id="rule-{two["rule"]}"' in page and "pill-off" in page and "All clients" in page
    token = csrf_from(page)
    r = await client.post(f"/event-monitor/rules/{two['rule']}", data=form(
        token, enabled="on", client_id=str(two["acme"]), severity="critical", email_to="x@x.com; IT@Acme.com, x@x.com"))
    assert r.status_code == 303 and r.headers["location"].endswith(f"open={two['rule']}#rule-{two['rule']}")
    with owner_engine.begin() as c:
        rule = c.execute(text("SELECT enabled, client_id, severity FROM alert_rules WHERE id = :i"), {"i": two["rule"]}).one()
        ch = c.execute(text("SELECT config_enc, client_id FROM notification_channels WHERE owner_rule_id = :i"),
                       {"i": two["rule"]}).one()
    assert tuple(rule) == (True, two["acme"], "critical")
    assert decrypt_secret(ch.config_enc) == {"to": ["x@x.com", "it@acme.com"]} and "x@x.com" not in ch.config_enc
    page = (await client.get(f"/event-monitor?tab=rules&open={two['rule']}")).text
    assert "pill-on" in page and "✉ x@x.com, it@acme.com" in page and f'id="rule-{two["rule"]}" open' in page
    assert "Rule e-mail:" not in (await client.get("/event-monitor?tab=channels")).text   # rule-owned, not a shared channel
    assert audit_rows("alert_rule_update")
    # clearing the addresses removes the rule's channel
    await client.post(f"/event-monitor/rules/{two['rule']}", data=form(token, enabled="on", email_to=""))
    with owner_engine.begin() as c:
        assert c.execute(text("SELECT count(*) FROM notification_channels WHERE owner_rule_id = :i"), {"i": two["rule"]}).scalar() == 0


async def test_validation(client, make_user, owner_engine, two):
    await full_login(client, make_user(role="engineer"))
    token = csrf_from((await client.get("/event-monitor?tab=rules")).text)
    bad = await client.post(f"/event-monitor/rules/{two['rule']}", data=form(token, email_to="not-an-address"))
    assert bad.status_code == 400 and "not-an-address" in bad.text
    assert (await client.post(f"/event-monitor/rules/{two['rule']}", data=form(token, client_id="99999"))).status_code == 403


async def test_copy_per_client_and_delivery(client, make_user, owner_engine, two):
    await full_login(client, make_user(role="engineer"))
    token = csrf_from((await client.get("/event-monitor?tab=rules")).text)
    rid = two["rule"]
    # Global rule -> Acme's IT; a copy for Beta -> Beta's IT
    await client.post(f"/event-monitor/rules/{rid}", data=form(token, enabled="on", client_id=str(two["acme"]), email_to="it@acme.com"))
    r = await client.post(f"/event-monitor/rules/{rid}/copy", data={"client_id": str(two["beta"]), "csrf_token": token})
    assert r.status_code == 303
    copy_id = int(re.search(r"open=(\d+)", r.headers["location"]).group(1))
    with owner_engine.begin() as c:
        name, cid, enabled = c.execute(text("SELECT name, client_id, enabled FROM alert_rules WHERE id = :i"), {"i": copy_id}).one()
    assert (name, cid, enabled) == ("Device offline (Beta)", two["beta"], False)
    await client.post(f"/event-monitor/rules/{copy_id}", data=form(token, enabled="on", client_id=str(two["beta"]), email_to="it@beta.com"))
    with owner_engine.begin() as c:
        for cid, dev in two["devs"].items():
            c.execute(text("INSERT INTO device_state (client_id, device_id, state, started_at) "
                           "VALUES (:c, :d, 'down', now() - interval '10 minutes')"), {"c": cid, "d": dev})
    sent = []

    async def capture(channel, alert, kind, settings):
        sent.append((alert["client"], tuple(decrypt_secret(channel["config_enc"])["to"])))
        return "sent"
    await AlertEngine(deliver_fn=capture).evaluate()
    assert sorted(sent) == [("Acme", ("it@acme.com",)), ("Beta", ("it@beta.com",))]
    # client copies can be deleted, the built-in global rules cannot
    page = (await client.get("/event-monitor?tab=rules")).text
    assert page.index(f'id="rule-{rid}"') < page.index(f'id="rule-{copy_id}"')      # the copy sits right after its original
    assert (await client.post(f"/event-monitor/rules/{copy_id}/delete", data={"csrf_token": token})).status_code == 303
    with owner_engine.begin() as c:
        c.execute(text("UPDATE alert_rules SET client_id = NULL WHERE id = :i"), {"i": rid})
    assert (await client.post(f"/event-monitor/rules/{rid}/delete", data={"csrf_token": token})).status_code == 400


async def test_send_test_email(client, make_user, owner_engine, two, monkeypatch):
    import app.web.routes_events as ev
    got = []

    async def fake(channel, alert, kind, settings):
        got.append((decrypt_secret(channel["config_enc"])["to"], alert["title"]))
        return "sent"
    monkeypatch.setattr(ev, "deliver", fake)
    await full_login(client, make_user(role="engineer"))
    token = csrf_from((await client.get("/event-monitor?tab=rules")).text)
    r = await client.post(f"/event-monitor/rules/{two['rule']}/test", data={"csrf_token": token})
    assert "no%20e-mail%20addresses" in r.headers["location"]
    await client.post(f"/event-monitor/rules/{two['rule']}", data=form(token, email_to="noc@msp.test"))
    r = await client.post(f"/event-monitor/rules/{two['rule']}/test", data={"csrf_token": token})
    assert "test=sent" in r.headers["location"] and got == [(["noc@msp.test"], "Test: Device offline")]
