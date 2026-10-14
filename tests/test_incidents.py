"""Phase 12: incidents — manual, from alert, automatic by rule; timeline, linking, scoping, audit."""

from datetime import UTC, datetime

from sqlalchemy import text

from app.alerts.engine import AlertEngine
from tests.conftest import csrf_from, full_login
from tests.test_alerts import Outbox, env, only  # noqa: F401  (fixtures)
from tests.test_logview import _add


async def _staff(client, make_user):
    await full_login(client, make_user(role="engineer", username="eng"))
    return csrf_from((await client.get("/incidents")).text)


async def test_manual_incident_lifecycle(client, make_user, owner_engine, env, audit_rows):
    cid, gw = env
    token = await _staff(client, make_user)
    r = await client.post("/incidents", data={"client_id": str(cid), "title": "Suspicious VPN scanning", "severity": "high",
                                              "description": "Lots of TLS errors", "csrf_token": token})
    assert r.status_code == 303
    iid = r.headers["location"].rsplit("/", 1)[1]
    with owner_engine.connect() as c:
        uid = c.execute(text("SELECT id FROM users WHERE username = 'eng'")).scalar()
    await client.post(f"/incidents/{iid}/update", data={"status": "investigating", "severity": "critical",
                                                         "assignee_id": str(uid), "csrf_token": token})
    await client.post(f"/incidents/{iid}/note", data={"body": "Blocked 85.217.149.17 upstream", "csrf_token": token})
    page = (await client.get(f"/incidents/{iid}")).text
    for s in ("Status new → investigating", "Severity high → critical", "Assigned to eng", "Blocked 85.217.149.17 upstream"):
        assert s in page
    assert audit_rows("incident_create") and audit_rows("incident_update") and audit_rows("incident_note")
    await client.post(f"/incidents/{iid}/update", data={"status": "closed", "csrf_token": token})
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT closed_at IS NOT NULL FROM incidents")).scalar()
    assert "Suspicious VPN scanning" not in (await client.get("/incidents?status=open")).text


async def test_incident_from_alert_and_link_event(client, make_user, owner_engine, env):
    cid, gw = env
    only(owner_engine, "device_offline")
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO device_state (client_id, device_id, state, started_at) VALUES (:c, :d, 'down', now() - interval '10 minutes')"),
                  {"c": cid, "d": gw})
        eid = _add(c, cid, gw, category="system", message="kernel: link down eth8")
    await AlertEngine(deliver_fn=Outbox()).evaluate(datetime.now(UTC))
    token = await _staff(client, make_user)
    with owner_engine.connect() as c:
        aid = c.execute(text("SELECT id FROM alerts")).scalar()
        ets = c.execute(text("SELECT ts FROM events WHERE id = :e"), {"e": eid}).scalar()
    r = await client.post(f"/incidents/from-alert/{aid}", data={"csrf_token": token})
    iid = r.headers["location"].rsplit("/", 1)[1]
    again = await client.post(f"/incidents/from-alert/{aid}", data={"csrf_token": token})
    assert again.headers["location"] == f"/incidents/{iid}"  # one incident per alert
    drawer = (await client.get(f"/logs/event/{eid}")).text
    assert "Add to incident" in drawer
    await client.post("/incidents/link-event", data={"incident_id": iid, "event_id": str(eid), "event_ts": ets.isoformat(), "csrf_token": token})
    page = (await client.get(f"/incidents/{iid}")).text
    assert "NW-HK is offline" in page and "kernel: link down eth8" in page and "Linked alert #" in page
    assert f"Incident #{iid}" in (await client.get("/event-monitor")).text


async def test_auto_incident_rule(owner_engine, env):
    cid, gw = env
    only(owner_engine, "device_offline")
    with owner_engine.begin() as c:
        c.execute(text("UPDATE alert_rules SET auto_incident = true WHERE rule_type = 'device_offline'"))
        c.execute(text("INSERT INTO device_state (client_id, device_id, state, started_at) VALUES (:c, :d, 'down', now() - interval '10 minutes')"),
                  {"c": cid, "d": gw})
    eng = AlertEngine(deliver_fn=Outbox())
    await eng.evaluate(datetime.now(UTC))
    await eng.evaluate(datetime.now(UTC))   # still down: no second incident
    with owner_engine.connect() as c:
        rows = c.execute(text("SELECT i.title, i.created_by, count(ia.alert_id) FROM incidents i JOIN incident_alerts ia ON ia.incident_id = i.id GROUP BY 1, 2")).all()
    assert rows == [("NW-HK is offline", "event-monitor", 1)]


async def test_scoping_and_cross_client_linking(client, make_user, owner_engine, env):
    cid, gw = env
    with owner_engine.begin() as c:
        other = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Other','other') RETURNING id")).scalar()
        od = c.execute(text("INSERT INTO devices (client_id, name, vendor) VALUES (:c,'og','unifi') RETURNING id"), {"c": other}).scalar()
        oe = _add(c, other, od, message="other client's event")
        ots = c.execute(text("SELECT ts FROM events WHERE id = :e"), {"e": oe}).scalar()
    token = await _staff(client, make_user)
    r = await client.post("/incidents", data={"client_id": str(cid), "title": "t", "severity": "low", "csrf_token": token})
    iid = r.headers["location"].rsplit("/", 1)[1]
    bad = await client.post("/incidents/link-event", data={"incident_id": iid, "event_id": str(oe), "event_ts": ots.isoformat(), "csrf_token": token})
    assert bad.status_code == 400
    await full_login(client, make_user(role="client_readonly", username="viewer"))
    assert (await client.get("/incidents")).status_code == 403
