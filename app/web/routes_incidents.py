"""Incidents (FortiAnalyzer Incidents & Events): case management over alerts and events. Staff only."""

from datetime import datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import text

from app.audit import audit
from app.incidents import STATUSES, add_timeline, create_incident, link_alert
from app.models.auth import ROLE_ADMIN, ROLE_ENGINEER
from app.web.deps import Ctx, check_csrf, require_role

router = APIRouter()
staff = require_role(ROLE_ADMIN, ROLE_ENGINEER)
SEVERITIES = ("low", "medium", "high", "critical")


async def _incident(ctx: Ctx, iid: int):
    row = (await ctx.db.execute(text("""
        SELECT i.*, c.name AS client, c.timezone, u.username AS assignee
        FROM incidents i JOIN clients c ON c.id = i.client_id LEFT JOIN users u ON u.id = i.assignee_id
        WHERE i.id = :i AND i.client_id = ANY(:ids)"""), {"i": iid, "ids": ctx.scope_ids})).first()
    if row is None:
        raise HTTPException(404, "No such incident.")
    return row


@router.get("/incidents")
async def incidents(ctx: Ctx = Depends(staff), status: str = "open"):
    where = {"open": "i.status IN ('new', 'investigating')", "closed": "i.status IN ('resolved', 'closed')"}.get(status, "TRUE")
    rows = (await ctx.db.execute(text(f"""
        SELECT i.*, c.name AS client, c.timezone, u.username AS assignee,
               (SELECT count(*) FROM incident_alerts a WHERE a.incident_id = i.id) AS alerts,
               (SELECT count(*) FROM incident_events e WHERE e.incident_id = i.id) AS events
        FROM incidents i JOIN clients c ON c.id = i.client_id LEFT JOIN users u ON u.id = i.assignee_id
        WHERE i.client_id = ANY(:ids) AND {where}
        ORDER BY CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, i.updated_at DESC
        LIMIT 500"""), {"ids": ctx.scope_ids})).all()
    return ctx.render("incidents.html", rows=rows, status=status, severities=SEVERITIES)


@router.post("/incidents")
async def create(request: Request, client_id: int = Form(0), title: str = Form(""), severity: str = Form("medium"),
                 description: str = Form(""), ctx: Ctx = Depends(staff)):
    await check_csrf(request, ctx.session.csrf_token)
    if not any(c.id == client_id for c in ctx.clients):
        raise HTTPException(403, "You cannot use that client.")
    if not title.strip() or severity not in SEVERITIES:
        raise HTTPException(400, "Give the incident a title and a valid severity.")
    iid = await create_incident(ctx.db, client_id, title.strip(), severity, ctx.user.username, description.strip())
    await audit(ctx.db, "incident_create", request=request, user=ctx.user, client_id=client_id, target=str(iid))
    await ctx.db.commit()
    return RedirectResponse(f"/incidents/{iid}", status_code=303)


@router.post("/incidents/from-alert/{alert_id}")
async def from_alert(alert_id: int, request: Request, ctx: Ctx = Depends(staff)):
    await check_csrf(request, ctx.session.csrf_token)
    a = (await ctx.db.execute(text("SELECT * FROM alerts WHERE id = :a AND client_id = ANY(:ids)"),
                              {"a": alert_id, "ids": ctx.scope_ids})).first()
    if a is None:
        raise HTTPException(404, "No such alert.")
    existing = (await ctx.db.execute(text("SELECT incident_id FROM incident_alerts WHERE alert_id = :a LIMIT 1"), {"a": alert_id})).scalar()
    if existing:
        return RedirectResponse(f"/incidents/{existing}", status_code=303)
    iid = await create_incident(ctx.db, a.client_id, a.title, a.severity, ctx.user.username, a.message, alert_id)
    await audit(ctx.db, "incident_create", request=request, user=ctx.user, client_id=a.client_id, target=str(iid),
                details={"from_alert": alert_id})
    await ctx.db.commit()
    return RedirectResponse(f"/incidents/{iid}", status_code=303)


@router.get("/incidents/{iid}")
async def incident(iid: int, ctx: Ctx = Depends(staff)):
    inc = await _incident(ctx, iid)
    alerts = (await ctx.db.execute(text("""
        SELECT a.* FROM alerts a JOIN incident_alerts ia ON ia.alert_id = a.id WHERE ia.incident_id = :i ORDER BY a.first_seen"""),
        {"i": iid})).all()
    events = (await ctx.db.execute(text("""
        SELECT e.id, e.ts, e.category, e.severity, e.action, host(e.src_ip) AS src_ip, host(e.dst_ip) AS dst_ip, e.message, d.name AS device
        FROM incident_events ie JOIN events e ON e.id = ie.event_id AND e.ts = ie.event_ts JOIN devices d ON d.id = e.device_id
        WHERE ie.incident_id = :i ORDER BY e.ts"""), {"i": iid})).all()
    timeline = (await ctx.db.execute(text("SELECT * FROM incident_timeline WHERE incident_id = :i ORDER BY ts, id"), {"i": iid})).all()
    users = (await ctx.db.execute(text("""SELECT u.id, u.username FROM users u JOIN roles r ON r.id = u.role_id
                                          WHERE u.is_active AND r.name IN ('admin', 'engineer') ORDER BY u.username"""))).all()
    return ctx.render("incident.html", inc=inc, alerts=alerts, events=events, timeline=timeline, users=users,
                      statuses=STATUSES, severities=SEVERITIES)


@router.post("/incidents/{iid}/update")
async def update(iid: int, request: Request, status: str = Form(""), severity: str = Form(""), assignee_id: str = Form(""),
                 ctx: Ctx = Depends(staff)):
    await check_csrf(request, ctx.session.csrf_token)
    inc = await _incident(ctx, iid)
    who = ctx.user.username
    changes = {}
    if status and status != inc.status:
        if status not in STATUSES:
            raise HTTPException(400, "Invalid status.")
        await ctx.db.execute(text("UPDATE incidents SET status = CAST(:s AS varchar), closed_at = CASE WHEN CAST(:s AS varchar) IN ('resolved', 'closed') THEN now() ELSE NULL END WHERE id = :i"),
                             {"s": status, "i": iid})
        await add_timeline(ctx.db, iid, who, "status", f"Status {inc.status} → {status}")
        changes["status"] = status
    if severity and severity != inc.severity:
        if severity not in SEVERITIES:
            raise HTTPException(400, "Invalid severity.")
        await ctx.db.execute(text("UPDATE incidents SET severity = :s WHERE id = :i"), {"s": severity, "i": iid})
        await add_timeline(ctx.db, iid, who, "severity", f"Severity {inc.severity} → {severity}")
        changes["severity"] = severity
    new_assignee = (int(assignee_id) or None) if assignee_id.isdigit() else None
    if assignee_id != "" and new_assignee != inc.assignee_id:
        name = (await ctx.db.execute(text("""SELECT u.username FROM users u JOIN roles r ON r.id = u.role_id
                                             WHERE u.id = :u AND u.is_active AND r.name IN ('admin', 'engineer')"""),
                                     {"u": new_assignee})).scalar() if new_assignee else None
        if new_assignee and name is None:
            raise HTTPException(400, "Assignee must be an active admin or engineer.")
        await ctx.db.execute(text("UPDATE incidents SET assignee_id = :u WHERE id = :i"), {"u": new_assignee, "i": iid})
        await add_timeline(ctx.db, iid, who, "assign", f"Assigned to {name}" if name else "Unassigned")
        changes["assignee"] = name
    if changes:
        await audit(ctx.db, "incident_update", request=request, user=ctx.user, client_id=inc.client_id, target=str(iid), details=changes)
    await ctx.db.commit()
    return RedirectResponse(f"/incidents/{iid}", status_code=303)


@router.post("/incidents/{iid}/note")
async def note(iid: int, request: Request, body: str = Form(""), ctx: Ctx = Depends(staff)):
    await check_csrf(request, ctx.session.csrf_token)
    inc = await _incident(ctx, iid)
    if not body.strip():
        raise HTTPException(400, "The note is empty.")
    await add_timeline(ctx.db, iid, ctx.user.username, "note", body.strip())
    await audit(ctx.db, "incident_note", request=request, user=ctx.user, client_id=inc.client_id, target=str(iid))
    await ctx.db.commit()
    return RedirectResponse(f"/incidents/{iid}", status_code=303)


@router.post("/incidents/link-event")
async def link_event(request: Request, incident_id: int = Form(0), event_id: int = Form(0), event_ts: datetime = Form(...),
                     ctx: Ctx = Depends(staff)):
    await check_csrf(request, ctx.session.csrf_token)
    inc = await _incident(ctx, incident_id)
    ev = (await ctx.db.execute(text("SELECT id, client_id, category, action, message FROM events WHERE id = :e AND ts = :t"),
                               {"e": event_id, "t": event_ts})).first()
    if ev is None or ev.client_id != inc.client_id:
        raise HTTPException(400, "That event does not belong to this incident's client.")
    res = await ctx.db.execute(text("INSERT INTO incident_events (incident_id, event_id, event_ts) VALUES (:i, :e, :t) ON CONFLICT DO NOTHING"),
                               {"i": incident_id, "e": event_id, "t": event_ts})
    if res.rowcount:
        await add_timeline(ctx.db, incident_id, ctx.user.username, "link",
                           f"Linked event #{event_id} ({ev.category}/{ev.action or '-'}): {(ev.message or '')[:200]}")
        await audit(ctx.db, "incident_link_event", request=request, user=ctx.user, client_id=inc.client_id,
                    target=str(incident_id), details={"event_id": event_id})
    await ctx.db.commit()
    return RedirectResponse(f"/incidents/{incident_id}", status_code=303)


@router.post("/incidents/{iid}/link-alert")
async def link_alert_route(iid: int, request: Request, alert_id: int = Form(0), ctx: Ctx = Depends(staff)):
    await check_csrf(request, ctx.session.csrf_token)
    inc = await _incident(ctx, iid)
    a = (await ctx.db.execute(text("SELECT client_id FROM alerts WHERE id = :a"), {"a": alert_id})).scalar()
    if a != inc.client_id:
        raise HTTPException(400, "That alert does not belong to this incident's client.")
    await link_alert(ctx.db, iid, alert_id, ctx.user.username)
    await ctx.db.commit()
    return RedirectResponse(f"/incidents/{iid}", status_code=303)
