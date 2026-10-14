"""Event Monitor: alerts (ack/resolve), alert rules (event handlers), notification channels. Staff only;
channels are admin only because they hold webhook URLs and addresses."""

import json
import re
from urllib.parse import quote, urlparse

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import text

from app.alerts.engine import deliver
from app.audit import audit
from app import mail
from app.config import get_settings
from app.drivers.base import decrypt_secret, encrypt_secret
from app.models.auth import ROLE_ADMIN, ROLE_ENGINEER
from app.web.deps import Ctx, check_csrf, require_role

router = APIRouter()
staff = require_role(ROLE_ADMIN, ROLE_ENGINEER)
admin_only = require_role(ROLE_ADMIN)
EMAIL_RE = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")
# Editable numeric parameters per rule type (label, key, min, max).
PARAMS = {
    "device_offline": [("Down for at least (minutes)", "minutes", 1, 1440)],
    "vpn_tunnel_down": [("Down for at least (minutes)", "minutes", 1, 1440)],
    "vpn_flapping": [("Drops", "drops", 2, 10000), ("Within (minutes)", "window_minutes", 5, 1440)],
    "failed_logins": [("Failures from one source", "count", 2, 100000), ("Within (minutes)", "window_minutes", 1, 1440)],
    "log_source_silent": [("Silent for (minutes)", "minutes", 5, 10080)],
    "event_match": [("At least (events)", "count", 1, 1000000), ("Within (minutes)", "window_minutes", 1, 1440)],
    "storage_quota": [("Warn at (% of quota)", "warn_pct", 10, 100)],
    "wan_down": [("Down for at least (minutes)", "minutes", 1, 1440)],
    "internet_down": [("Down for at least (minutes)", "minutes", 1, 1440)],
    # Older hits (e.g. from imported history) stay visible in Insights/Log View but do not raise new alerts.
    "ioc_match": [("Only hits newer than (hours)", "max_age_hours", 1, 168),
                  ("Inbound from a listed address only if the session moved at least (KB)", "inbound_min_kb", 0, 1000000)],
    # lo = None: a list of numbers (comma-separated in the form)
    "unifi_event": [("UniFi event IDs (comma-separated; e.g. 524 tunnel disconnected, 105 internet failover, 113 packet loss, 200 threat)",
                     "event_ids", None, None)],
    "vpn_disconnect": [("Alert when down for at least (seconds)", "min_seconds", 10, 3600)],
    "ap_offline": [("Offline for at least (minutes)", "minutes", 1, 1440),
                   ("Ignore APs offline longer than (days, removed hardware)", "ignore_after_days", 1, 365)],
    "wifi_quality": [("For at least (minutes)", "minutes", 3, 240), ("Channel utilisation at or above (%)", "utilisation_pct", 30, 100),
                     ("Wi-Fi experience below (%)", "experience_pct", 10, 100), ("Weak signal: weaker than (dBm)", "weak_dbm", -95, -50),
                     ("Weak-signal clients on one AP (at least)", "weak_clients", 1, 100)],
    "poe_issue": [("Switch PoE budget used (% at or above)", "budget_pct", 50, 100)],
    "server_health": [("No logs / parser idle for (minutes)", "stall_minutes", 5, 120),
                      ("Parser backlog over (lines)", "backlog", 1000, 10000000), ("Data disk over (%)", "disk_pct", 50, 99),
                      ("No successful backup for (hours)", "backup_hours", 2, 168),
                      ("Consoles failing to poll at least (%)", "poll_fail_pct", 10, 100)],
    "isp_degraded": [("Packet loss at least (%)", "loss_pct", 1, 100), ("or latency at least (ms)", "latency_ms", 10, 5000),
                     ("for (5-minute periods)", "periods", 1, 24)],
}
TYPE_LABELS = {"device_offline": "Device offline", "vpn_tunnel_down": "VPN tunnel down", "vpn_flapping": "VPN tunnel flapping",
               "failed_logins": "Repeated failed logins", "config_change": "Configuration change",
               "wan_failover": "WAN address change", "outdated_firmware": "Outdated firmware",
               "log_source_silent": "Log source silent", "event_match": "Custom event match", "ioc_match": "Threat intel match", "storage_quota": "Storage quota",
               "wan_down": "WAN interface down", "internet_down": "Internet down", "isp_degraded": "Internet degraded",
               "server_health": "Log server health", "unifi_event": "Gateway events (immediate)",
               "vpn_disconnect": "Site-to-site VPN disconnected", "ap_offline": "Access point offline",
               "wifi_quality": "Wi-Fi quality", "poe_issue": "PoE problem"}


@router.get("/event-monitor")
async def event_monitor(ctx: Ctx = Depends(staff), status: str = "active", tab: str = "alerts", open: int = 0):
    where = {"active": "a.status <> 'resolved'", "resolved": "a.status = 'resolved'", "all": "TRUE"}.get(status, "a.status <> 'resolved'")
    alerts = (await ctx.db.execute(text(f"""
        SELECT a.*, c.name AS client, c.timezone, r.name AS rule_name, d.name AS device,
               (SELECT min(ia.incident_id) FROM incident_alerts ia WHERE ia.alert_id = a.id) AS incident_id,
               (SELECT string_agg(DISTINCT n.status, ', ') FROM notifications n WHERE n.alert_id = a.id) AS delivery
        FROM alerts a JOIN clients c ON c.id = a.client_id JOIN alert_rules r ON r.id = a.rule_id
        LEFT JOIN devices d ON d.id = a.device_id
        WHERE a.client_id = ANY(:ids) AND {where}
        ORDER BY CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                 a.last_seen DESC LIMIT 500"""), {"ids": ctx.scope_ids})).all()
    rules = (await ctx.db.execute(text("""
        SELECT r.*, coalesce(c.name, g.name || ' (company)') AS client FROM alert_rules r
        LEFT JOIN clients c ON c.id = r.client_id LEFT JOIN companies g ON g.id = r.company_id
        WHERE r.client_id IS NULL OR r.client_id = ANY(:ids)
        ORDER BY regexp_replace(r.name, ' [(].*[)]$', ''), r.client_id NULLS FIRST, r.id"""), {"ids": ctx.scope_ids})).all()
    channels = (await ctx.db.execute(text("""
        SELECT ch.id, ch.name, ch.type, ch.enabled, ch.client_id, coalesce(c.name, g.name || ' (company)') AS client, ch.company_id,
               (SELECT string_agg(r.name, ', ' ORDER BY r.id) FROM alert_rules r WHERE ch.id = ANY(r.channel_ids)) AS rules,
               ch.config_enc
        FROM notification_channels ch
        LEFT JOIN clients c ON c.id = ch.client_id LEFT JOIN companies g ON g.id = ch.company_id
        WHERE ch.owner_rule_id IS NULL AND (ch.client_id IS NULL OR ch.client_id = ANY(:ids)) ORDER BY ch.name"""),
        {"ids": [c.id for c in ctx.clients]})).all()   # every channel the user may see, whatever client is picked on top
    channels = [{**dict(c._mapping), "target": _target(c.config_enc), **_recipients(c.config_enc)} for c in channels]
    owned = (await ctx.db.execute(text(
        "SELECT owner_rule_id, config_enc FROM notification_channels WHERE owner_rule_id IS NOT NULL"))).all()
    rule_emails = {o.owner_rule_id: (decrypt_secret(o.config_enc) or {}).get("to", []) for o in owned}
    return ctx.render("event_monitor.html", alerts=alerts, rules=rules, channels=channels, status=status, tab=tab,
                      params=PARAMS, type_labels=TYPE_LABELS, is_admin=ctx.role == ROLE_ADMIN,
                      smtp=bool((await mail.effective(get_settings(), ctx.db)).smtp_host), rule_emails=rule_emails, open_rule=open,
                      clients=ctx.clients, test=None)


def _recipients(enc: str) -> dict:
    """To / CC of an e-mail channel, for its edit form (webhook URLs are never sent back to the browser)."""
    cfg = decrypt_secret(enc) or {}
    return {"to_list": ", ".join(cfg.get("to") or []), "cc_list": ", ".join(cfg.get("cc") or [])}


def _target(enc: str) -> str:
    """Show where a channel delivers without exposing webhook secrets (addresses are shown; URLs only by host)."""
    cfg = decrypt_secret(enc) or {}
    if "to" in cfg:
        return ", ".join(cfg["to"]) + (f" · cc: {', '.join(cfg['cc'])}" if cfg.get("cc") else "")
    u = urlparse(cfg.get("url", ""))
    return f"{u.scheme}://{u.netloc}/…" if u.netloc else ""


@router.get("/event-monitor/alerts/{alert_id}")
async def alert_page(alert_id: int, ctx: Ctx = Depends(staff)):
    a = (await ctx.db.execute(text("""
        SELECT a.*, c.name AS client, c.timezone, r.name AS rule_name, d.name AS device,
               (SELECT min(ia.incident_id) FROM incident_alerts ia WHERE ia.alert_id = a.id) AS incident_id
        FROM alerts a JOIN clients c ON c.id = a.client_id JOIN alert_rules r ON r.id = a.rule_id
        LEFT JOIN devices d ON d.id = a.device_id WHERE a.id = :i AND a.client_id = ANY(:ids)"""),
        {"i": alert_id, "ids": ctx.scope_ids})).first()
    if a is None:
        raise HTTPException(404, "No such alert in your scope.")
    notifications = (await ctx.db.execute(text("""
        SELECT n.sent_at, n.kind, n.status, ch.name AS channel FROM notifications n
        LEFT JOIN notification_channels ch ON ch.id = n.channel_id WHERE n.alert_id = :i ORDER BY n.sent_at DESC"""),
        {"i": alert_id})).all()
    comments = (await ctx.db.execute(text("SELECT ts, username, body FROM alert_comments WHERE alert_id = :i ORDER BY ts"),
                                     {"i": alert_id})).all()
    # Related events: the alert's device (if any) from 15 minutes before it was first seen until it was last seen.
    from zoneinfo import ZoneInfo
    from datetime import timedelta
    tz = ZoneInfo(ctx.tz)
    params = {"range": "custom", "from": (a.first_seen - timedelta(minutes=15)).astimezone(tz).strftime("%Y-%m-%dT%H:%M:%S"),
              "to": (a.last_seen + timedelta(minutes=5)).astimezone(tz).strftime("%Y-%m-%dT%H:%M:%S")}
    if a.device_id:
        params["device"] = str(a.device_id)
    from urllib.parse import urlencode
    return ctx.render("alert.html", a=a, notifications=notifications, comments=comments, related=urlencode(params))


@router.post("/event-monitor/alerts/{alert_id}/comment")
async def alert_comment(alert_id: int, request: Request, body: str = Form(""), ctx: Ctx = Depends(staff)):
    await check_csrf(request, ctx.session.csrf_token)
    body = body.strip()[:4000]
    if not body:
        raise HTTPException(400, "Write a comment first.")
    if (await ctx.db.execute(text("SELECT 1 FROM alerts WHERE id = :i AND client_id = ANY(:ids)"),
                             {"i": alert_id, "ids": ctx.scope_ids})).first() is None:
        raise HTTPException(404, "No such alert in your scope.")
    await ctx.db.execute(text("INSERT INTO alert_comments (alert_id, username, body) VALUES (:a, :u, :b)"),
                         {"a": alert_id, "u": ctx.user.username, "b": body})
    await audit(ctx.db, "alert_comment", request=request, user=ctx.user, target=str(alert_id))
    await ctx.db.commit()
    return RedirectResponse(f"/event-monitor/alerts/{alert_id}", status_code=303)


@router.post("/event-monitor/alerts/{alert_id}/{action}")
async def alert_action(alert_id: int, action: str, request: Request, ctx: Ctx = Depends(staff)):
    await check_csrf(request, ctx.session.csrf_token)
    nxt = str((await request.form()).get("next") or "")
    sets = {"ack": "status = 'acknowledged', acknowledged_by = :u, acknowledged_at = now()",
            "resolve": "status = 'resolved', resolved_at = now()"}.get(action)
    if sets is None:
        raise HTTPException(404, "Unknown action.")
    res = await ctx.db.execute(text(f"UPDATE alerts SET {sets} WHERE id = :i AND client_id = ANY(:ids) AND status <> 'resolved'"),
                               {"i": alert_id, "ids": ctx.scope_ids, "u": ctx.user.username})
    if res.rowcount == 0:
        raise HTTPException(404, "No such open alert.")
    await audit(ctx.db, f"alert_{action}", request=request, user=ctx.user, target=str(alert_id))
    await ctx.db.commit()
    back = nxt if nxt == f"/event-monitor/alerts/{alert_id}" else "/event-monitor"
    return RedirectResponse(back, status_code=303)


def _emails(raw: str) -> list[str]:
    to = list(dict.fromkeys(x.strip().lower() for x in re.split(r"[,\s;]+", raw or "") if x.strip()))
    bad = [x for x in to if not EMAIL_RE.match(x)]
    if bad:
        raise HTTPException(400, f"Not a valid e-mail address: {', '.join(bad)}")
    if len(to) > 50:
        raise HTTPException(400, "At most 50 e-mail addresses per rule.")
    return to


async def _rule(ctx: Ctx, rule_id: int):
    rule = (await ctx.db.execute(text("SELECT * FROM alert_rules WHERE id = :i AND (client_id IS NULL OR client_id = ANY(:ids))"),
                                 {"i": rule_id, "ids": ctx.scope_ids})).first()
    if rule is None:
        raise HTTPException(404, "No such rule.")
    return rule


def _target_choice(ctx: Ctx, raw: str) -> tuple[int | None, int | None]:
    """'' = all clients, '<id>' = one client, 'g<id>' = a company (all its sites) -> (client_id, company_id)."""
    if raw.startswith("g"):
        if not any(f"g{g.id}" == raw for g in ctx.companies):
            raise HTTPException(403, "You cannot use that company.")
        return None, int(raw[1:])
    return _client_choice(ctx, raw), None


def _client_choice(ctx: Ctx, raw: str) -> int | None:
    """'' = all clients; otherwise one of the clients this user may use."""
    if not raw:
        return None
    if not raw.isdigit() or not any(c.id == int(raw) for c in ctx.clients):
        raise HTTPException(403, "You cannot use that client.")
    return int(raw)


async def _set_rule_emails(ctx: Ctx, rule_id: int, name: str, to: list[str]) -> None:
    """The rule's own e-mail channel: created, updated or removed to match the address list."""
    if to:
        await ctx.db.execute(text("""
            INSERT INTO notification_channels (client_id, name, type, config_enc, owner_rule_id)
            VALUES (NULL, :n, 'email', :cfg, :r)
            ON CONFLICT (owner_rule_id) WHERE owner_rule_id IS NOT NULL
            DO UPDATE SET config_enc = EXCLUDED.config_enc, name = EXCLUDED.name, enabled = true"""),
            {"n": f"Rule e-mail: {name}"[:100], "cfg": encrypt_secret({"to": to}), "r": rule_id})
    else:
        await ctx.db.execute(text("DELETE FROM notification_channels WHERE owner_rule_id = :r"), {"r": rule_id})


@router.post("/event-monitor/rules/{rule_id}")
async def update_rule(rule_id: int, request: Request, ctx: Ctx = Depends(staff)):
    await check_csrf(request, ctx.session.csrf_token)
    form = await request.form()
    rule = await _rule(ctx, rule_id)
    params = dict(rule.params)
    for label, key, lo, hi in PARAMS.get(rule.rule_type, []):
        if key in form and lo is None:
            raw = [x.strip() for x in str(form[key]).replace(";", ",").split(",") if x.strip()]
            if not all(x.isdigit() and 1 <= int(x) <= 9999 for x in raw):
                raise HTTPException(400, f"{label}: numbers only, separated by commas.")
            params[key] = sorted({int(x) for x in raw})
        elif key in form:
            try:
                v = int(form[key])
            except ValueError:
                raise HTTPException(400, f"{label} must be a number.")
            if not lo <= v <= hi:
                raise HTTPException(400, f"{label} must be between {lo} and {hi}.")
            params[key] = v
    sev = form.get("severity", rule.severity)
    if sev not in ("low", "medium", "high", "critical"):
        raise HTTPException(400, "Invalid severity.")
    try:
        throttle = int(form.get("throttle_minutes", rule.throttle_minutes))
    except ValueError:
        raise HTTPException(400, "Throttle must be a number.")
    current = f"g{rule.company_id}" if rule.company_id else str(rule.client_id or "")
    client_id, company_id = _target_choice(ctx, str(form.get("client_id", current)))
    to = _emails(str(form.get("email_to", "")))
    ch_ids = [int(x) for x in form.getlist("channel_ids") if str(x).isdigit()]
    enabled = form.get("enabled") == "on"
    await ctx.db.execute(text("""UPDATE alert_rules SET params = CAST(:p AS jsonb), severity = :s, enabled = :e,
                                 throttle_minutes = :t, notify_resolve = :nr, auto_incident = :ai, channel_ids = :ch,
                                 client_id = :c, company_id = :g WHERE id = :i"""),
                         {"p": json.dumps(params), "s": sev, "e": enabled, "t": max(0, throttle),
                          "nr": form.get("notify_resolve") == "on", "ai": form.get("auto_incident") == "on",
                          "ch": ch_ids, "c": client_id, "g": company_id, "i": rule_id})
    await _set_rule_emails(ctx, rule_id, rule.name, to)
    await audit(ctx.db, "alert_rule_update", request=request, user=ctx.user, target=rule.name,
                details={"params": params, "severity": sev, "enabled": enabled, "channels": ch_ids,
                         "client_id": client_id, "company_id": company_id, "email_to": to})
    await ctx.db.commit()
    return RedirectResponse(f"/event-monitor?tab=rules&open={rule_id}#rule-{rule_id}", status_code=303)


@router.post("/event-monitor/rules/{rule_id}/copy")
async def copy_rule(rule_id: int, request: Request, client_id: str = Form(""), ctx: Ctx = Depends(staff)):
    """A copy of the rule for one client (e.g. the same "Device offline" rule, with that client's own recipients)."""
    await check_csrf(request, ctx.session.csrf_token)
    rule = await _rule(ctx, rule_id)
    cid, gid = _target_choice(ctx, client_id)
    client = next((c.name for c in ctx.clients if c.id == cid), None) or next((g.name for g in ctx.companies if g.id == gid), "all clients")
    new_id = (await ctx.db.execute(text("""
        INSERT INTO alert_rules (client_id, company_id, name, rule_type, params, severity, enabled, throttle_minutes, notify_resolve,
                                 auto_incident, channel_ids)
        VALUES (:c, :g, :n, :t, CAST(:p AS jsonb), :s, false, :th, :nr, :ai, '{}') RETURNING id"""),
        {"c": cid, "g": gid, "n": f"{rule.name} ({client})"[:200], "t": rule.rule_type, "p": json.dumps(dict(rule.params)),
         "s": rule.severity, "th": rule.throttle_minutes, "nr": rule.notify_resolve, "ai": rule.auto_incident})).scalar()
    await audit(ctx.db, "alert_rule_copy", request=request, user=ctx.user, target=rule.name,
                details={"from": rule_id, "new": new_id, "client_id": cid, "company_id": gid})
    await ctx.db.commit()
    return RedirectResponse(f"/event-monitor?tab=rules&open={new_id}#rule-{new_id}", status_code=303)


@router.post("/event-monitor/rules/{rule_id}/delete")
async def delete_rule(rule_id: int, request: Request, ctx: Ctx = Depends(staff)):
    await check_csrf(request, ctx.session.csrf_token)
    rule = await _rule(ctx, rule_id)
    if rule.client_id is None and rule.company_id is None:
        raise HTTPException(400, "Built-in rules for all clients cannot be deleted; switch them off instead.")
    await ctx.db.execute(text("DELETE FROM alert_rules WHERE id = :i"), {"i": rule_id})
    await audit(ctx.db, "alert_rule_delete", request=request, user=ctx.user, target=rule.name)
    await ctx.db.commit()
    return RedirectResponse("/event-monitor?tab=rules", status_code=303)


@router.post("/event-monitor/rules/{rule_id}/test")
async def test_rule_email(rule_id: int, request: Request, ctx: Ctx = Depends(staff)):
    """Send a test message to the rule's e-mail recipients (as saved)."""
    await check_csrf(request, ctx.session.csrf_token)
    rule = await _rule(ctx, rule_id)
    ch = (await ctx.db.execute(text("SELECT * FROM notification_channels WHERE owner_rule_id = :r"), {"r": rule_id})).first()
    if ch is None:
        msg = "no e-mail addresses saved for this rule yet"
    else:
        from datetime import UTC, datetime
        fake = {"id": 0, "title": f"Test: {rule.name}", "severity": rule.severity, "client": "Test",
                "message": f"This is a test of the Event Monitor rule “{rule.name}”.", "first_seen": datetime.now(UTC)}
        try:
            msg = await deliver(dict(ch._mapping), fake, "open", get_settings())
        except Exception as e:  # noqa: BLE001
            msg = f"failed: {type(e).__name__}: {e}"
    await audit(ctx.db, "alert_rule_test", request=request, user=ctx.user, target=rule.name, details={"result": msg})
    await ctx.db.commit()
    return RedirectResponse(f"/event-monitor?tab=rules&open={rule_id}&test={quote(msg[:120])}#rule-{rule_id}",
                            status_code=303)


@router.post("/event-monitor/channels")
async def create_channel(request: Request, name: str = Form(""), type: str = Form("email"), target: str = Form(""),
                         cc: str = Form(""), client_id: str = Form(""), all_rules: str = Form(""),
                         ctx: Ctx = Depends(admin_only)):
    await check_csrf(request, ctx.session.csrf_token)
    if not name.strip():
        raise HTTPException(400, "Name the channel.")
    if type == "email":
        to = [x.strip() for x in re.split(r"[,\s;]+", target) if x.strip()]
        copy = [x.strip() for x in re.split(r"[,\s;]+", cc) if x.strip()]
        if not to or any(not EMAIL_RE.match(x) for x in to + copy):
            raise HTTPException(400, "Give one or more valid e-mail addresses.")
        cfg = {"to": to, **({"cc": copy} if copy else {})}
    elif type in ("teams", "slack", "webhook"):
        u = urlparse(target.strip())
        if u.scheme != "https" or not u.netloc:
            raise HTTPException(400, "The webhook URL must be https://…")
        cfg = {"url": target.strip()}
    else:
        raise HTTPException(400, "Unknown channel type.")
    cid, gid = _target_choice(ctx, client_id)
    ch_id = (await ctx.db.execute(text("INSERT INTO notification_channels (client_id, company_id, name, type, config_enc) "
                                       "VALUES (:c, :g, :n, :t, :cfg) RETURNING id"),
                                  {"c": cid, "g": gid, "n": name.strip()[:100], "t": type, "cfg": encrypt_secret(cfg)})).scalar()
    attached = 0
    if all_rules:
        # Every global rule, plus that client's own rules. The engine still delivers a client channel only the
        # alerts of ITS client, so attaching it to global rules is safe.
        attached = (await ctx.db.execute(text("""
            UPDATE alert_rules SET channel_ids = array(SELECT DISTINCT unnest(channel_ids || ARRAY[:ch]))
            WHERE client_id IS NULL OR client_id = :c"""), {"ch": ch_id, "c": cid})).rowcount
    await audit(ctx.db, "channel_create", request=request, user=ctx.user, target=name,
                details={"type": type, "client_id": cid, "company_id": gid, "attached_rules": attached})
    await ctx.db.commit()
    return RedirectResponse("/event-monitor?tab=channels", status_code=303)


@router.post("/event-monitor/channels/{channel_id}/edit")
async def edit_channel(channel_id: int, request: Request, name: str = Form(""), target: str = Form(""), cc: str = Form(""),
                       ctx: Ctx = Depends(admin_only)):
    """Rename a channel and change its recipients (e-mail: To and CC) or its webhook URL (empty = keep the current one)."""
    await check_csrf(request, ctx.session.csrf_token)
    ch = (await ctx.db.execute(text("SELECT * FROM notification_channels WHERE id = :i AND owner_rule_id IS NULL"),
                               {"i": channel_id})).first()
    if ch is None:
        raise HTTPException(404, "No such channel.")
    if not name.strip():
        raise HTTPException(400, "Name the channel.")
    old = decrypt_secret(ch.config_enc) or {}
    if ch.type == "email":
        to = [x.strip() for x in re.split(r"[,\s;]+", target) if x.strip()]
        copy = [x.strip() for x in re.split(r"[,\s;]+", cc) if x.strip()]
        if not to or any(not EMAIL_RE.match(x) for x in to + copy):
            raise HTTPException(400, "Give one or more valid e-mail addresses.")
        cfg = {"to": to, **({"cc": copy} if copy else {})}
        details = {"to": to, "cc": copy, "before": {"to": old.get("to", []), "cc": old.get("cc", [])}}
    else:
        if target.strip():
            u = urlparse(target.strip())
            if u.scheme != "https" or not u.netloc:
                raise HTTPException(400, "The webhook URL must be https://…")
            cfg = {"url": target.strip()}
        else:
            cfg = old
        details = {"url_changed": bool(target.strip())}
    await ctx.db.execute(text("UPDATE notification_channels SET name = :n, config_enc = :c WHERE id = :i"),
                         {"n": name.strip()[:100], "c": encrypt_secret(cfg), "i": channel_id})
    await audit(ctx.db, "channel_edit", request=request, user=ctx.user, target=name.strip()[:100], details=details)
    await ctx.db.commit()
    return RedirectResponse("/event-monitor?tab=channels", status_code=303)


@router.post("/event-monitor/channels/{channel_id}/{action}")
async def channel_action(channel_id: int, action: str, request: Request, ctx: Ctx = Depends(admin_only)):
    await check_csrf(request, ctx.session.csrf_token)
    ch = (await ctx.db.execute(text("SELECT * FROM notification_channels WHERE id = :i"), {"i": channel_id})).first()
    if ch is None:
        raise HTTPException(404, "No such channel.")
    if action == "delete":
        await ctx.db.execute(text("DELETE FROM notification_channels WHERE id = :i"), {"i": channel_id})
        msg = None
    elif action == "toggle":
        await ctx.db.execute(text("UPDATE notification_channels SET enabled = NOT enabled WHERE id = :i"), {"i": channel_id})
        msg = None
    elif action == "test":
        from datetime import UTC, datetime
        fake = {"id": 0, "title": "Test notification", "message": "This is a test from the Uniwatch Event Monitor.",
                "severity": "low", "client": "Test", "first_seen": datetime.now(UTC)}
        try:
            msg = await deliver(dict(ch._mapping), fake, "open", get_settings())
        except Exception as e:  # noqa: BLE001
            msg = f"failed: {type(e).__name__}: {e}"
    else:
        raise HTTPException(404, "Unknown action.")
    await audit(ctx.db, f"channel_{action}", request=request, user=ctx.user, target=ch.name, details={"result": msg} if msg else None)
    await ctx.db.commit()
    return RedirectResponse("/event-monitor?tab=channels" + (f"&test={msg[:80]}" if msg else ""), status_code=303)

