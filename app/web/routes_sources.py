"""Clients, devices (log sources), unknown senders, and a raw-line viewer for verifying ingest."""

import ipaddress
import re
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, func, select, text

from app import packs
from app.audit import audit
from app.models import Client, Device, RawLog, UnknownSource
from app.models.auth import ROLE_ADMIN, ROLE_ENGINEER
from app.models.sources import VENDORS
from app.web.deps import Ctx, check_csrf, require_role

router = APIRouter()
staff = require_role(ROLE_ADMIN, ROLE_ENGINEER)
admin_only = require_role(ROLE_ADMIN)
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}$")
TIMEZONES = sorted(available_timezones())


# ------------------------------------------------------------------ clients (admin)
async def _clients_page(ctx: Ctx, status_code: int = 200, **kw):
    rows = (await ctx.db.execute(
        select(Client, func.count(Device.id)).outerjoin(Device, Device.client_id == Client.id)
        .group_by(Client.id).order_by(Client.name)
    )).all()
    kw.setdefault("form", {})
    companies = (await ctx.db.execute(text("""
        SELECT g.id, g.name, count(c.id) AS sites,
               (SELECT count(*) FROM alert_rules r WHERE r.company_id = g.id) AS rules,
               (SELECT count(*) FROM notification_channels n WHERE n.company_id = g.id) AS channels
        FROM companies g LEFT JOIN clients c ON c.company_id = g.id GROUP BY g.id ORDER BY g.name"""))).all()
    return ctx.render("admin_clients.html", status_code, rows=rows, timezones=TIMEZONES, companies=companies,
                      suggestions=_company_suggestions([c for c, _ in rows]), **kw)


def _company_suggestions(clients) -> list[tuple[str, list[str]]]:
    """Clients not in a company whose names start alike (CTS KL, CTS SG ... -> "CTS")."""
    groups: dict[str, list[str]] = {}
    for c in clients:
        if c.company_id:
            continue
        key = re.split(r"[\s_-]+", c.name.strip())[0].upper()
        if len(key) >= 3:
            groups.setdefault(key, []).append(c.name)
    return sorted((k, v) for k, v in groups.items() if len(v) > 1)


@router.post("/admin/clients/{client_id}/company")
async def set_client_company(client_id: int, request: Request, company_id: str = Form(""), new_company: str = Form(""),
                             ctx: Ctx = Depends(admin_only)):
    """Put a client site in a company (an existing one, or a new one by name), or take it out ('')."""
    await check_csrf(request, ctx.session.csrf_token)
    new_company = " ".join(new_company.split())[:100]
    if new_company:
        gid = (await ctx.db.execute(text("""INSERT INTO companies (name) VALUES (:n)
                                            ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id"""),
                                    {"n": new_company})).scalar()
    elif company_id.isdigit():
        gid = (await ctx.db.execute(text("SELECT id FROM companies WHERE id = :i"), {"i": int(company_id)})).scalar()
        if gid is None:
            raise HTTPException(404, "No such company.")
    else:
        gid = None
    res = await ctx.db.execute(text("UPDATE clients SET company_id = :g WHERE id = :c"), {"g": gid, "c": client_id})
    if res.rowcount == 0:
        raise HTTPException(404, "No such client.")
    await audit(ctx.db, "client_company_set", request=request, user=ctx.user, client_id=client_id,
                details={"company_id": gid, "new_company": new_company or None})
    await ctx.db.commit()
    return RedirectResponse("/admin/clients", status_code=303)


@router.post("/admin/companies/{company_id}/delete")
async def delete_company(company_id: int, request: Request, ctx: Ctx = Depends(admin_only)):
    """Delete a company: its sites stay (no longer grouped); its own rules and channels are deleted."""
    await check_csrf(request, ctx.session.csrf_token)
    name = (await ctx.db.execute(text("DELETE FROM companies WHERE id = :i RETURNING name"), {"i": company_id})).scalar()
    if name is None:
        raise HTTPException(404, "No such company.")
    await audit(ctx.db, "company_delete", request=request, user=ctx.user, target=name)
    await ctx.db.commit()
    return RedirectResponse("/admin/clients", status_code=303)


@router.get("/admin/clients")
async def clients(ctx: Ctx = Depends(admin_only)):
    return await _clients_page(ctx)


@router.post("/admin/clients")
async def create_client(
    request: Request,
    name: str = Form(""),
    slug: str = Form(""),
    timezone: str = Form("Asia/Hong_Kong"),
    retention_days: int = Form(90),
    ctx: Ctx = Depends(admin_only),
):
    await check_csrf(request, ctx.session.csrf_token)
    name, slug, timezone = name.strip(), slug.strip().lower(), timezone.strip()
    errors = []
    if not name:
        errors.append("Name is required.")
    if not SLUG_RE.match(slug):
        errors.append("Slug: 2-31 characters, lowercase letters, digits and hyphens, starting with a letter or digit.")
    elif (await ctx.db.execute(select(Client.id).where(Client.slug == slug))).first():
        errors.append("That slug is already used.")
    try:
        ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError):
        errors.append("Unknown time zone.")
    if not 1 <= retention_days <= 3650:
        errors.append("Retention must be between 1 and 3650 days.")
    if errors:
        return await _clients_page(ctx, 400, errors=errors,
                                   form={"name": name, "slug": slug, "timezone": timezone, "retention_days": retention_days})
    c = Client(name=name[:200], slug=slug, timezone=timezone, retention_days=retention_days)
    ctx.db.add(c)
    await ctx.db.flush()
    await audit(ctx.db, "client_create", request=request, user=ctx.user, target=slug, client_id=c.id,
                details={"name": name, "timezone": timezone, "retention_days": retention_days})
    await ctx.db.commit()
    return RedirectResponse("/admin/clients", status_code=303)


# ------------------------------------------------------------------ devices + unknown senders (staff)
def _norm_ip(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    return str(ipaddress.ip_address(value))


async def _sources_page(ctx: Ctx, status_code: int = 200, **kw):
    db = ctx.db
    devices = (await db.execute(
        select(Device).join(Client, Client.id == Device.client_id).where(Device.client_id.in_(ctx.scope_ids))
        .order_by(Client.name, Device.name)
    )).scalars().all()
    states = {r.device_id: r for r in (await db.execute(text(
        "SELECT device_id, state, started_at, reason FROM device_state WHERE ended_at IS NULL AND client_id = ANY(:ids)"),
        {"ids": ctx.scope_ids})).all()}
    known = {r[0] for r in (await db.execute(text(
        "SELECT host(ip) FROM devices, unnest(array_prepend(syslog_source_ip, alt_source_ips)) AS ip WHERE ip IS NOT NULL"))).all()}
    unknown = [u for u in (await db.execute(
        select(UnknownSource).where(UnknownSource.ignored.is_(False)).order_by(UnknownSource.last_seen.desc())
    )).scalars().all() if str(u.source_ip) not in known]
    cloud = {r.device_id for r in (await db.execute(text(
        "SELECT device_id FROM sitemanager_hosts WHERE device_id IS NOT NULL AND client_id = ANY(:ids)"), {"ids": ctx.scope_ids})).all()}
    return ctx.render("sources.html", status_code, devices=devices, unknown=unknown, states=states, cloud=cloud, **kw)


async def _add_page(ctx: Ctx, status_code: int = 200, **kw):
    q = ctx.request.query_params
    kw.setdefault("form", {"syslog_source_ip": q.get("register", ""), "name": q.get("name", ""),
                           "model": q.get("model", ""), "vendor": q.get("vendor", ""),
                           "client_id": int(q["client"]) if q.get("client", "").isdigit()
                           else (ctx.selected.id if ctx.selected else None)})
    return ctx.render("sources_add.html", status_code, clients=list(ctx.clients), vendors=VENDORS, **kw)


@router.get("/sources")
async def sources(ctx: Ctx = Depends(staff)):
    return await _sources_page(ctx)


@router.get("/sources/add")
async def add_device_page(ctx: Ctx = Depends(staff)):
    return await _add_page(ctx)


# Product lines as UniFi reports them (local API types and Site Manager product names).
PRODUCTS = {"udm": "Gateway", "ugw": "Gateway", "uxg": "Gateway", "usw": "Switch", "uap": "Access point",
            "network": "Network", "protect": "Protect (camera / NVR)", "access": "Access (door)", "talk": "Talk",
            "connect": "Connect"}
NO_SYSLOG = {"protect", "access", "talk", "connect"}   # product lines that send no syslog to register


async def inventory(ctx: Ctx, q: str = "", status: str = "", product: str = "", updates: int = 0, lifecycle: str = ""):
    """Every device known for the clients in scope: what the controllers / Site Manager report (gateways, switches, APs,
    cameras, door readers ...) plus registered log sources that no controller reports. Returns (all rows, filtered rows)."""
    rows = [dict(r._mapping) for r in (await ctx.db.execute(text("""
        SELECT c.name AS client, c.id AS client_id, coalesce(i.name, d.name) AS name, i.type, i.model, host(i.ip) AS ip,
               i.mac::text AS mac, i.firmware, i.upgradable, i.firmware_latest, i.connected, i.seen_at,
               p.name AS via, d.id AS log_device_id, d.last_log_at,
               CASE WHEN i.seen_at > now() - interval '5 minutes' THEN i.cpu_pct END AS cpu,
               CASE WHEN i.seen_at > now() - interval '5 minutes' THEN i.mem_pct END AS mem,
               CASE WHEN i.seen_at > now() - interval '5 minutes' THEN i.uptime_s END AS uptime,
               CASE WHEN i.seen_at > now() - interval '5 minutes' THEN i.client_count END AS clients_now,
               i.extra->>'serial' AS serial, coalesce((i.extra->>'eol')::boolean, false) AS eol,
               coalesce((i.extra->>'lts')::boolean, false) AS lts
        FROM device_inventory i JOIN devices p ON p.id = i.poll_device_id JOIN clients c ON c.id = p.client_id
        LEFT JOIN devices d ON d.id = i.device_id
        WHERE p.client_id = ANY(:ids)
        UNION ALL
        SELECT c.name, c.id, d.name, NULL, nullif(d.model, ''), host(coalesce(d.mgmt_ip, d.syslog_source_ip)), NULL, d.firmware,
               d.upgradable, d.firmware_latest, NULL, d.last_log_at, NULL, d.id, d.last_log_at, NULL, NULL, NULL, NULL,
               NULL, false, false
        FROM devices d JOIN clients c ON c.id = d.client_id
        WHERE d.client_id = ANY(:ids) AND d.is_active AND NOT EXISTS (SELECT 1 FROM device_inventory x WHERE x.device_id = d.id)
        ORDER BY 1, 3"""), {"ids": ctx.scope_ids})).all()]
    now = (await ctx.db.execute(text("SELECT now()"))).scalar()
    # A site is "local" when one of its log sources sends from a private address (same network as this server). At a
    # remote site everything reaches the server from the gateway's public IP, so a device's private IP can't be a
    # log source: its logs (if any) arrive under the gateway.
    gw = {r.client_id: r for r in (await ctx.db.execute(text("""
        SELECT DISTINCT ON (client_id) client_id, name,
               bool_or(syslog_source_ip << '10.0.0.0/8' OR syslog_source_ip << '172.16.0.0/12' OR syslog_source_ip << '192.168.0.0/16')
                 OVER (PARTITION BY client_id) AS local
        FROM devices WHERE client_id = ANY(:ids) AND is_active AND (syslog_source_ip IS NOT NULL OR alt_source_ips <> '{}')
        ORDER BY client_id, last_log_at DESC NULLS LAST"""), {"ids": ctx.scope_ids})).all()}
    for r in rows:
        r["product"] = PRODUCTS.get((r["type"] or "").lower(), r["type"] or ("Log source" if r["log_device_id"] else ""))
        r["logging"] = bool(r["last_log_at"] and now - r["last_log_at"] < timedelta(hours=1))
        r["lifecycle"] = "End of life" if r["eol"] else ("Long-term support" if r["lts"] else "")
        site = gw.get(r["client_id"])
        private = bool(r["ip"]) and ipaddress.ip_address(r["ip"]).is_private
        sends = not r["log_device_id"] and (r["type"] or "").lower() not in NO_SYSLOG
        r["registrable"] = sends and (not private or site is None or bool(site.local))
        r["via"] = site.name if sends and not r["registrable"] and site is not None else None
    shown = rows
    needle = q.strip().lower()
    if needle:
        shown = [r for r in shown if any(needle in str(r[k] or "").lower() for k in ("name", "model", "ip", "mac", "client", "via", "serial"))]
    if status == "online":
        shown = [r for r in shown if r["connected"]]
    elif status == "offline":
        shown = [r for r in shown if r["connected"] is False]
    if product:
        shown = [r for r in shown if r["product"] == product]
    if updates:
        shown = [r for r in shown if r["upgradable"]]
    if lifecycle == "eol":
        shown = [r for r in shown if r["eol"]]
    return rows, shown


def firmware_by_model(rows: list[dict]) -> list[dict]:
    """Firmware compliance: per model, how many devices run which firmware, how many can be updated, end of life."""
    out: dict = {}
    for r in rows:
        if not r["model"] or not r["type"]:
            continue
        m = out.setdefault((r["product"], r["model"]), {"product": r["product"], "model": r["model"], "n": 0, "versions": {},
                                                        "updates": 0, "eol": False, "latest": None, "sites": set()})
        m["n"] += 1
        m["versions"][r["firmware"] or "?"] = m["versions"].get(r["firmware"] or "?", 0) + 1
        m["updates"] += 1 if r["upgradable"] else 0
        m["eol"] = m["eol"] or bool(r["eol"])
        m["latest"] = m["latest"] or r["firmware_latest"]
        m["sites"].add(r["client"])
    return sorted(out.values(), key=lambda m: (-m["updates"], not m["eol"], m["product"], m["model"]))


@router.get("/devices")
async def all_devices(ctx: Ctx = Depends(staff), q: str = "", status: str = "", product: str = "", updates: int = 0,
                      lifecycle: str = ""):
    rows, shown = await inventory(ctx, q, status, product, updates, lifecycle)
    summary = {"total": len(rows), "online": sum(1 for r in rows if r["connected"]),
               "offline": sum(1 for r in rows if r["connected"] is False), "updates": sum(1 for r in rows if r["upgradable"]),
               "eol": sum(1 for r in rows if r["eol"])}
    products = sorted({r["product"] for r in rows if r["product"]})
    return ctx.render("devices.html", rows=shown, summary=summary, products=products, models=firmware_by_model(rows),
                      f={"q": q, "status": status, "product": product, "updates": updates, "lifecycle": lifecycle})


@router.get("/devices.xlsx")
async def devices_xlsx(ctx: Ctx = Depends(staff), q: str = "", status: str = "", product: str = "", updates: int = 0,
                       lifecycle: str = ""):
    """The asset inventory (with the same filters) as an Excel file."""
    import io

    from fastapi.responses import Response
    from openpyxl import Workbook

    from app.reports.render import _sheet
    rows, shown = await inventory(ctx, q, status, product, updates, lifecycle)
    wb = Workbook()
    wb.remove(wb.active)
    _sheet(wb, "Assets", ["Client", "Device", "Type", "Model", "Serial", "MAC", "IP", "Firmware", "Update available",
                          "Lifecycle", "Status", "Uptime (days)", "Clients now", "Last seen (UTC)"],
           [[r["client"], r["name"], r["product"], r["model"], r["serial"], r["mac"], r["ip"], r["firmware"],
             (r["firmware_latest"] or "yes") if r["upgradable"] else "", r["lifecycle"],
             "online" if r["connected"] else ("offline" if r["connected"] is False else ""),
             round(r["uptime"] / 86400, 1) if r["uptime"] else None, r["clients_now"],
             r["seen_at"].replace(tzinfo=None) if r["seen_at"] else None] for r in shown])
    _sheet(wb, "Firmware by model", ["Type", "Model", "Devices", "Firmware versions", "Updates available", "Latest",
                                     "End of life", "Sites"],
           [[m["product"], m["model"], m["n"], ", ".join(f"{v} ({n})" for v, n in sorted(m["versions"].items())), m["updates"],
             m["latest"] or "", "yes" if m["eol"] else "", len(m["sites"])] for m in firmware_by_model(rows)])
    buf = io.BytesIO()
    wb.save(buf)
    name = f"assets-{(ctx.selected.slug if ctx.selected else 'all-clients')}.xlsx"
    return Response(buf.getvalue(), media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.post("/sources/devices")
async def create_device(
    request: Request,
    client_id: int = Form(0),
    name: str = Form(""),
    vendor: str = Form(""),
    model: str = Form(""),
    site: str = Form(""),
    syslog_source_ip: str = Form(""),
    mgmt_ip: str = Form(""),
    ctx: Ctx = Depends(staff),
):
    await check_csrf(request, ctx.session.csrf_token)
    db = ctx.db
    form = {"client_id": client_id, "name": name, "vendor": vendor, "model": model, "site": site,
            "syslog_source_ip": syslog_source_ip, "mgmt_ip": mgmt_ip}
    errors = []
    client = await db.get(Client, client_id)
    if client is None:
        errors.append("Pick a client.")
    if not name.strip():
        errors.append("Device name is required.")
    if vendor not in VENDORS:
        errors.append("Pick a vendor.")
    src = mgmt = None
    try:
        src = _norm_ip(syslog_source_ip)
    except ValueError:
        errors.append("Syslog source IP is not a valid IP address.")
    try:
        mgmt = _norm_ip(mgmt_ip)
    except ValueError:
        errors.append("Management IP is not a valid IP address.")
    if src and (other := await _ip_in_use(db, src)):
        errors.append(f"{src} is already the syslog source of {other}.")
    if errors:
        return await _add_page(ctx, 400, errors=errors, form=form)

    d = Device(client_id=client.id, name=name.strip()[:200], vendor=vendor, model=model.strip()[:100],
               site=site.strip()[:200], syslog_source_ip=src, mgmt_ip=mgmt)
    db.add(d)
    await db.flush()
    if src:
        await db.execute(delete(UnknownSource).where(UnknownSource.source_ip == src))
    await audit(db, "device_create", request=request, user=ctx.user, target=d.name, client_id=client.id,
                details={"device_id": d.id, "vendor": vendor, "syslog_source_ip": src})
    await db.commit()
    return RedirectResponse("/sources", status_code=303)


async def _ip_in_use(db, ip: str, except_device: int | None = None) -> str | None:
    """Name of another device that already uses this address (primary or additional), if any."""
    return (await db.execute(text("""
        SELECT name FROM devices WHERE (syslog_source_ip = CAST(:ip AS inet) OR CAST(:ip AS inet) = ANY(alt_source_ips))
          AND id IS DISTINCT FROM :d LIMIT 1"""), {"ip": ip, "d": except_device})).scalar()


@router.post("/sources/devices/{device_id}/ips")
async def set_device_ips(device_id: int, request: Request, syslog_source_ip: str = Form(""), alt_source_ips: str = Form(""),
                         silent_after_minutes: str = Form(""), ctx: Ctx = Depends(staff)):
    """Change the addresses a device's logs come from: the primary plus others (e.g. a second WAN)."""
    await check_csrf(request, ctx.session.csrf_token)
    d = await ctx.db.get(Device, device_id)
    if d is None or d.client_id not in ctx.scope_ids:
        raise HTTPException(404, "No such device.")
    try:
        primary = _norm_ip(syslog_source_ip)
        alts = [a for a in dict.fromkeys(_norm_ip(x) for x in re.split(r"[,\s;]+", alt_source_ips) if x.strip())
                if a and a != primary]
    except ValueError:
        raise HTTPException(400, "Every source address must be a valid IP address.") from None
    for ip in ([primary] if primary else []) + alts:
        if other := await _ip_in_use(ctx.db, ip, d.id):
            raise HTTPException(400, f"{ip} is already a source address of {other}.")
    quiet = silent_after_minutes.strip()
    if quiet and (not quiet.isdigit() or not 5 <= int(quiet) <= 10080):
        raise HTTPException(400, "Normal silence must be 5 to 10080 minutes (or empty for the default).")
    await ctx.db.execute(text("UPDATE devices SET syslog_source_ip = CAST(:p AS inet), alt_source_ips = CAST(:a AS inet[]), "
                              "silent_after_minutes = :q WHERE id = :i"),
                         {"p": primary, "a": alts, "q": int(quiet) if quiet else None, "i": d.id})
    for ip in ([primary] if primary else []) + alts:
        await ctx.db.execute(delete(UnknownSource).where(UnknownSource.source_ip == ip))
    await audit(ctx.db, "device_source_ips", request=request, user=ctx.user, target=d.name, client_id=d.client_id,
                details={"device_id": d.id, "syslog_source_ip": primary, "alt_source_ips": alts,
                         "silent_after_minutes": int(quiet) if quiet else None})
    await ctx.db.commit()
    return RedirectResponse("/sources", status_code=303)


@router.post("/sources/devices/{device_id}/active")
async def toggle_device(device_id: int, request: Request, ctx: Ctx = Depends(staff)):
    await check_csrf(request, ctx.session.csrf_token)
    d = await ctx.db.get(Device, device_id)
    if d is None:
        raise HTTPException(404, "No such device.")
    d.is_active = not d.is_active
    await audit(ctx.db, "device_enable" if d.is_active else "device_disable", request=request, user=ctx.user,
                target=d.name, client_id=d.client_id, details={"device_id": d.id})
    await ctx.db.commit()
    return RedirectResponse("/sources", status_code=303)


@router.post("/sources/devices/{device_id}/flows")
async def toggle_cloud_flows(device_id: int, request: Request, ctx: Ctx = Depends(staff)):
    """Traffic flows through UniFi Site Manager for a console that is not polled locally. While on, NetFlow from the
    device is not stored (the same traffic would be counted twice)."""
    await check_csrf(request, ctx.session.csrf_token)
    d = await ctx.db.get(Device, device_id)
    if d is None or d.client_id not in ctx.scope_ids:
        raise HTTPException(404, "No such device.")
    if (d.poll_config or {}).get("driver") == "unifi":
        raise HTTPException(400, "This device is polled locally; its flows are collected through the local API.")
    linked = (await ctx.db.execute(text("SELECT 1 FROM sitemanager_hosts WHERE device_id = :d"), {"d": d.id})).first()
    if not linked:
        raise HTTPException(400, "This device is not linked to a UniFi Site Manager console.")
    on = not bool((d.poll_config or {}).get("collect_flows"))
    cfg = {k: v for k, v in (d.poll_config or {}).items() if k != "flow_cursor_ms"}
    cfg["collect_flows"] = on
    d.poll_config = cfg
    await audit(ctx.db, "device_cloud_flows", request=request, user=ctx.user, target=d.name, client_id=d.client_id,
                details={"device_id": d.id, "enabled": on})
    await ctx.db.commit()
    return RedirectResponse("/sources", status_code=303)


@router.post("/sources/unknown/ignore")
async def ignore_unknown(request: Request, source_ip: str = Form(""), ctx: Ctx = Depends(staff)):
    await check_csrf(request, ctx.session.csrf_token)
    try:
        ip = _norm_ip(source_ip)
    except ValueError:
        raise HTTPException(400, "Invalid IP.")
    row = await ctx.db.get(UnknownSource, ip)
    if row is None:
        raise HTTPException(404, "No such unknown source.")
    row.ignored = True
    await audit(ctx.db, "unknown_source_ignore", request=request, user=ctx.user, target=ip)
    await ctx.db.commit()
    return RedirectResponse("/sources", status_code=303)


@router.get("/sources/raw")
async def raw_lines(device_id: int, limit: int = 100, ctx: Ctx = Depends(staff)):
    d = await ctx.db.get(Device, device_id)
    if d is None:
        raise HTTPException(404, "No such device.")
    rows = (await ctx.db.execute(
        select(RawLog).where(RawLog.device_id == d.id).order_by(RawLog.ts_received.desc()).limit(max(1, min(limit, 1000)))
    )).scalars().all()
    return ctx.render("sources_raw.html", device=d, rows=rows)


# ------------------------------------------------------------------ maintenance windows (staff)
@router.get("/sources/maintenance")
async def maintenance(ctx: Ctx = Depends(staff)):
    rows = (await ctx.db.execute(text("""
        SELECT m.id, m.starts_at, m.ends_at, m.reason, m.created_by, c.name AS client, c.timezone, d.name AS device,
               (now() BETWEEN m.starts_at AND m.ends_at) AS active, m.ends_at < now() AS past
        FROM maintenance_windows m JOIN clients c ON c.id = m.client_id LEFT JOIN devices d ON d.id = m.device_id
        WHERE m.client_id = ANY(:ids) ORDER BY m.starts_at DESC LIMIT 200"""), {"ids": ctx.scope_ids})).all()
    devices = (await ctx.db.execute(text(
        "SELECT d.id, d.name, c.id AS client_id, c.name AS client FROM devices d JOIN clients c ON c.id = d.client_id "
        "WHERE d.client_id = ANY(:ids) ORDER BY c.name, d.name"), {"ids": ctx.scope_ids})).all()
    return ctx.render("maintenance.html", rows=rows, devices=devices, clients=ctx.clients)


@router.post("/sources/maintenance")
async def create_maintenance(request: Request, client_id: int = Form(0), device_id: str = Form(""),
                             starts: str = Form(""), ends: str = Form(""), reason: str = Form(""),
                             ctx: Ctx = Depends(staff)):
    await check_csrf(request, ctx.session.csrf_token)
    client = next((c for c in ctx.clients if c.id == client_id), None)
    if client is None:
        raise HTTPException(400, "Pick a client you have access to.")
    try:
        tz = ZoneInfo(client.timezone)
        s = datetime.fromisoformat(starts).replace(tzinfo=tz)
        e = datetime.fromisoformat(ends).replace(tzinfo=tz)
    except ValueError:
        raise HTTPException(400, "Start and end must be valid date/times.")
    if e <= s:
        raise HTTPException(400, "The window must end after it starts.")
    dev = int(device_id) if device_id.isdigit() else None
    if dev is not None and (await ctx.db.get(Device, dev)) is None:
        raise HTTPException(400, "No such device.")
    await ctx.db.execute(text("INSERT INTO maintenance_windows (client_id, device_id, starts_at, ends_at, reason, created_by) "
                              "VALUES (:c, :d, :s, :e, :r, :u)"),
                         {"c": client.id, "d": dev, "s": s, "e": e, "r": reason.strip()[:300], "u": ctx.user.username})
    await audit(ctx.db, "maintenance_create", request=request, user=ctx.user, client_id=client.id,
                details={"device_id": dev, "starts": s.isoformat(), "ends": e.isoformat(), "reason": reason[:300]})
    await ctx.db.commit()
    return RedirectResponse("/sources/maintenance", status_code=303)


@router.post("/sources/maintenance/{mw_id}/delete")
async def delete_maintenance(mw_id: int, request: Request, ctx: Ctx = Depends(staff)):
    await check_csrf(request, ctx.session.csrf_token)
    res = await ctx.db.execute(text("DELETE FROM maintenance_windows WHERE id = :i AND client_id = ANY(:ids)"),
                               {"i": mw_id, "ids": ctx.scope_ids})
    if res.rowcount == 0:
        raise HTTPException(404, "No such maintenance window.")
    await audit(ctx.db, "maintenance_delete", request=request, user=ctx.user, target=str(mw_id))
    await ctx.db.commit()
    return RedirectResponse("/sources/maintenance", status_code=303)
