"""Device Manager -> Config backups: the latest configuration backup of each UniFi console, what changed and when
(object by object, before / after), and a download of the backup. Secrets are redacted at collection time.
Staff only (configuration detail)."""

import json
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import text

from app.models.auth import ROLE_ADMIN, ROLE_ENGINEER
from app.poller.config_backup import LABELS
from app.web.deps import Ctx, require_role

router = APIRouter()
staff = require_role(ROLE_ADMIN, ROLE_ENGINEER)
admin_only = require_role(ROLE_ADMIN)


@router.get("/config")
async def config_backups(ctx: Ctx = Depends(staff), days: int = 30, section: str = ""):
    days = days if days in (7, 30, 90, 365) else 30
    (now,) = (await ctx.db.execute(text("SELECT now()"))).one()
    p = {"ids": ctx.scope_ids, "since": now - timedelta(days=days), "section": section}
    sites = (await ctx.db.execute(text("""
        SELECT c.id, c.name, c.timezone, max(s.taken_at) AS last_change, count(DISTINCT s.section) AS sections,
               count(*) FILTER (WHERE s.changes IS NOT NULL AND s.taken_at >= :since) AS changes,
               (SELECT max(p.last_sync) FROM sitemanager_hosts p WHERE p.client_id = c.id) AS last_check
        FROM config_snapshots s JOIN clients c ON c.id = s.client_id
        WHERE s.client_id = ANY(:ids) GROUP BY c.id ORDER BY c.name"""), p)).all()
    changes = (await ctx.db.execute(text("""
        SELECT s.id, s.taken_at, s.section, s.summary, c.name AS client, c.timezone,
               (SELECT string_agg(DISTINCT cc.admin_user, ', ') FROM config_changes cc
                 WHERE cc.client_id = s.client_id AND cc.ts BETWEEN s.taken_at - interval '4 hours' AND s.taken_at
                   AND cc.admin_user IS NOT NULL) AS admins
        FROM config_snapshots s JOIN clients c ON c.id = s.client_id
        WHERE s.client_id = ANY(:ids) AND s.changes IS NOT NULL AND s.taken_at >= :since AND (:section = '' OR s.section = :section)
        ORDER BY s.taken_at DESC LIMIT 300"""), p)).all()
    full = (await ctx.db.execute(text("""
        SELECT b.id, b.filename, b.taken_at, b.version, b.size, b.fetched_at, c.name AS client, c.timezone, d.name AS device
        FROM firewall_backups b JOIN clients c ON c.id = b.client_id JOIN devices d ON d.id = b.device_id
        WHERE b.client_id = ANY(:ids) ORDER BY c.name, b.taken_at DESC NULLS LAST"""), p)).all()
    return ctx.render("config.html", sites=sites, changes=changes, labels=LABELS, days=days, section=section, full=full,
                      is_admin=ctx.role == ROLE_ADMIN)


@router.get("/config/full/{backup_id}")
async def full_backup_download(backup_id: int, request: Request, ctx: Ctx = Depends(admin_only)):
    """A console's own backup file (.unf, restorable in UniFi), decrypted for download. Admins only; audited."""
    from pathlib import Path

    from app.audit import audit
    from app.poller.fw_backup import decrypt
    b = (await ctx.db.execute(text("""SELECT b.id, b.filename, b.path, b.sha256, b.client_id FROM firewall_backups b
                                       WHERE b.id = :i AND b.client_id = ANY(:ids)"""), {"i": backup_id, "ids": ctx.scope_ids})).one_or_none()
    if b is None or not Path(b.path).exists():
        raise HTTPException(404, "No such backup file.")
    import asyncio
    import hashlib
    data = await asyncio.to_thread(lambda: decrypt(Path(b.path).read_bytes()))
    if hashlib.sha256(data).hexdigest() != b.sha256:
        raise HTTPException(500, "The stored backup does not match its checksum.")
    await audit(ctx.db, "firewall_backup_download", request=request, user=ctx.user, client_id=b.client_id, target=b.filename)
    await ctx.db.commit()
    return Response(data, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{b.filename}"'})


@router.get("/config/change/{snapshot_id}")
async def config_change(snapshot_id: int, ctx: Ctx = Depends(staff)):
    s = (await ctx.db.execute(text("""
        SELECT s.id, s.taken_at, s.section, s.summary, s.changes, s.client_id, c.name AS client, c.timezone,
               (SELECT max(x.taken_at) FROM config_snapshots x WHERE x.host_id = s.host_id AND x.section = s.section
                  AND x.taken_at < s.taken_at) AS previous
        FROM config_snapshots s JOIN clients c ON c.id = s.client_id
        WHERE s.id = :i AND s.client_id = ANY(:ids)"""), {"i": snapshot_id, "ids": ctx.scope_ids})).one_or_none()
    if s is None:
        raise HTTPException(404, "No such change.")
    admins = (await ctx.db.execute(text("""
        SELECT cc.ts, cc.admin_user, host(cc.source_ip) AS ip, cc.summary FROM config_changes cc
        WHERE cc.client_id = :c AND cc.ts BETWEEN coalesce(:prev, :t - interval '4 hours') AND :t ORDER BY cc.ts"""),
        {"c": s.client_id, "prev": s.previous, "t": s.taken_at})).all()
    return ctx.render("config_change.html", s=s, label=LABELS.get(s.section, s.section), admins=admins)


@router.get("/config/site/{client_id}/backup.json")
async def config_download(client_id: int, ctx: Ctx = Depends(staff)):
    """The latest version of every section of the site's console(s), as one JSON file (secrets redacted)."""
    if client_id not in ctx.scope_ids and not any(c.id == client_id for c in ctx.clients):
        raise HTTPException(404, "No such site.")
    rows = (await ctx.db.execute(text("""
        SELECT DISTINCT ON (s.host_id, s.section) s.host_id, s.section, s.taken_at, s.data, c.slug
        FROM config_snapshots s JOIN clients c ON c.id = s.client_id
        WHERE s.client_id = :c ORDER BY s.host_id, s.section, s.taken_at DESC"""), {"c": client_id})).all()
    if not rows:
        raise HTTPException(404, "No backup for this site yet.")
    body = {"note": "UniFi configuration backup from the Uniwatch; secrets are redacted (fingerprints only). "
                    "For a full restore use the console's own backup (UniFi OS -> Settings -> Backups).",
            "consoles": {}}
    for r in rows:
        body["consoles"].setdefault(r.host_id, {})[r.section] = {"backed_up": r.taken_at.isoformat(), "objects": r.data}
    name = f"unifi-config-{rows[0].slug}-{max(r.taken_at for r in rows):%Y%m%d}.json"
    return Response(json.dumps(body, indent=1, default=str), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})
