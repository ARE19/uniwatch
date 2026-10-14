"""Reports: request a report for a period, list runs, download PDF/Excel, manage monthly schedules.
Every role can see and download its clients' reports (brief: client users get dashboards and reports);
schedules are staff-only."""

import re
from datetime import date, datetime, time, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy import text

from app.audit import audit
from app import mail
from app.config import get_settings
from app.models.auth import ROLE_ADMIN, ROLE_ENGINEER
from app.reports.data import BUNDLE_TITLES, TITLES, month_bounds, report_types
from app.web.deps import Ctx, check_csrf, current, require_role

router = APIRouter()
staff = require_role(ROLE_ADMIN, ROLE_ENGINEER)
TYPES = {"firewall_bundle": "Executive summary report (summary + 7 detailed sections)",
         "monthly_bundle": "Monthly bundle (network reports)", **TITLES}
EMAIL_RE = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")


def _client(ctx: Ctx, client_id: int):
    c = next((c for c in ctx.clients if c.id == client_id), None)
    if c is None:
        raise HTTPException(403, "You cannot use that client.")
    return c


def _recipients(raw: str) -> list[str]:
    out = [x.strip() for x in re.split(r"[,\s;]+", raw or "") if x.strip()]
    bad = [x for x in out if not EMAIL_RE.match(x)]
    if bad:
        raise HTTPException(400, f"Not an e-mail address: {', '.join(bad)}")
    return out[:20]


@router.get("/reports")
async def reports(ctx: Ctx = Depends(current)):
    runs = (await ctx.db.execute(text("""
        SELECT r.id, r.report_type, r.period_start, r.period_end, r.status, r.requested_by, r.created_at, r.finished_at,
               r.summary, r.error, r.email_status, r.recipients, c.name AS client, c.timezone
        FROM report_runs r JOIN clients c ON c.id = r.client_id
        WHERE r.client_id = ANY(:ids) ORDER BY r.created_at DESC LIMIT 200"""), {"ids": ctx.scope_ids})).all()
    schedules = (await ctx.db.execute(text("""
        SELECT s.id, s.report_type, s.recipients, s.day_of_month, s.hour_local, s.enabled, c.name AS client, c.timezone
        FROM report_schedules s JOIN clients c ON c.id = s.client_id WHERE s.client_id = ANY(:ids) ORDER BY c.name, s.report_type"""),
        {"ids": ctx.scope_ids})).all() if ctx.is_staff else []
    tz = ctx.tz
    today = datetime.now(ZoneInfo(tz)).date()
    this_month = today.replace(day=1)
    last_month = (this_month - timedelta(days=1)).replace(day=1)
    presets = {"Last month": (last_month, this_month - timedelta(days=1)), "This month": (this_month, today),
               "Last 7 days": (today - timedelta(days=7), today - timedelta(days=1)),
               "Last 30 days": (today - timedelta(days=30), today - timedelta(days=1))}
    types = report_types()
    return ctx.render("reports.html", runs=runs, schedules=schedules, types=types, presets=presets, today=today,
                      names={**BUNDLE_TITLES, **TITLES, **types},
                      default_from=last_month, default_to=this_month - timedelta(days=1),
                      smtp=bool((await mail.effective(get_settings(), ctx.db)).smtp_host), staff=ctx.is_staff)


@router.post("/reports")
async def request_report(request: Request, client_id: str = Form("0"), report_type: str = Form("monthly_bundle"),
                         month: str = Form(""), from_: str = Form("", alias="from"), to: str = Form(""),
                         date_from: str = Form(""), date_to: str = Form(""),
                         recipients: str = Form(""), ctx: Ctx = Depends(current)):
    await check_csrf(request, ctx.session.csrf_token)
    if client_id.startswith("g"):                     # a company: one report per site (each in its own time zone)
        g = next((g for g in ctx.companies if f"g{g.id}" == client_id), None)
        if g is None:
            raise HTTPException(403, "You cannot use that company.")
        sites = [c for c in ctx.clients if c.company_id == g.id]
    else:
        sites = [_client(ctx, int(client_id) if client_id.isdigit() else 0)]
    if report_type not in report_types():
        raise HTTPException(400, "Unknown report type.")
    for c in sites:
        await _queue_report(ctx, request, c, report_type, month, from_, to, date_from, date_to, recipients)
    await ctx.db.commit()
    return RedirectResponse("/reports", status_code=303)


async def _queue_report(ctx: Ctx, request: Request, c, report_type: str, month: str, from_: str, to: str, date_from: str,
                        date_to: str, recipients: str) -> None:
    tz = ZoneInfo(c.timezone)
    if date_from or date_to:                       # calendar range, whole days in the client's time zone (both included)
        try:
            d0, d1 = date.fromisoformat(date_from), date.fromisoformat(date_to)
        except ValueError:
            raise HTTPException(400, "Pick a start and an end date.")
        if d1 < d0:
            raise HTTPException(400, "The end date must be on or after the start date.")
        if (d1 - d0).days > 366:
            raise HTTPException(400, "The period can be at most one year.")
        start = datetime.combine(d0, time.min, tz)
        end = datetime.combine(d1 + timedelta(days=1), time.min, tz)
    elif from_ and to:
        try:
            start = datetime.fromisoformat(from_).replace(tzinfo=tz)
            end = datetime.fromisoformat(to).replace(tzinfo=tz)
        except ValueError:
            raise HTTPException(400, "Invalid custom period.")
    else:
        m = re.fullmatch(r"(\d{4})-(\d{2})", month or "")
        if not m or not 1 <= int(m[2]) <= 12:
            raise HTTPException(400, "Pick a month (YYYY-MM).")
        start, end = month_bounds(int(m[1]), int(m[2]), c.timezone)
    if end <= start:
        raise HTTPException(400, "The period must end after it starts.")
    rcpt = _recipients(recipients) if ctx.is_staff else []
    await ctx.db.execute(text("""
        INSERT INTO report_runs (client_id, report_type, period_start, period_end, requested_by, recipients)
        VALUES (:c, :t, :s, :e, :u, :r)"""), {"c": c.id, "t": report_type, "s": start, "e": end, "u": ctx.user.username, "r": rcpt})
    await audit(ctx.db, "report_request", request=request, user=ctx.user, client_id=c.id,
                details={"type": report_type, "start": start.isoformat(), "end": end.isoformat(), "recipients": rcpt})


@router.get("/reports/{run_id}/{fmt}")
async def download(run_id: int, fmt: str, request: Request, ctx: Ctx = Depends(current)):
    if fmt not in ("pdf", "xlsx"):
        raise HTTPException(404, "Unknown format.")
    row = (await ctx.db.execute(text(
        "SELECT client_id, pdf_path, xlsx_path, status FROM report_runs WHERE id = :i AND client_id = ANY(:ids)"),
        {"i": run_id, "ids": ctx.scope_ids})).first()
    if row is None or row.status != "done":
        raise HTTPException(404, "No such report.")
    path = Path(row.pdf_path if fmt == "pdf" else row.xlsx_path)
    root = Path(get_settings().reports_dir).resolve()
    if not path.resolve().is_relative_to(root) or not path.exists():
        raise HTTPException(404, "Report file is missing.")
    await audit(ctx.db, "report_download", request=request, user=ctx.user, client_id=row.client_id,
                target=str(run_id), details={"format": fmt})
    await ctx.db.commit()
    media = "application/pdf" if fmt == "pdf" else "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    return FileResponse(path, media_type=media, filename=path.name)


@router.post("/reports/{run_id}/delete")
async def delete_report(run_id: int, request: Request, ctx: Ctx = Depends(staff)):
    """Delete a generated report: its PDF and Excel files and the list entry."""
    await check_csrf(request, ctx.session.csrf_token)
    row = (await ctx.db.execute(text(
        "SELECT client_id, report_type, status, pdf_path, xlsx_path, period_start FROM report_runs WHERE id = :i AND client_id = ANY(:ids)"),
        {"i": run_id, "ids": ctx.scope_ids})).first()
    if row is None:
        raise HTTPException(404, "No such report.")
    if row.status == "running":
        raise HTTPException(409, "The report is being generated; delete it when it has finished.")
    root = Path(get_settings().reports_dir).resolve()
    for f in (row.pdf_path, row.xlsx_path):
        if f:
            p = Path(f).resolve()
            if p.is_relative_to(root):
                p.unlink(missing_ok=True)
    await ctx.db.execute(text("DELETE FROM report_runs WHERE id = :i"), {"i": run_id})
    await audit(ctx.db, "report_delete", request=request, user=ctx.user, client_id=row.client_id, target=str(run_id),
                details={"type": row.report_type, "period_start": row.period_start.isoformat()})
    await ctx.db.commit()
    return RedirectResponse("/reports", status_code=303)


@router.post("/reports/schedules")
async def create_schedule(request: Request, client_id: int = Form(0), report_type: str = Form("monthly_bundle"),
                          recipients: str = Form(""), day_of_month: int = Form(1), hour_local: int = Form(6),
                          ctx: Ctx = Depends(staff)):
    await check_csrf(request, ctx.session.csrf_token)
    c = _client(ctx, client_id)
    if report_type not in report_types() or not 1 <= day_of_month <= 28 or not 0 <= hour_local <= 23:
        raise HTTPException(400, "Invalid schedule.")
    rcpt = _recipients(recipients)
    await ctx.db.execute(text("""
        INSERT INTO report_schedules (client_id, report_type, recipients, day_of_month, hour_local, created_by)
        VALUES (:c, :t, :r, :d, :h, :u)
        ON CONFLICT (client_id, report_type) DO UPDATE SET recipients = EXCLUDED.recipients,
            day_of_month = EXCLUDED.day_of_month, hour_local = EXCLUDED.hour_local, enabled = true"""),
        {"c": c.id, "t": report_type, "r": rcpt, "d": day_of_month, "h": hour_local, "u": ctx.user.username})
    await audit(ctx.db, "report_schedule_set", request=request, user=ctx.user, client_id=c.id,
                details={"type": report_type, "recipients": rcpt, "day": day_of_month, "hour": hour_local})
    await ctx.db.commit()
    return RedirectResponse("/reports", status_code=303)


@router.post("/reports/schedules/{sid}/delete")
async def delete_schedule(sid: int, request: Request, ctx: Ctx = Depends(staff)):
    await check_csrf(request, ctx.session.csrf_token)
    res = await ctx.db.execute(text("DELETE FROM report_schedules WHERE id = :i AND client_id = ANY(:ids)"),
                               {"i": sid, "ids": ctx.scope_ids})
    if res.rowcount == 0:
        raise HTTPException(404, "No such schedule.")
    await audit(ctx.db, "report_schedule_delete", request=request, user=ctx.user, target=str(sid))
    await ctx.db.commit()
    return RedirectResponse("/reports", status_code=303)
