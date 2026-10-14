"""Report runner and monthly scheduler.

Runs are rows in report_runs. The web UI and the scheduler only ever INSERT a queued row; this service
claims queued rows (FOR UPDATE SKIP LOCKED), builds the data once, writes PDF + Excel, and e-mails them
when recipients and SMTP are configured. Monthly schedules create the previous calendar month's run (in
the client's own time zone) once that month has ended and the configured day/hour has passed."""

import asyncio
import logging
import smtplib
import ssl
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path
from zoneinfo import ZoneInfo

from psycopg.types.json import Jsonb
from sqlalchemy import text

from app import db
from app.config import Settings, get_settings
from app.reports.data import BUNDLE_TITLES, TITLES, build, previous_month
from app.reports.render import write_pdf, write_xlsx

log = logging.getLogger("reporter")


def summary_of(report: dict) -> dict:
    """Small headline numbers stored with the run (shown in the UI list)."""
    out = {}
    for s in report["sections"]:
        if s["type"] == "device_uptime":
            av = [d["availability"] for d in s["devices"] if d["availability"] is not None]
            out["device_availability_min"] = round(min(av) * 100, 3) if av else None
        elif s["type"] == "vpn_uptime":
            av = [t["availability"] for t in s["tunnels"] if t["availability"] is not None]
            out["vpn_availability_min"] = round(min(av) * 100, 3) if av else None
            out["vpn_drops"] = sum(t["drops"] for t in s["tunnels"])
        elif s["type"] == "vpn_sessions":
            out["vpn_sessions"] = len(s["sessions"])
        elif s["type"] == "internet_usage" and s["wans"]:
            out["internet_download_gb"] = round(sum(w["rx"] for w in s["wans"]) / 1e9, 2)
            out["internet_upload_gb"] = round(sum(w["tx"] for w in s["wans"]) / 1e9, 2)
    return out


def send_mail(s: Settings, to: list[str], subject: str, body: str, files: list[Path]) -> None:
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = s.smtp_from or s.smtp_user, ", ".join(to), subject
    msg.set_content(body)
    for f in files:
        sub = "pdf" if f.suffix == ".pdf" else "vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        msg.add_attachment(f.read_bytes(), maintype="application", subtype=sub, filename=f.name)
    with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=60) as smtp:
        if s.smtp_starttls:
            smtp.starttls(context=ssl.create_default_context())
        if s.smtp_user:
            smtp.login(s.smtp_user, s.smtp_password)
        smtp.send_message(msg)


class Reporter:
    def __init__(self, settings: Settings | None = None, mailer=send_mail):
        self.s = settings or get_settings()
        self.mailer = mailer

    async def claim(self, session) -> dict | None:
        row = (await session.execute(text("""
            UPDATE report_runs SET status = 'running', started_at = now()
            WHERE id = (SELECT id FROM report_runs WHERE status = 'queued' ORDER BY created_at
                        FOR UPDATE SKIP LOCKED LIMIT 1)
            RETURNING id, client_id, report_type, period_start, period_end, recipients""")) ).first()
        await session.commit()
        return dict(row._mapping) if row else None

    async def run_next(self, now: datetime | None = None) -> int | None:
        """Process one queued run. Returns its id, or None when the queue is empty."""
        async with db.sessionmaker()() as session:
            run = await self.claim(session)
            if run is None:
                return None
            try:
                report = await build(session, run["report_type"], run["client_id"], run["period_start"], run["period_end"], now)
                slug, tz = report["client"]["slug"], report["client"]["timezone"]
                label = run["period_start"].astimezone(ZoneInfo(tz)).strftime("%Y-%m-%d")
                base = Path(self.s.reports_dir) / slug / f"{run['id']}-{run['report_type']}-{label}"
                pdf, xlsx = base.with_suffix(".pdf"), base.with_suffix(".xlsx")
                await asyncio.to_thread(write_pdf, report, pdf)
                await asyncio.to_thread(write_xlsx, report, xlsx)
                email_status, emailed_at = None, None
                if run["recipients"]:
                    from app import mail
                    ms = await mail.effective(self.s, session)    # Admin -> Mail settings, else .env
                    if not ms.smtp_host:
                        email_status = "not sent: SMTP is not configured"
                    else:
                        title = TITLES.get(run["report_type"]) or BUNDLE_TITLES.get(run["report_type"], "Network report")
                        subject = f"{report['client']['name']} — {title} — {label[:7]}"
                        try:
                            await asyncio.to_thread(self.mailer, ms, list(run["recipients"]), subject,
                                                    f"Attached: {title} for {report['client']['name']}, period starting {label}.",
                                                    [pdf, xlsx])
                            email_status, emailed_at = "sent", datetime.now(UTC)
                        except Exception as e:  # noqa: BLE001 — the report itself succeeded
                            email_status = f"failed: {type(e).__name__}: {e}"[:300]
                await session.execute(text("""
                    UPDATE report_runs SET status = 'done', finished_at = now(), pdf_path = :pdf, xlsx_path = :xlsx,
                           summary = :summary, email_status = :es, emailed_at = :ea WHERE id = :id"""),
                    {"pdf": str(pdf), "xlsx": str(xlsx), "summary": Jsonb(summary_of(report)), "es": email_status,
                     "ea": emailed_at, "id": run["id"]})
                await session.commit()
                log.info("report %s done (%s)", run["id"], run["report_type"])
            except Exception as e:  # noqa: BLE001
                await session.rollback()
                log.exception("report %s failed", run["id"])
                await session.execute(text("UPDATE report_runs SET status = 'failed', finished_at = now(), error = :e WHERE id = :id"),
                                      {"e": f"{type(e).__name__}: {e}"[:1000], "id": run["id"]})
                await session.commit()
            return run["id"]

    async def drain(self, now: datetime | None = None) -> int:
        n = 0
        while await self.run_next(now) is not None:
            n += 1
        return n

    async def check_schedules(self, now: datetime | None = None) -> int:
        now = now or datetime.now(UTC)
        created = 0
        async with db.sessionmaker()() as session:
            rows = (await session.execute(text("""
                SELECT s.id, s.client_id, s.report_type, s.recipients, s.day_of_month, s.hour_local, c.timezone
                FROM report_schedules s JOIN clients c ON c.id = s.client_id WHERE s.enabled"""))).all()
            for r in rows:
                local = now.astimezone(ZoneInfo(r.timezone))
                if (local.day, local.hour) < (r.day_of_month, r.hour_local):
                    continue
                start, end = previous_month(now, r.timezone)
                res = await session.execute(text("""
                    INSERT INTO report_runs (client_id, report_type, period_start, period_end, schedule_id, requested_by, recipients)
                    VALUES (:c, :t, :s, :e, :sid, 'schedule', :rcpt)
                    ON CONFLICT (schedule_id, period_start) WHERE schedule_id IS NOT NULL DO NOTHING"""),
                    {"c": r.client_id, "t": r.report_type, "s": start, "e": end, "sid": r.id, "rcpt": list(r.recipients)})
                created += res.rowcount
            await session.commit()
        return created
