"""Phase 8: report numbers vs. hand calculation, PDF/Excel output, schedules, scoping, downloads.

Acceptance: a sample monthly report must match hand-checked numbers. The fixture builds October 2026
(client time zone Asia/Hong_Kong) with known outages and a maintenance window; the expected values are
worked out in the comments and asserted against the data AND the rendered Excel file."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from openpyxl import load_workbook
from sqlalchemy import text

from app import db
from app.reporter.service import Reporter
from app.reports.data import build, month_bounds, previous_month
from app.reports.intervals import summarize
from tests.conftest import csrf_from, full_login

HK = "Asia/Hong_Kong"
START, END = month_bounds(2026, 10, HK)          # 2026-09-30T16:00Z .. 2026-10-31T16:00Z
MONTH_S = (END - START).total_seconds()          # 31 days = 2,678,400 s
AFTER = END + timedelta(days=2)                  # "now" for report generation


def at(day, hour=0, minute=0):
    """A local (HKT) time in October 2026, as UTC."""
    return datetime(2026, 10, day, hour, minute, tzinfo=UTC) - timedelta(hours=8)


def test_month_bounds_and_previous_month():
    assert START == datetime(2026, 9, 30, 16, 0, tzinfo=UTC) and END == datetime(2026, 10, 31, 16, 0, tzinfo=UTC)
    assert MONTH_S == 31 * 86400
    assert previous_month(datetime(2026, 11, 1, 2, 0, tzinfo=UTC), HK) == (START, END)   # 10:00 HKT on 1 Nov
    assert previous_month(datetime(2027, 1, 5, tzinfo=UTC), HK) == month_bounds(2026, 12, HK)


def test_summarize_clips_and_reclassifies_maintenance():
    s, e = at(1), at(2)
    iv = [("up", at(1) - timedelta(hours=5), at(1, 10)), ("down", at(1, 10), at(1, 12)), ("up", at(1, 12), None)]
    sm = summarize(iv, s, e, maintenance=[(at(1, 11), at(1, 13))], now=at(3))
    # up 00:00-10:00 (10h) + 12:00-24:00 (12h) = 22h; down 10:00-11:00 unplanned (1h) + 11:00-12:00 planned (1h)
    assert sm.seconds == {"up": 22 * 3600, "down": 3600, "maintenance": 3600}
    assert sm.drops == 1 and sm.outages == [(at(1, 10), at(1, 11))]
    assert sm.availability == pytest.approx(22 / 23)


@pytest.fixture
def october(owner_engine):
    with owner_engine.begin() as c:
        cid = c.execute(text("INSERT INTO clients (name, slug, timezone) VALUES ('Northwind HK','nwhk',:tz) RETURNING id"), {"tz": HK}).scalar()
        gw = c.execute(text("INSERT INTO devices (client_id, name, vendor, model, firmware) VALUES (:c,'NW-HK','unifi','UDM-Pro-SE','5.1.33') RETURNING id"), {"c": cid}).scalar()
        ap = c.execute(text("INSERT INTO devices (client_id, name, vendor, model) VALUES (:c,'NWHKWAP-01','unifi','U6-Lite') RETURNING id"), {"c": cid}).scalar()
        ins = text("INSERT INTO device_state (client_id, device_id, state, started_at, ended_at) VALUES (:c, :d, :s, :a, :b)")
        # Gateway: up all month except down 3 Oct 09:00-11:00 (2 h) and down 20 Oct 22:00-23:30, of which
        # 22:00-23:00 is inside a maintenance window -> unplanned down = 2h + 30m = 2.5 h = 9000 s.
        for s, a, b in (("up", START - timedelta(days=3), at(3, 9)), ("down", at(3, 9), at(3, 11)), ("up", at(3, 11), at(20, 22)),
                        ("down", at(20, 22), at(20, 23, 30)), ("up", at(20, 23, 30), None)):
            c.execute(ins, {"c": cid, "d": gw, "s": s, "a": a, "b": b})
        c.execute(text("INSERT INTO maintenance_windows (client_id, device_id, starts_at, ends_at, reason) VALUES (:c, :d, :a, :b, 'fw')"),
                  {"c": cid, "d": gw, "a": at(20, 22), "b": at(20, 23)})
        # AP: monitored only from 15 Oct 00:00 -> no data for 14 days; never down.
        c.execute(ins, {"c": cid, "d": ap, "s": "up", "a": at(15), "b": None})
        # Tunnel: up, 3 drops of 5 min each inside October, and one drop that started in September (not counted as a drop
        # in October, but its October part counts as downtime): 30 Sep 23:50 HKT -> 1 Oct 00:10 HKT = 10 min in October.
        tins = text("INSERT INTO vpn_tunnel_state (client_id, device_id, tunnel_name, peer, state, started_at, ended_at) "
                    "VALUES (:c, :d, 'tunovpnc1', '11.124.200.216:1194', :s, :a, :b)")
        tl = [("down", START - timedelta(minutes=10), at(1, 0, 10)), ("up", at(1, 0, 10), at(5, 8))]
        for day in (5, 12, 19):
            tl += [("down", at(day, 8), at(day, 8, 5)), ("up", at(day, 8, 5), at(12, 8) if day == 5 else at(19, 8) if day == 12 else None)]
        for s, a, b in tl:
            c.execute(tins, {"c": cid, "d": gw, "s": s, "a": a, "b": b})
        # Sessions: alice 2 h; bob 30 min; carol connect never logged
        sins = text("INSERT INTO vpn_sessions (client_id, device_id, user_name, source_ip, started_at, ended_at, last_seen_at, status, close_reason) "
                    "VALUES (:c, :d, :u, :ip, :a, :b, coalesce(:b, :a), 'closed', :r)")
        c.execute(sins, {"c": cid, "d": gw, "u": "alice", "ip": "85.217.149.17", "a": at(7, 9), "b": at(7, 11), "r": "disconnect"})
        c.execute(sins, {"c": cid, "d": gw, "u": "bob", "ip": "203.0.113.5", "a": at(8, 9), "b": at(8, 9, 30), "r": "disconnect"})
        c.execute(sins, {"c": cid, "d": gw, "u": "carol", "ip": None, "a": None, "b": at(9, 9), "r": "disconnect-without-connect"})
    return cid, gw, ap


async def test_monthly_numbers_match_hand_calculation(october):
    cid, gw, ap = october
    async with db.sessionmaker()() as s:
        rep = await build(s, "monthly_bundle", cid, START, END, now=AFTER)
    sec = {x["type"]: x for x in rep["sections"]}

    dev = {d["name"]: d for d in sec["device_uptime"]["devices"]}
    g = dev["NW-HK"]
    assert g["down_s"] == 9000 and g["maintenance_s"] == 3600 and g["drops"] == 2
    assert g["up_s"] == MONTH_S - 9000 - 3600
    assert g["availability"] == pytest.approx((MONTH_S - 12600) / (MONTH_S - 3600))   # 99.6638 %
    assert round(g["availability"] * 100, 3) == 99.664
    a = dev["NWHKWAP-01"]
    assert a["availability"] == 1.0 and a["no_data_s"] == 14 * 86400

    t = sec["vpn_uptime"]["tunnels"][0]
    assert t["drops"] == 3                                  # the September-started drop is not an October drop
    assert t["down_s"] == 3 * 300 + 600                     # 15 min + 10 min carried over = 1500 s
    assert t["availability"] == pytest.approx((MONTH_S - 1500) / MONTH_S)               # 99.9440 %
    assert t["longest"][0] == (START, at(1, 0, 10))

    vs = sec["vpn_sessions"]
    users = {u["user"]: u for u in vs["users"]}
    assert users["alice"]["total_s"] == 7200 and users["bob"]["total_s"] == 1800 and users["carol"]["total_s"] == 0
    assert len(vs["sessions"]) == 3


async def test_reporter_writes_pdf_and_matching_excel(october, owner_engine, tmp_path):
    cid, gw, ap = october
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO report_runs (client_id, report_type, period_start, period_end, requested_by, recipients) "
                       "VALUES (:c, 'monthly_bundle', :s, :e, 'test', ARRAY['noc@example.com'])"), {"c": cid, "s": START, "e": END})
    from app.config import get_settings
    sent = []
    reporter = Reporter(get_settings().model_copy(update={"reports_dir": str(tmp_path), "smtp_host": "smtp.example"}),
                        mailer=lambda s, to, subj, body, files: sent.append((to, subj, [f.name for f in files])))
    assert await reporter.drain(now=AFTER) == 1
    with owner_engine.connect() as c:
        run = c.execute(text("SELECT status, pdf_path, xlsx_path, summary, email_status, error FROM report_runs")).one()
    assert run.status == "done", run.error
    pdf, xlsx = Path(run.pdf_path), Path(run.xlsx_path)
    assert pdf.read_bytes()[:5] == b"%PDF-" and pdf.stat().st_size > 5000
    assert pdf.name.startswith("1-monthly_bundle-2026-10-01")
    wb = load_workbook(xlsx)
    up = {r[0]: r for r in wb["Device uptime"].iter_rows(min_row=2, values_only=True)}
    assert up["NW-HK"][3] == 99.664 and up["NW-HK"][5] == 9000 and up["NW-HK"][6] == 3600
    vpn = list(wb["VPN uptime"].iter_rows(min_row=2, values_only=True))[0]
    assert vpn[3] == round((MONTH_S - 1500) / MONTH_S * 100, 3) and vpn[8] == 3
    assert len(list(wb["VPN downtime"].iter_rows(min_row=2))) == 4
    assert run.summary["vpn_drops"] == 3 and run.summary["device_availability_min"] == 99.664
    assert run.email_status == "sent" and sent[0][0] == ["noc@example.com"] and len(sent[0][2]) == 2


async def test_email_skipped_without_smtp(october, owner_engine, tmp_path):
    cid, *_ = october
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO report_runs (client_id, report_type, period_start, period_end, recipients) "
                       "VALUES (:c, 'vpn_uptime', :s, :e, ARRAY['x@example.com'])"), {"c": cid, "s": START, "e": END})
    from app.config import get_settings
    await Reporter(get_settings().model_copy(update={"reports_dir": str(tmp_path), "smtp_host": ""})).drain(now=AFTER)
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT email_status FROM report_runs")).scalar() == "not sent: SMTP is not configured"


async def test_schedule_creates_previous_month_once(october, owner_engine):
    cid, *_ = october
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO report_schedules (client_id, report_type, day_of_month, hour_local) VALUES (:c, 'monthly_bundle', 1, 6)"), {"c": cid})
    r = Reporter()
    assert await r.check_schedules(datetime(2026, 10, 31, 21, 0, tzinfo=UTC)) == 0   # 1 Nov 05:00 HKT: before 06:00
    assert await r.check_schedules(datetime(2026, 10, 31, 23, 0, tzinfo=UTC)) == 1   # 1 Nov 07:00 HKT
    assert await r.check_schedules(datetime(2026, 11, 2, 1, 0, tzinfo=UTC)) == 0     # already created
    with owner_engine.connect() as c:
        s, e = c.execute(text("SELECT period_start, period_end FROM report_runs")).one()
    assert (s, e) == (START, END)


async def test_reports_ui_request_download_and_scope(client, make_user, owner_engine, october, tmp_path, audit_rows):
    cid, *_ = october
    with owner_engine.begin() as c:
        other = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Other','other') RETURNING id")).scalar()
    viewer = make_user(role="client_readonly", username="viewer")
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO user_clients (user_id, client_id) VALUES (:u, :c)"), {"u": viewer["id"], "c": cid})
    await full_login(client, viewer)
    token = csrf_from((await client.get("/reports")).text)
    r = await client.post("/reports", data={"client_id": str(cid), "report_type": "vpn_uptime", "month": "2026-10", "csrf_token": token})
    assert r.status_code == 303
    assert (await client.post("/reports", data={"client_id": str(other), "report_type": "vpn_uptime", "month": "2026-10",
                                                "csrf_token": token})).status_code == 403
    assert (await client.post("/reports/schedules", data={"client_id": str(cid), "csrf_token": token})).status_code == 403
    from app.config import get_settings
    await Reporter(get_settings().model_copy(update={"reports_dir": "/tmp/reports"})).drain(now=AFTER)
    page = (await client.get("/reports")).text
    assert "VPN tunnel availability" in page and "/pdf" in page
    run_id = page.split('href="/reports/')[1].split("/")[0]
    pdf = await client.get(f"/reports/{run_id}/pdf")
    assert pdf.status_code == 200 and pdf.content[:5] == b"%PDF-"
    assert audit_rows("report_download")
    with owner_engine.begin() as c:  # a report of another client is invisible
        oid = c.execute(text("INSERT INTO report_runs (client_id, report_type, period_start, period_end, status, pdf_path) "
                             "VALUES (:c, 'vpn_uptime', :s, :e, 'done', '/tmp/reports/x.pdf') RETURNING id"),
                        {"c": other, "s": START, "e": END}).scalar()
    assert (await client.get(f"/reports/{oid}/pdf")).status_code == 404



async def test_staff_can_delete_report_and_files(client, make_user, owner_engine, october, tmp_path, audit_rows):
    from app.config import get_settings
    cid, gw, ap = october
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO report_runs (client_id, report_type, period_start, period_end, requested_by) "
                       "VALUES (:c, 'vpn_uptime', :s, :e, 'test')"), {"c": cid, "s": START, "e": END})
    await Reporter(get_settings().model_copy(update={"reports_dir": "/tmp/reports"})).drain(now=AFTER)
    with owner_engine.connect() as c:
        run = c.execute(text("SELECT id, pdf_path, xlsx_path FROM report_runs")).one()
    assert Path(run.pdf_path).exists()
    viewer = make_user(role="client_readonly", username="viewer")
    with owner_engine.begin() as c:
        c.execute(text("INSERT INTO user_clients (user_id, client_id) VALUES (:u, :c)"), {"u": viewer["id"], "c": cid})
    await full_login(client, viewer)
    page = (await client.get("/reports")).text
    assert f"/reports/{run.id}/delete" not in page                                        # client users cannot delete
    assert (await client.post(f"/reports/{run.id}/delete", data={"csrf_token": csrf_from(page)})).status_code == 403
    client.cookies.clear()
    await full_login(client, make_user(role="engineer", username="eng"))
    page = (await client.get("/reports")).text
    assert f"/reports/{run.id}/delete" in page
    r = await client.post(f"/reports/{run.id}/delete", data={"csrf_token": csrf_from(page)})
    assert r.status_code == 303
    assert not Path(run.pdf_path).exists() and not Path(run.xlsx_path).exists()
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM report_runs")).scalar() == 0
    assert audit_rows("report_delete")



async def test_request_report_by_calendar_range(client, make_user, owner_engine, october):  # noqa: F811
    """Date pickers: whole days in the client's time zone, both days included."""
    cid, *_ = october
    await full_login(client, make_user(role="engineer"))
    page = (await client.get("/reports")).text
    assert 'name="date_from"' in page and "Last month" in page and 'type="month"' not in page
    token = csrf_from(page)
    r = await client.post("/reports", data={"client_id": str(cid), "report_type": "vpn_sessions", "csrf_token": token,
                                            "date_from": "2026-10-05", "date_to": "2026-10-11"})
    assert r.status_code == 303
    with owner_engine.connect() as c:
        run = c.execute(text("SELECT period_start, period_end FROM report_runs ORDER BY id DESC LIMIT 1")).one()
    assert run.period_start == datetime(2026, 10, 4, 16, tzinfo=UTC) and run.period_end == datetime(2026, 10, 11, 16, tzinfo=UTC)
    bad = await client.post("/reports", data={"client_id": str(cid), "report_type": "vpn_sessions", "csrf_token": token,
                                              "date_from": "2026-10-11", "date_to": "2026-10-05"})
    assert bad.status_code == 400
