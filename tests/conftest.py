"""Tests run in the `tests` compose service against the separate <DB_NAME>_test database.

The schema is rebuilt from the Alembic migrations once per run (downgrade base -> upgrade head), so
the migrations themselves are exercised. Tables are truncated between tests via the owner role;
the app under test connects as the restricted app role, exactly as in production."""

import json
import re

import pyotp
import pytest
from alembic import command
from alembic.config import Config
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session

from app.alerts.defaults import DEFAULT_RULES, LATER_RULES
from app.config import get_settings
from app.models import Role, User
from app.security import passwords, totp

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
STRONG_PW = "Correct-Horse-Battery-9"


@pytest.fixture(scope="session")
def owner_engine():
    s = get_settings()
    assert s.db_name.endswith("_test"), f"refusing to run tests against non-test database {s.db_name!r}"
    eng = create_engine(s.db_url(owner=True))
    cfg = Config("alembic.ini")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    # No background materialisation in the test DB: continuous aggregates then answer entirely in
    # real time, so truncating tables between tests can never leave stale aggregate rows behind.
    with eng.begin() as c:
        for view in ("raw_logs_1m", "events_5m", "events_src_1h", "events_dst_1h", "events_rule_1h", "events_web_1h",
                     "events_traffic_1h", "events_talkers_1h", "events_usage_1h"):
            c.execute(text(f"SELECT remove_continuous_aggregate_policy('{view}', if_exists => true)"))
    yield eng
    eng.dispose()


@pytest.fixture(autouse=True)
def no_saved_site_manager_key():
    """The Site Manager key a poller test put in effect must not reach the next test."""
    from app.drivers import unifi
    unifi.SITE_MANAGER_KEY = None
    yield
    unifi.SITE_MANAGER_KEY = None


@pytest.fixture(autouse=True)
def clean_db(owner_engine):
    with owner_engine.begin() as c:
        c.execute(text("TRUNCATE sitemanager_settings, firewall_backups, config_snapshots, companies, ap_metrics, protect_activity, protect_consoles, mail_settings, sitemanager_hosts, isp_metrics, user_dashboards, dashboards, wan_metrics, wan_state, forwarding_targets, ioc_networks, ioc_domains, incident_timeline, incident_events, incident_alerts, incidents, notifications, alerts, notification_channels, report_runs, report_schedules, device_credentials, device_inventory, network_clients, maintenance_windows, device_state, device_metrics, vpn_tunnel_state, vpn_tunnel_aliases, vpn_sessions, tracker_cursors, saved_searches, events, config_changes, ingest_stats, raw_logs, unknown_sources, devices, users, clients, user_clients, web_sessions, audit_log RESTART IDENTITY CASCADE"))
        # TRUNCATE ... CASCADE also empties alert_rules (FK to clients): restore the global defaults.
        c.execute(text("TRUNCATE alert_rules RESTART IDENTITY CASCADE"))
        for name, rtype, sev, params in DEFAULT_RULES + LATER_RULES:
            c.execute(text("INSERT INTO alert_rules (name, rule_type, severity, params) VALUES (:n, :t, :s, CAST(:p AS jsonb))"),
                      {"n": name, "t": rtype, "s": sev, "p": json.dumps(params)})
    yield


@pytest.fixture
async def client():
    from app.web.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="https://testserver") as c:
        yield c


@pytest.fixture
def make_user(owner_engine):
    def _make(username="alice", role="engineer", password=STRONG_PW, mfa=True, must_change=False, active=True):
        secret = pyotp.random_base32() if mfa else None
        with Session(owner_engine) as s:
            role_id = s.execute(select(Role.id).where(Role.name == role)).scalar_one()
            u = User(
                username=username,
                display_name=username.title(),
                password_hash=passwords.hash_password(password),
                role_id=role_id,
                must_change_password=must_change,
                is_active=active,
                totp_enabled=mfa,
                totp_secret_enc=totp.encrypt_secret(secret) if secret else None,
            )
            s.add(u)
            s.commit()
            return {"id": u.id, "username": username, "password": password, "secret": secret}

    return _make


def csrf_from(html: str) -> str:
    m = CSRF_RE.search(html)
    assert m, "no csrf token in page"
    return m.group(1)


async def password_step(client, username, password):
    page = await client.get("/login")
    return await client.post("/login", data={"username": username, "password": password, "csrf_token": csrf_from(page.text)})


async def full_login(client, user) -> None:
    r = await password_step(client, user["username"], user["password"])
    assert r.status_code == 303 and r.headers["location"] == "/mfa"
    page = await client.get("/mfa")
    r = await client.post("/mfa", data={"code": pyotp.TOTP(user["secret"]).now(), "csrf_token": csrf_from(page.text)})
    assert r.status_code == 303, r.text


@pytest.fixture
def audit_rows(owner_engine):
    def _rows(action=None):
        q = "SELECT action, success, username, details FROM audit_log"
        params = {}
        if action:
            q += " WHERE action = :a"
            params["a"] = action
        with owner_engine.connect() as c:
            return [dict(r._mapping) for r in c.execute(text(q + " ORDER BY id"), params)]

    return _rows
