"""Health, database roles and privileges, time zone, security headers."""

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from app import db


async def test_healthz_reports_timescaledb(client):
    r = await client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["timescaledb"]


async def test_app_role_is_restricted():
    async with db.engine().connect() as c:
        row = (await c.execute(text(
            "SELECT rolsuper, rolbypassrls, rolcreaterole FROM pg_roles WHERE rolname = current_user"))).one()
    assert tuple(row) == (False, False, False)


async def test_sessions_run_in_utc():
    async with db.engine().connect() as c:
        assert (await c.execute(text("SHOW timezone"))).scalar() == "UTC"


async def test_audit_log_is_append_only(client, make_user):
    await client.get("/login")  # no-op, just ensures the app is importable
    async with db.engine().connect() as c:
        await c.execute(text("INSERT INTO audit_log (action) VALUES ('probe')"))
        with pytest.raises(ProgrammingError, match="permission denied"):
            await c.execute(text("UPDATE audit_log SET action = 'tampered'"))
        await c.rollback()
    async with db.engine().connect() as c:
        with pytest.raises(ProgrammingError, match="permission denied"):
            await c.execute(text("DELETE FROM audit_log"))
        await c.rollback()


async def test_roles_table_is_read_only_for_app():
    async with db.engine().connect() as c:
        with pytest.raises(ProgrammingError, match="permission denied"):
            await c.execute(text("INSERT INTO roles (id, name) VALUES (99, 'superadmin')"))
        await c.rollback()


async def test_security_headers_present(client):
    r = await client.get("/login")
    assert r.status_code == 200
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"


async def test_static_assets_served(client):
    assert (await client.get("/static/htmx.min.js")).status_code == 200
    assert (await client.get("/static/app.css")).status_code == 200
