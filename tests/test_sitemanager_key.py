"""System Settings -> UniFi Site Manager: the API key saved in the portal (encrypted, never shown) replaces the one from
.env, the poller picks it up on its next cycle, and "Test connection" reports what Site Manager answers."""

import httpx
from sqlalchemy import text

from app import sitemanager_key
from app.config import get_settings
from app.drivers import unifi
from app.poller.service import Poller
from tests.conftest import csrf_from, full_login

KEY = "AbCdEf0123456789-test_key.value"


async def test_only_admins_open_the_page(client, make_user):
    await full_login(client, make_user(role="engineer"))
    assert (await client.get("/admin/site-manager")).status_code == 403


async def test_save_test_and_remove_the_key(client, make_user, owner_engine, audit_rows, monkeypatch):
    from app.web import routes_sitemanager
    no_env_key = get_settings().model_copy(update={"unifi_site_manager_api_key": ""})
    monkeypatch.setattr(routes_sitemanager, "get_settings", lambda: no_env_key)      # as on a fresh installation
    await full_login(client, make_user(username="root-admin", role="admin"))
    page = await client.get("/admin/site-manager")
    assert page.status_code == 200 and "No key is set" in page.text and "Test connection" not in page.text
    token = csrf_from(page.text)

    bad = await client.post("/admin/site-manager", data={"csrf_token": token, "api_key": "has spaces in it"})
    assert bad.status_code == 400 and "paste the key exactly" in bad.text
    r = await client.post("/admin/site-manager", data={"csrf_token": token, "api_key": f"  {KEY}\n"})
    assert r.status_code == 303 and r.headers["location"] == "/admin/site-manager?saved=1"
    with owner_engine.connect() as c:
        enc = c.execute(text("SELECT api_key_enc FROM sitemanager_settings")).scalar()
    assert KEY not in enc and sitemanager_key.decode(enc) == KEY                    # stored encrypted
    page = (await client.get("/admin/site-manager?saved=1")).text
    assert KEY not in page and "A key is saved here (by root-admin" in page and "API key saved" in page
    assert audit_rows("sitemanager_key_set")[0]["details"] == {"key": "changed"}    # the key is never in the audit log

    seen = []

    async def three(key, transport=None):
        seen.append(key)
        return 3
    monkeypatch.setattr(sitemanager_key, "count_consoles", three)
    r = await client.post("/admin/site-manager/test", data={"csrf_token": token})
    assert r.status_code == 200 and "connected: the key can see 3 consoles" in r.text and seen == [KEY]

    async def rejected(key, transport=None):
        req = httpx.Request("GET", "https://api.ui.com/v1/hosts")
        raise httpx.HTTPStatusError("401", request=req, response=httpx.Response(401, request=req))
    monkeypatch.setattr(sitemanager_key, "count_consoles", rejected)
    r = await client.post("/admin/site-manager/test", data={"csrf_token": token})
    assert "failed: Site Manager rejected the key (HTTP 401)" in r.text and audit_rows("sitemanager_key_test")[-1]["success"] is False

    r = await client.post("/admin/site-manager/remove", data={"csrf_token": token})
    assert r.status_code == 303
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM sitemanager_settings")).scalar() == 0
    assert audit_rows("sitemanager_key_remove")


async def test_count_consoles_follows_pages():
    calls = []

    def handler(request):
        calls.append((request.url.path, request.headers.get("x-api-key"), request.url.params.get("nextToken")))
        first = request.url.params.get("nextToken") is None
        return httpx.Response(200, json={"data": [{}, {}] if first else [{}], **({"nextToken": "t2"} if first else {})})
    assert await sitemanager_key.count_consoles(KEY, transport=httpx.MockTransport(handler)) == 3
    assert calls == [("/v1/hosts", KEY, None), ("/v1/hosts", KEY, "t2")]


async def test_poller_uses_the_saved_key_and_falls_back_to_env(owner_engine):
    p = Poller(get_settings().model_copy(update={"unifi_site_manager_api_key": "env-key-0123456789"}), drivers={})
    conn = await p.connect()
    try:
        await p.refresh_site_manager_key(conn)
        assert p.s.unifi_site_manager_api_key == "env-key-0123456789" and unifi.SITE_MANAGER_KEY == "env-key-0123456789"
        with owner_engine.begin() as c:
            c.execute(text("INSERT INTO sitemanager_settings (id, api_key_enc) VALUES (1, :k)"), {"k": sitemanager_key.encode(KEY)})
        p._sm_last = 123.0
        await p.refresh_site_manager_key(conn)
        assert p.s.unifi_site_manager_api_key == KEY and unifi.SITE_MANAGER_KEY == KEY and p._sm_last == 0.0   # syncs at once
        with owner_engine.begin() as c:
            c.execute(text("DELETE FROM sitemanager_settings"))
        await p.refresh_site_manager_key(conn)
        assert p.s.unifi_site_manager_api_key == "env-key-0123456789"                 # removed in the portal: .env again
    finally:
        await conn.close()
