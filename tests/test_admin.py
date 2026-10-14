"""Role enforcement and admin user management."""

from tests.conftest import csrf_from, full_login, password_step


async def test_engineer_cannot_open_admin_pages(client, make_user):
    await full_login(client, make_user(role="engineer"))
    assert (await client.get("/admin/users")).status_code == 403
    assert (await client.get("/admin/audit")).status_code == 403


async def test_client_readonly_cannot_open_admin_pages(client, make_user):
    await full_login(client, make_user(role="client_readonly"))
    assert (await client.get("/admin/users")).status_code == 403


async def test_admin_creates_user_who_must_change_password(client, make_user, audit_rows):
    await full_login(client, make_user(username="root-admin", role="admin"))
    page = await client.get("/admin/users")
    assert page.status_code == 200
    token = csrf_from(page.text)
    r = await client.post("/admin/users", data={
        "username": "bob", "display_name": "Bob", "role_id": "2", "password": "Temporary-Pass-123", "csrf_token": token})
    assert r.status_code == 303
    assert "bob" in (await client.get("/admin/users")).text
    created = audit_rows("user_create")
    assert created and created[0]["username"] == "root-admin"

    # client_readonly without a client is refused
    r = await client.post("/admin/users", data={
        "username": "carol", "role_id": "3", "password": "Temporary-Pass-123", "csrf_token": token})
    assert r.status_code == 400 and "at least one client" in r.text


async def test_admin_post_without_csrf_is_rejected(client, make_user):
    await full_login(client, make_user(username="root-admin", role="admin"))
    r = await client.post("/admin/users", data={"username": "eve", "role_id": "1", "password": "Temporary-Pass-123"})
    assert r.status_code == 403


async def test_disabled_user_is_signed_out(client, make_user):
    admin = make_user(username="root-admin", role="admin")
    victim = make_user(username="dave")
    await full_login(client, admin)
    token = csrf_from((await client.get("/admin/users")).text)
    r = await client.post(f"/admin/users/{victim['id']}/active", data={"csrf_token": token})
    assert r.status_code == 303
    client.cookies.clear()
    assert (await password_step(client, "dave", victim["password"])).status_code == 401


async def test_audit_page_lists_events(client, make_user):
    await full_login(client, make_user(username="root-admin", role="admin"))
    r = await client.get("/admin/audit")
    assert r.status_code == 200 and "login" in r.text and "root-admin" in r.text



async def test_admin_deletes_user_but_not_self(client, make_user, owner_engine, audit_rows):
    from sqlalchemy import text
    from tests.conftest import csrf_from, full_login
    me = make_user(username="boss", role="admin")
    other = make_user(username="leaver", role="engineer")
    await full_login(client, me)
    page = (await client.get("/admin/users")).text
    token = csrf_from(page)
    assert f'/admin/users/{other["id"]}/delete' in page and f'/admin/users/{me["id"]}/delete' not in page
    r = await client.post(f"/admin/users/{other['id']}/delete", data={"csrf_token": token})
    assert r.status_code == 303
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM users WHERE username = 'leaver'")).scalar() == 0
    assert audit_rows("user_delete")[0]["details"]["role"] == "engineer"
    assert (await client.post(f"/admin/users/{me['id']}/delete", data={"csrf_token": token})).status_code == 400

