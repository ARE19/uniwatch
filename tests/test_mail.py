"""Admin -> Mail (SMTP): settings saved in the web UI replace .env, password encrypted and never shown, test e-mail."""

from sqlalchemy import text

from tests.conftest import csrf_from, full_login


async def test_only_admins_open_mail_settings(client, make_user):
    await full_login(client, make_user(role="engineer"))
    assert (await client.get("/admin/mail")).status_code == 403


async def test_save_test_and_reset_mail_settings(client, make_user, owner_engine, audit_rows, monkeypatch):
    from app import mail
    from app.config import get_settings
    await full_login(client, make_user(username="root-admin", role="admin"))
    page = await client.get("/admin/mail")
    assert page.status_code == 200 and "Mail server" in page.text
    token = csrf_from(page.text)

    bad = await client.post("/admin/mail", data={"csrf_token": token, "host": "bad host!", "port": "587", "from_addr": "x"})
    assert bad.status_code == 400 and "SMTP server" in bad.text and "From:" in bad.text

    r = await client.post("/admin/mail", data={"csrf_token": token, "host": "smtp.office365.com", "port": "587",
                                               "username": "logserver@example.com", "password": "S3cret-pass!",
                                               "from_addr": "Uniwatch <logserver@example.com>", "starttls": "1",
                                               "subject_prefix": " Example MSP   Network Alert "})
    assert r.status_code == 303 and r.headers["location"] == "/admin/mail?saved=1"
    with owner_engine.connect() as c:
        row = c.execute(text("SELECT host, port, username, password_enc, starttls FROM mail_settings")).one()
    assert row.host == "smtp.office365.com" and row.port == 587 and row.starttls
    assert "S3cret" not in row.password_enc                                        # stored encrypted
    page = (await client.get("/admin/mail?saved=1")).text
    assert "S3cret" not in page and "set; leave empty to keep it" in page and "Mail settings saved" in page
    assert audit_rows("mail_settings_set")[0]["details"]["password"] == "changed"

    # services pick the saved settings over .env; saving again without a password keeps it
    async with __import__("app.db", fromlist=["x"]).sessionmaker()() as s:
        eff = await mail.effective(get_settings(), s)
    assert eff.smtp_host == "smtp.office365.com" and eff.smtp_user == "logserver@example.com" and eff.smtp_password == "S3cret-pass!"
    assert eff.alert_subject_prefix == "Example MSP Network Alert"
    await client.post("/admin/mail", data={"csrf_token": token, "host": "smtp.office365.com", "port": "587",
                                           "username": "logserver@example.com", "from_addr": "logserver@example.com",
                                           "starttls": "1"})
    async with __import__("app.db", fromlist=["x"]).sessionmaker()() as s:
        assert (await mail.effective(get_settings(), s)).smtp_password == "S3cret-pass!"

    sent = []
    monkeypatch.setattr(mail, "send_test", lambda st, to: sent.append((st.smtp_host, st.smtp_password, to)))
    r = await client.post("/admin/mail/test", data={"csrf_token": token, "to": "noc@example.com"})
    assert r.status_code == 200 and "Test e-mail to noc@example.com: sent" in r.text
    assert sent == [("smtp.office365.com", "S3cret-pass!", "noc@example.com")]

    def boom(st, to):
        raise ConnectionRefusedError("refused")
    monkeypatch.setattr(mail, "send_test", boom)
    r = await client.post("/admin/mail/test", data={"csrf_token": token, "to": "noc@example.com"})
    assert "failed: ConnectionRefusedError: refused" in r.text and audit_rows("mail_test")[-1]["success"] is False

    r = await client.post("/admin/mail/reset", data={"csrf_token": token})
    assert r.status_code == 303
    with owner_engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM mail_settings")).scalar() == 0


async def test_alert_email_uses_saved_mail_settings(owner_engine, monkeypatch):
    """deliver() reads the saved settings at send time (no restart needed)."""
    from app.alerts import engine as eng
    from app.config import get_settings
    from app.drivers.base import encrypt_secret
    with owner_engine.begin() as c:
        c.execute(text("""INSERT INTO mail_settings (host, port, username, password_enc, from_addr, starttls, subject_prefix)
                          VALUES ('relay.example.test', 2525, '', NULL, 'logs@example.test', false, 'Example MSP Network Alert')"""))
    used = {}
    monkeypatch.setattr(eng, "_send_email", lambda st, to, subject, body, html=None: used.update(host=st.smtp_host, port=st.smtp_port,
                                                                                               subject=subject))
    from datetime import UTC, datetime
    alert = {"id": 1, "title": "x", "message": "m", "severity": "high", "client": "Northwind HK", "first_seen": datetime.now(UTC)}
    status = await eng.deliver({"type": "email", "config_enc": encrypt_secret({"to": ["a@b.c"]})}, alert, "open",
                               get_settings().model_copy(update={"smtp_host": ""}))
    assert status == "sent" and used["host"] == "relay.example.test" and used["port"] == 2525
    assert used["subject"].startswith("Example MSP Network Alert: ")
