"""Login, TOTP MFA, sessions, CSRF, lockout, password change."""

import re

import pyotp

from app.security import passwords, totp
from app.security.sessions import COOKIE_NAME
from tests.conftest import STRONG_PW, csrf_from, full_login, password_step


async def test_login_page_renders(client):
    r = await client.get("/login")
    assert r.status_code == 200 and "Sign in" in r.text


async def test_anonymous_is_sent_to_login(client):
    r = await client.get("/")
    assert r.status_code == 303 and r.headers["location"] == "/login"


async def test_login_requires_prelogin_csrf(client, make_user):
    make_user()
    r = await client.post("/login", data={"username": "alice", "password": STRONG_PW, "csrf_token": "forged"})
    assert r.status_code == 403
    assert COOKIE_NAME not in client.cookies


async def test_wrong_password_and_unknown_user_look_the_same(client, make_user, audit_rows):
    make_user()
    r1 = await password_step(client, "alice", "wrong-password-123")
    r2 = await password_step(client, "nobody", "wrong-password-123")
    assert r1.status_code == r2.status_code == 401
    assert "Invalid username or password" in r1.text and "Invalid username or password" in r2.text
    reasons = [row["details"]["reason"] for row in audit_rows("login")]
    assert reasons == ["bad_password", "unknown_user"]


async def test_inactive_user_cannot_log_in(client, make_user):
    make_user(active=False)
    r = await password_step(client, "alice", STRONG_PW)
    assert r.status_code == 401


async def test_lockout_after_repeated_failures(client, make_user, audit_rows):
    make_user()
    for _ in range(10):
        assert (await password_step(client, "alice", "nope-nope-nope")).status_code == 401
    r = await password_step(client, "alice", STRONG_PW)  # correct password, still locked
    assert r.status_code == 429
    assert audit_rows("login_locked")


async def test_password_alone_does_not_grant_access(client, make_user):
    make_user()
    r = await password_step(client, "alice", STRONG_PW)
    assert r.status_code == 303 and r.headers["location"] == "/mfa"
    r = await client.get("/")
    assert r.status_code == 303 and r.headers["location"] == "/mfa"


async def test_first_login_enrols_totp(client, make_user, audit_rows):
    make_user(mfa=False)
    await password_step(client, "alice", STRONG_PW)
    page = await client.get("/mfa")
    assert "Set up two-factor" in page.text and "<svg" in page.text
    secret = re.search(r'id="totp-secret">([A-Z2-7]+)<', page.text).group(1)
    # Reloading keeps the same secret, so a scanned QR code stays valid.
    assert secret in (await client.get("/mfa")).text
    r = await client.post("/mfa", data={"code": pyotp.TOTP(secret).now(), "csrf_token": csrf_from(page.text)})
    assert r.status_code == 303 and r.headers["location"] == "/"
    home = await client.get("/")
    assert home.status_code == 200 and "Dashboard" in home.text
    assert audit_rows("mfa_enrolled")
    assert [r["details"]["stage"] for r in audit_rows("login")] == ["password", "mfa"]


async def test_session_token_rotates_after_mfa(client, make_user):
    user = make_user()
    await password_step(client, "alice", STRONG_PW)
    pre_mfa = client.cookies[COOKIE_NAME]
    page = await client.get("/mfa")
    await client.post("/mfa", data={"code": pyotp.TOTP(user["secret"]).now(), "csrf_token": csrf_from(page.text)})
    post_mfa = client.cookies[COOKIE_NAME]
    assert post_mfa != pre_mfa
    client.cookies.clear()
    # The pre-MFA token must be dead; the rotated one must work.
    r = await client.get("/", headers={"cookie": f"{COOKIE_NAME}={pre_mfa}"})
    assert r.status_code == 303 and r.headers["location"] == "/login"
    r = await client.get("/", headers={"cookie": f"{COOKIE_NAME}={post_mfa}"})
    assert r.status_code == 200


async def test_repeated_bad_codes_end_the_session(client, make_user, audit_rows):
    make_user()
    await password_step(client, "alice", STRONG_PW)
    page = await client.get("/mfa")
    token = csrf_from(page.text)
    for _ in range(4):
        assert (await client.post("/mfa", data={"code": "000000", "csrf_token": token})).status_code == 401
    r = await client.post("/mfa", data={"code": "000000", "csrf_token": token})
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert audit_rows("mfa_lockout")
    assert (await client.get("/mfa")).headers["location"] == "/login"


def test_totp_code_cannot_be_replayed():
    secret = pyotp.random_base32()
    now = 1_800_000_000.0
    code = pyotp.TOTP(secret).at(now)
    step = totp.verify_code(secret, code, None, now=now)
    assert step is not None
    assert totp.verify_code(secret, code, step, now=now) is None
    assert totp.verify_code(secret, "12345", None, now=now) is None


def test_totp_secret_encrypted_at_rest():
    enc = totp.encrypt_secret("JBSWY3DPEHPK3PXP")
    assert "JBSWY3DPEHPK3PXP" not in enc
    assert totp.decrypt_secret(enc) == "JBSWY3DPEHPK3PXP"
    assert totp.decrypt_secret("garbage") is None


def test_passwords_use_argon2id():
    h = passwords.hash_password("Some-Long-Password-1")
    assert h.startswith("$argon2id$")
    assert passwords.verify_password(h, "Some-Long-Password-1")
    assert not passwords.verify_password(h, "some-long-password-1")
    assert not passwords.verify_password(None, "anything")
    assert passwords.password_problems("short")


async def test_logout_requires_csrf_and_ends_session(client, make_user, audit_rows):
    user = make_user()
    await full_login(client, user)
    assert (await client.post("/logout", data={})).status_code == 403
    token = csrf_from((await client.get("/")).text)
    r = await client.post("/logout", data={"csrf_token": token})
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert (await client.get("/")).headers["location"] == "/login"
    assert audit_rows("logout")


async def test_forced_password_change(client, make_user, audit_rows):
    user = make_user(must_change=True)
    await full_login(client, user)
    r = await client.get("/")
    assert r.status_code == 303 and r.headers["location"] == "/account/password"
    token = csrf_from((await client.get("/account/password")).text)
    bad = await client.post("/account/password", data={
        "current_password": STRONG_PW, "new_password": "short", "confirm_password": "short", "csrf_token": token})
    assert bad.status_code == 400
    new_pw = "A-Brand-New-Passphrase-7"
    ok = await client.post("/account/password", data={
        "current_password": STRONG_PW, "new_password": new_pw, "confirm_password": new_pw, "csrf_token": token})
    assert ok.status_code == 200 and "Password changed" in ok.text
    assert (await client.get("/")).status_code == 200
    assert [r["success"] for r in audit_rows("password_change")] == [False, True]


async def test_mfa_page_has_no_app_shell(client, make_user):
    """Before the second factor there must be no menu or sign-out button competing with the code form."""
    make_user()
    await password_step(client, "alice", STRONG_PW)
    page = (await client.get("/mfa")).text
    assert 'action="/logout"' not in page and "Log sources" not in page and 'class="sidebar"' not in page
    assert page.count('type="submit"') == 1
