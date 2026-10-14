"""Report packs: signed pack + licence files add report types; anything unsigned, altered, mismatched or expired is refused."""

import base64
import json
from datetime import date

import pytest
from sqlalchemy import text
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import packs
from app.config import get_settings
from app.reports import data
from tests.conftest import csrf_from, full_login
from tests.test_reports import AFTER, END, START, october  # noqa: F401

SOURCE = '''
from app.reports import data as base

async def uptime_digest(db, client_id, start, end, now=None):
    return {"rows": [], "note": "digest of " + base.TITLES["device_uptime"]}

TITLES = {"uptime_digest": "Uptime digest", "device_uptime": "must not replace a built-in report"}
BUILDERS = {"uptime_digest": uptime_digest}
BUNDLES = {"digest_bundle": ("uptime_digest",)}
BUNDLE_TITLES = {"digest_bundle": "Digest pack"}
TYPE_LABELS = {"digest_bundle": "Digest pack (1 report)"}
'''


def public_of(key) -> str:
    from cryptography.hazmat.primitives import serialization
    return base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def sign(key, kind: str, content: dict) -> bytes:
    """A pack or licence file, exactly as scripts/make_pack.py writes it."""
    payload = json.dumps(content, sort_keys=True).encode()
    return json.dumps({"kind": kind, "payload": base64.b64encode(payload).decode(),
                       "signature": base64.b64encode(key.sign(packs.signed_message(kind, payload))).decode()}).encode()


@pytest.fixture
def publisher(tmp_path, monkeypatch):
    """A pack publisher's key, and this installation set up to accept that publisher's packs."""
    key = Ed25519PrivateKey.generate()
    monkeypatch.setattr(packs, "SETTINGS", get_settings().model_copy(update={"packs_dir": str(tmp_path / "packs"),
                                                                             "pack_public_key": public_of(key)}))
    packs.refresh()
    yield key
    monkeypatch.setattr(packs, "SETTINGS", get_settings().model_copy(update={"packs_dir": str(tmp_path / "none")}))
    packs.refresh()                                              # nothing of this test stays registered


def pack_file(key, pack_id="digest", source=SOURCE):
    return sign(key, "pack", {"id": pack_id, "name": "Digest pack", "version": "1.0", "description": "test", "source": source})


def licence_file(key, pack_id="digest", expires=None, customer="Example Ltd"):
    return sign(key, "licence", {"pack": pack_id, "customer": customer, "expires": expires, "issued": "2026-10-01"})


def test_pack_adds_report_types_and_licence_expiry_removes_them(publisher):
    assert "uptime_digest" not in data.report_types()
    done = packs.install(pack_file(publisher), licence_file(publisher, expires="2027-06-30"))
    assert done["pack"] == "digest" and sorted(done["stored"]) == ["digest.uwlic", "digest.uwpack"]
    types = data.report_types()
    assert types["digest_bundle"] == "Digest pack (1 report)" and types["uptime_digest"] == "Uptime digest"
    assert data.TITLES["device_uptime"] == "Device uptime and downtime"            # built-in types are never replaced
    assert list(types)[0] == "monthly_bundle"
    row = packs.status()[0]
    assert (row["name"], row["version"], row["customer"], row["expires"], row["problem"]) == \
        ("Digest pack", "1.0", "Example Ltd", "2027-06-30", None)

    packs.refresh(today=date(2027, 7, 1))                                          # the day after the last valid day
    assert "uptime_digest" not in data.BUILDERS and "digest_bundle" not in data.BUNDLES
    assert packs.status(date(2027, 7, 1))[0]["problem"] == "the licence expired on 2027-06-30"
    packs.refresh(today=date(2027, 6, 30))
    assert "uptime_digest" in data.BUILDERS

    assert packs.remove("digest") and packs.status() == [] and "uptime_digest" not in data.report_types()


def test_refused_files(publisher):
    other = Ed25519PrivateKey.generate()
    good_pack, good_lic = pack_file(publisher), licence_file(publisher)
    with pytest.raises(packs.PackError, match="not signed by"):
        packs.install(pack_file(other), licence_file(other))                       # someone else's packs
    tampered = json.loads(good_pack)
    payload = json.loads(base64.b64decode(tampered["payload"]))
    payload["source"] += "\nimport os\n"
    tampered["payload"] = base64.b64encode(json.dumps(payload, sort_keys=True).encode()).decode()
    with pytest.raises(packs.PackError, match="not signed by"):
        packs.install(json.dumps(tampered).encode(), good_lic)                     # code changed after signing
    with pytest.raises(packs.PackError, match="not a pack file"):
        packs.install(good_lic, good_lic)                                          # a licence passed off as a pack
    with pytest.raises(packs.PackError, match="another pack"):
        packs.install(good_pack, licence_file(publisher, pack_id="other"))
    with pytest.raises(packs.PackError, match="expired on 2020-01-01"):
        packs.install(good_pack, licence_file(publisher, expires="2020-01-01"))
    with pytest.raises(packs.PackError, match="not installed yet"):
        packs.install(None, good_lic)                                              # a licence alone, for a pack never uploaded
    with pytest.raises(packs.PackError, match="cannot be read"):
        packs.install(b"not json at all", good_lic)
    assert packs.status() == [] and packs.loaded() == set()

    packs.install(good_pack, None)                                                 # a pack without a licence stays unused
    assert packs.status()[0]["problem"] == "no licence file has been uploaded for this pack" and packs.loaded() == set()
    packs.install(None, good_lic)                                                  # ... until the licence arrives
    assert packs.loaded() == {"digest"}


async def test_report_of_a_missing_pack_fails_with_a_clear_message(publisher, october):  # noqa: F811
    from app import db
    cid, *_ = october
    async with db.sessionmaker()() as s:
        with pytest.raises(LookupError, match="needs a report pack"):
            await data.build(s, "digest_bundle", cid, START, END, AFTER)
        packs.install(pack_file(publisher), licence_file(publisher))
        r = await data.build(s, "digest_bundle", cid, START, END, AFTER)
    assert [x["title"] for x in r["sections"]] == ["Uptime digest"] and r["sections"][0]["note"].startswith("digest of Device uptime")


async def test_admin_page_upload_and_remove(client, make_user, publisher, audit_rows):
    await full_login(client, make_user(role="engineer"))
    assert (await client.get("/admin/packs")).status_code == 403
    client.cookies.clear()
    await full_login(client, make_user(username="root-admin", role="admin"))
    page = (await client.get("/admin/packs")).text
    assert "No report packs are installed" in page and 'name="licence"' in page
    token = csrf_from(page)
    files = {"pack": ("digest.uwpack", pack_file(publisher)), "licence": ("digest.uwlic", licence_file(publisher))}
    bad = await client.post("/admin/packs", data={"csrf_token": token},
                            files={"pack": ("x.uwpack", pack_file(Ed25519PrivateKey.generate()))})
    assert bad.status_code == 400 and "not signed by" in bad.text
    r = await client.post("/admin/packs", data={"csrf_token": token}, files=files)
    assert r.status_code == 303 and r.headers["location"] == "/admin/packs?installed=digest"
    page = (await client.get("/admin/packs?installed=digest")).text
    assert "Digest pack" in page and "Example Ltd" in page and "● in use" in page
    assert "Digest pack (1 report)" in (await client.get("/reports")).text          # can be requested now
    r = await client.post("/admin/packs/digest/remove", data={"csrf_token": token})
    assert r.status_code == 303 and "Digest pack (1 report)" not in (await client.get("/reports")).text
    assert audit_rows("pack_install")[0]["success"] is False and audit_rows("pack_install")[1]["details"]["customer"] == "Example Ltd"
    assert audit_rows("pack_remove")


async def test_trial_licence_edition_and_expiry_reminder(client, make_user, publisher):
    """A trial: a pack licence with an end date. Admins are reminded on every page before it ends."""
    from datetime import UTC, datetime, timedelta
    today = datetime.now(UTC).date()
    ends = (today + timedelta(days=12)).isoformat()
    trial = {"customer": "Example Ltd", "expires": ends, "issued": (today - timedelta(days=300)).isoformat(), "edition": "Trial"}
    packs.install(pack_file(publisher), sign(publisher, "licence", {**trial, "pack": "digest"}))
    assert packs.status()[0]["edition"] == "Trial"
    assert packs.expiry_notices() == [f"Digest pack ends in 12 days ({ends})."]
    assert packs.expiry_notices(today - timedelta(days=30)) == []                 # more than 30 days to go: quiet
    assert packs._remind_from(today.isoformat(), today + timedelta(days=30)) == 7  # a 30-day trial: only its last week
    after = today + timedelta(days=13)
    assert packs.expiry_notices(after) == [f"Digest pack ended on {ends}: its reports are no longer available."]

    await full_login(client, make_user(username="root-admin", role="admin"))
    page = (await client.get("/admin/packs")).text
    assert "(Trial)" in page and "Example Ltd" in page
    assert f"Digest pack ends in 12 days ({ends})." in (await client.get("/reports")).text       # on every page for admins
    client.cookies.clear()
    await full_login(client, make_user(role="engineer"))
    assert "Digest pack ends" not in (await client.get("/reports")).text
