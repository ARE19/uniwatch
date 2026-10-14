"""Config backups: secrets redacted (a changed password still shows), only changed sections stored, object-level diff."""

import json

from sqlalchemy import text

from app.config import get_settings
from app.poller import config_backup as cb
from app.poller.service import Poller
from tests.conftest import full_login

# shapes as returned by the console (verified 2026-10-11), values shortened
WLAN = {"_id": "64af1", "name": "CTS-Staff", "enabled": True, "security": "wpapsk", "x_passphrase": "OldSecret123",
        "networkconf_id": "64ae0", "private_preshared_keys": [{"password": "ppsk1", "networkconf_id": "64ae0"}]}
NET = {"_id": "64ae0", "name": "Staff", "purpose": "corporate", "vlan": 10, "ip_subnet": "192.168.10.1/24",
       "x_ipsec_pre_shared_key": "psk-abc"}
POLICY = {"_id": "p1", "name": "Block Guest to LAN", "action": "BLOCK", "enabled": True, "hits": 10, "last_hit": 1791644520}
SETTING = {"_id": "s1", "key": "mgmt", "x_ssh_password": "rootpw", "advanced_feature_enabled": True}


def test_redact_normalize_and_diff():
    n = cb.normalize([WLAN])[0]
    assert n["x_passphrase"].startswith("redacted:") and "OldSecret123" not in json.dumps(n)
    assert n["private_preshared_keys"].startswith("redacted:") and "ppsk1" not in json.dumps(n)   # the whole list is secret
    s = cb.normalize([SETTING])[0]
    assert s["key"] == "mgmt" and s["x_ssh_password"].startswith("redacted:")        # "key" (section name) is not a secret
    p = cb.normalize([POLICY])[0]
    assert "hits" not in p and "last_hit" not in p                                   # hit counters change by themselves
    assert cb.digest(cb.normalize([{**POLICY, "hits": 99}])) == cb.digest(cb.normalize([POLICY]))
    new = cb.normalize([{**WLAN, "x_passphrase": "NewSecret456"}, {"_id": "64af2", "name": "CTS-Guest"}])
    changes = cb.diff(cb.normalize([WLAN]), new)
    assert {"change": "added", "object": "CTS-Guest"} in changes
    pw = next(c for c in changes if c["change"] == "changed")
    assert pw["object"] == "CTS-Staff" and pw["fields"][0]["field"] == "x_passphrase"
    assert pw["fields"][0]["after"].startswith("redacted:") and pw["fields"][0]["after"] != pw["fields"][0]["before"]
    assert cb.summarize("wlanconf", changes) == "Wi-Fi networks: 'CTS-Guest' added; 'CTS-Staff' changed: passphrase (secret)"


async def test_backup_job_stores_versions_and_pages(client, make_user, owner_engine):
    with owner_engine.begin() as c:
        cid = c.execute(text("INSERT INTO clients (name, slug) VALUES ('CTS KL','cts-kl') RETURNING id")).scalar()
        c.execute(text("INSERT INTO sitemanager_hosts (host_id, client_id, name, state, last_sync) VALUES ('h1', :c, 'CTS KL', 'connected', now())"),
                  {"c": cid})
    configs = [{"wlanconf": [WLAN], "networkconf": [NET], "firewall-policies": [POLICY]},
               {"wlanconf": [WLAN], "networkconf": [{**NET, "vlan": 20}], "firewall-policies": [{**POLICY, "hits": 50}]}]

    async def fetch(key, host):
        return configs.pop(0)
    p = Poller(get_settings().model_copy(update={"unifi_site_manager_api_key": "k"}), drivers={})
    conn = await p.connect()
    try:
        assert await p.config_backups(conn, force=True, fetch=fetch) == {"h1": 0}        # first backup: 3 sections, no changes
        assert await p.config_backups(conn, force=True, fetch=fetch) == {"h1": 1}        # only the network's VLAN changed
    finally:
        await conn.close()
    with owner_engine.connect() as c:
        rows = c.execute(text("SELECT section, summary, data::text FROM config_snapshots ORDER BY id")).all()
    assert [r.section for r in rows] == ["wlanconf", "networkconf", "firewall-policies", "networkconf"]
    assert rows[-1].summary == "Networks & VPN: 'Staff' changed: vlan"
    assert not any("OldSecret123" in r.data or "psk-abc" in r.data for r in rows)
    await full_login(client, make_user(role="engineer"))
    page = (await client.get("/config")).text
    assert "Networks &amp; VPN: &#39;Staff&#39; changed: vlan" in page and "CTS KL" in page
    sid = rows and (await client.get("/config")).text.split('/config/change/')[1].split('"')[0]
    detail = (await client.get(f"/config/change/{sid}")).text
    assert "<code>10</code>" in detail and "<code>20</code>" in detail
    dl = await client.get(f"/config/site/{cid}/backup.json")
    assert dl.status_code == 200 and "OldSecret123" not in dl.text and '"vlan": 20' in dl.text



async def test_full_backups_copied_encrypted_admin_download(client, make_user, owner_engine, tmp_path, audit_rows):
    """Local console: new auto-backup files are downloaded once, stored encrypted, newest N kept; only admins download."""
    from app.drivers.base import encrypt_secret
    from app.poller import fw_backup
    with owner_engine.begin() as c:
        cid = c.execute(text("INSERT INTO clients (name, slug) VALUES ('Northwind HK','nwhk') RETURNING id")).scalar()
        did = c.execute(text("""INSERT INTO devices (client_id, name, vendor, poll_config) VALUES (:c, 'NW-HK', 'unifi',
                               '{"driver": "unifi", "base_url": "https://192.168.1.1", "tls_fingerprint": "ab"}') RETURNING id"""),
                        {"c": cid}).scalar()
        c.execute(text("INSERT INTO device_credentials (device_id, secret_enc) VALUES (:d, :s)"),
                  {"d": did, "s": encrypt_secret({"api_key": "k"})})
    files = {f"autobackup_10.6.106_202609{d:02d}_1630_{d}.unf": f"UNF-{d}".encode() * 1000 for d in (1, 2, 3)}
    listed = [{"filename": n, "time": 1790000000000 + i * 86400000, "version": "10.6.106", "size": len(v)}
              for i, (n, v) in enumerate(files.items())]
    downloads = []

    async def lister(cfg, secret):
        assert secret == {"api_key": "k"}
        return listed

    async def downloader(cfg, secret, name):
        downloads.append(name)
        return files[name]
    p = Poller(get_settings().model_copy(update={"fw_backup_dir": str(tmp_path), "fw_backup_keep": 2,
                                                 "fw_backup_keep_days": 0}), drivers={})
    conn = await p.connect()
    try:
        assert await p.firewall_backups(conn, force=True, lister=lister, downloader=downloader) == {did: "2 new"}
        assert await p.firewall_backups(conn, force=True, lister=lister, downloader=downloader) == {did: "0 new"}
    finally:
        await conn.close()
    assert downloads == list(files)[1:]                                         # each file once, the oldest never
    p3 = Poller(get_settings().model_copy(update={"fw_backup_dir": str(tmp_path), "fw_backup_keep": 2,
                                                  "fw_backup_keep_days": 3650}), drivers={})
    conn = await p3.connect()
    try:      # with a 3-month (here: 10-year) retention the older file is kept as well
        assert await p3.firewall_backups(conn, force=True, lister=lister, downloader=downloader) == {did: "1 new"}
    finally:
        await conn.close()
    with owner_engine.begin() as c:
        assert c.execute(text("SELECT count(*) FROM firewall_backups")).scalar() == 3
        c.execute(text("DELETE FROM firewall_backups WHERE filename = :f"), {"f": list(files)[0]})
    with owner_engine.connect() as c:
        rows = c.execute(text("SELECT id, filename, path FROM firewall_backups ORDER BY taken_at")).all()
    assert [r.filename for r in rows] == list(files)[1:]                        # newest 2 kept
    raw = open(rows[-1].path, "rb").read()
    assert b"UNF-3" not in raw and fw_backup.decrypt(raw) == files[rows[-1].filename]   # encrypted at rest
    await full_login(client, make_user(role="engineer"))
    page = (await client.get("/config")).text
    assert "Full backups (restorable)" in page and "admins only" in page
    assert (await client.get(f"/config/full/{rows[-1].id}")).status_code == 403
    client.cookies.clear()
    await full_login(client, make_user(username="root-admin", role="admin"))
    r = await client.get(f"/config/full/{rows[-1].id}")
    assert r.status_code == 200 and r.content == files[rows[-1].filename] and audit_rows("firewall_backup_download")



def test_weekly_slot_sunday_0130_hong_kong():
    from datetime import UTC, datetime
    p = Poller(get_settings().model_copy(update={"fw_backup_weekly": "sun 01:30 Asia/Hong_Kong"}), drivers={})
    assert p._weekly_due(datetime(2026, 10, 10, 12, 0, tzinfo=UTC)) is False      # first look: remember the last slot
    assert p._weekly_due(datetime(2026, 10, 10, 17, 29, tzinfo=UTC)) is False     # Sun 11 Oct 01:29 HKT: not yet
    assert p._weekly_due(datetime(2026, 10, 10, 17, 31, tzinfo=UTC)) is True      # Sun 01:31 HKT: due
    assert p._weekly_due(datetime(2026, 10, 10, 18, 31, tzinfo=UTC)) is False     # once per week
    assert p._weekly_due(datetime(2026, 10, 17, 17, 30, tzinfo=UTC)) is True      # next Sunday 01:30 HKT
