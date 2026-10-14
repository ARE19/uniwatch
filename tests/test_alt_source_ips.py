"""Dual-WAN firewalls: a device can have additional source IPs; the receiver maps them all to the same device."""

from sqlalchemy import text

from app.config import get_settings
from app.receiver.pipeline import Pipeline
from tests.conftest import csrf_from, full_login


async def test_additional_source_ips(client, make_user, owner_engine, audit_rows):
    with owner_engine.begin() as c:
        cid = c.execute(text("INSERT INTO clients (name, slug, timezone) VALUES ('CTS SG','cts-sg','Asia/Singapore') RETURNING id")).scalar()
        dev = c.execute(text("INSERT INTO devices (client_id, name, vendor, syslog_source_ip) VALUES (:c, 'CTS-SG', 'unifi', '11.31.33.170') "
                             "RETURNING id"), {"c": cid}).scalar()
        other = c.execute(text("INSERT INTO devices (client_id, name, vendor, syslog_source_ip) VALUES (:c, 'Other', 'unifi', '198.51.100.9') "
                               "RETURNING id"), {"c": cid}).scalar()
        c.execute(text("INSERT INTO unknown_sources (source_ip, first_seen, last_seen, count, sample) "
                       "VALUES ('11.145.54.44', now(), now(), 3, 'x')"))
    await full_login(client, make_user(role="engineer"))
    page = (await client.get("/sources")).text
    assert "11.145.54.44" in page                                      # listed as unknown sender
    token = csrf_from(page)
    r = await client.post(f"/sources/devices/{dev}/ips", data={"syslog_source_ip": "11.31.33.170",
                                                               "alt_source_ips": "11.145.54.44, 11.31.33.170", "csrf_token": token})
    assert r.status_code == 303
    with owner_engine.begin() as c:
        alts = c.execute(text("SELECT array(SELECT host(x) FROM unnest(alt_source_ips) x) FROM devices WHERE id = :d"), {"d": dev}).scalar()
        assert alts == ["11.145.54.44"]                                # the primary is not repeated
        assert c.execute(text("SELECT count(*) FROM unknown_sources")).scalar() == 0
    page = (await client.get("/sources")).text
    assert 'title="Additional source address">11.145.54.44' in page
    # an address can belong to only one device
    r = await client.post(f"/sources/devices/{other}/ips", data={"syslog_source_ip": "198.51.100.9",
                                                                 "alt_source_ips": "11.145.54.44", "csrf_token": token})
    assert r.status_code == 400 and "CTS-SG" in r.text
    assert (await client.post(f"/sources/devices/{dev}/ips", data={"syslog_source_ip": "nope", "csrf_token": token})).status_code == 400
    assert audit_rows("device_source_ips")

    p = Pipeline(get_settings())
    try:
        await p.refresh_devices()
    finally:
        await p._drop_conn()
    assert p.devices["11.31.33.170"].device_id == dev and p.devices["11.145.54.44"].device_id == dev
    assert p.devices["198.51.100.9"].device_id == other
