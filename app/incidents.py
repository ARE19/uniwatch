"""Incident helpers shared by the web UI and the alert engine (auto-incident)."""

from sqlalchemy import text

STATUSES = ("new", "investigating", "resolved", "closed")


async def create_incident(s, client_id: int, title: str, severity: str, author: str, description: str = "",
                          alert_id: int | None = None) -> int:
    iid = (await s.execute(text("""
        INSERT INTO incidents (client_id, title, description, severity, created_by)
        VALUES (:c, :t, :d, :s, :a) RETURNING id"""),
        {"c": client_id, "t": title[:300], "d": description[:5000], "s": severity, "a": author})).scalar()
    await add_timeline(s, iid, author, "created", f"Incident created ({severity})" + (f" from alert #{alert_id}" if alert_id else ""))
    if alert_id is not None:
        await link_alert(s, iid, alert_id, author)
    return iid


async def add_timeline(s, incident_id: int, author: str | None, kind: str, body: str) -> None:
    await s.execute(text("INSERT INTO incident_timeline (incident_id, author, kind, text) VALUES (:i, :a, :k, :t)"),
                    {"i": incident_id, "a": author, "k": kind, "t": body[:5000]})
    await s.execute(text("UPDATE incidents SET updated_at = now() WHERE id = :i"), {"i": incident_id})


async def link_alert(s, incident_id: int, alert_id: int, author: str | None) -> bool:
    res = await s.execute(text("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (:i, :a) ON CONFLICT DO NOTHING"),
                          {"i": incident_id, "a": alert_id})
    if res.rowcount:
        title = (await s.execute(text("SELECT title FROM alerts WHERE id = :a"), {"a": alert_id})).scalar()
        await add_timeline(s, incident_id, author, "link", f"Linked alert #{alert_id}: {title}")
    return bool(res.rowcount)
