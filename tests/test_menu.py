"""Main menu: role-aware groups and the highlighted entry for tabs, defaults and deeper pages."""

from app.web import menu
from tests.conftest import full_login


def active(path, query=None, role="admin"):
    groups = menu.build(path, query or {}, role)
    hits = [(g.label, e.label) for g in groups for e in g.entries if e.active]
    assert len(hits) <= 1 and all(g.active == any(e.active for e in g.entries) for g in groups)
    return hits[0] if hits else None


def test_highlight_follows_tabs_and_defaults():
    assert active("/") == ("Dashboards", "Overview")
    assert active("/logs") == ("Log View", "All logs")
    assert active("/logs", {"type": "vpn", "q": "src:1.2.3.4"}) == ("Log View", "VPN")
    assert active("/logs/event/42") == ("Log View", "All logs")
    assert active("/insights") == ("Insights", "Websites & apps")              # the page's default view
    assert active("/insights", {"view": "countries", "range": "7d"}) == ("Insights", "Countries & map")
    assert active("/event-monitor", {"tab": "rules"}) == ("Incidents & Events", "Event handlers")
    assert active("/event-monitor/alerts/7") == ("Incidents & Events", "Alerts")
    assert active("/sources/maintenance") == ("Device Manager", "Maintenance windows")
    assert active("/sources/add", {"register": "10.0.0.1"}) == ("Device Manager", "Add device")
    assert active("/sources/raw", {"device_id": "3"}) == ("Device Manager", "Log sources")
    assert active("/devices", {"status": "offline"}) == ("Device Manager", "All devices")
    assert active("/vpn/user", {"name": "bob"}) == ("VPN Monitor", "IPsec tunnels")
    assert active("/ip/8.8.8.8") is None
    assert active("/cctv", {"kind": "recordings"}) == ("CCTV", "Access log")
    assert active("/site/12", {}) == ("Dashboards", "Site overview")


def test_roles():
    labels = lambda role: {g.label: [e.label for e in g.entries] for g in menu.build("/", {}, role)}  # noqa: E731
    admin, eng, client = labels("admin"), labels("engineer"), labels("client_readonly")
    assert "Clients" in admin["System Settings"] and eng["System Settings"] == ["Password"]
    assert "Log View" in eng and "Device Manager" in eng and "Global search" in eng
    assert set(client) == {"Dashboards", "Insights", "CCTV", "VPN Monitor", "Reports", "System Settings"}   # CCTV: own sites only


async def test_sidebar_renders(client, make_user):
    await full_login(client, make_user(role="engineer"))
    page = (await client.get("/logs?type=security")).text
    assert 'data-menu="logs" open data-active' in page
    assert 'class="side-item active" href="/logs?type=security" aria-current="page"' in page
    assert "/admin/users" not in page and 'href="/search"' in page
