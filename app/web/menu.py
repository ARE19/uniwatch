"""Main menu (FortiAnalyzer style): icon groups that fold open, role-aware, with the current page highlighted.

An entry may carry query parameters (Log View tabs, Insights views); the highlighted entry is the one whose path and
parameters match the request best. Deeper pages (an alert, an incident, one event) highlight their section's entry."""

from dataclasses import dataclass, field

ALL, STAFF, ADMIN = "all", "staff", "admin"

# What a page shows when the parameter is absent, so "/insights" highlights "Websites & apps".
DEFAULTS = {"/insights": {"view": "web"}, "/event-monitor": {"tab": "alerts"}, "/vpn": {"kind": "ipsec"}, "/logs": {"type": ""}}


@dataclass
class Entry:
    label: str
    path: str
    args: dict = field(default_factory=dict)
    role: str = ALL
    active: bool = False

    @property
    def href(self) -> str:
        q = "&".join(f"{k}={v}" for k, v in self.args.items() if v)
        return self.path + (f"?{q}" if q else "")


@dataclass
class Group:
    key: str
    label: str
    icon: str
    entries: list
    role: str = ALL
    active: bool = False


def _menu() -> list[Group]:
    return [
        Group("dash", "Dashboards", "dash", [
            Entry("Overview", "/"), Entry("Site overview", "/site"), Entry("Fleet", "/fleet"), Entry("NOC wall", "/wall")]),
        Group("devices", "Device Manager", "server", [
            Entry("All devices", "/devices"), Entry("Log sources", "/sources"), Entry("Add device", "/sources/add"),
            Entry("Config backups", "/config"), Entry("Maintenance windows", "/sources/maintenance")], role=STAFF),
        Group("view", "Insights", "chart", [
            Entry(label, "/insights", {"view": v}) for v, label in (
                ("usage", "Devices & usage"), ("web", "Websites & apps"), ("sources", "Top sources"), ("destinations", "Top destinations"),
                ("countries", "Countries & map"), ("threats", "Threats"), ("blocked", "Blocked & failed"),
                ("dns", "DNS filtering"), ("wifi", "WiFi"), ("admin", "Admin activity"), ("system", "System events"))]),
        Group("logs", "Log View", "list", [
            Entry("All logs", "/logs", {"type": ""}), Entry("Traffic", "/logs", {"type": "traffic"}),
            Entry("Security", "/logs", {"type": "security"}), Entry("VPN", "/logs", {"type": "vpn"}),
            Entry("System events", "/logs", {"type": "system"}), Entry("Config changes", "/logs/config-changes")], role=STAFF),
        Group("cctv", "CCTV", "camera", [Entry("Access log", "/cctv")]),
        Group("vpn", "VPN Monitor", "lock", [
            Entry("IPsec tunnels", "/vpn", {"kind": "ipsec"}), Entry("All interfaces", "/vpn", {"kind": "all"})]),
        Group("events", "Incidents & Events", "bell", [
            Entry("Alerts", "/event-monitor", {"tab": "alerts"}), Entry("Event handlers", "/event-monitor", {"tab": "rules"}),
            Entry("Notification channels", "/event-monitor", {"tab": "channels"}), Entry("Incidents", "/incidents"),
            Entry("Threat intel", "/threat-intel")], role=STAFF),
        Group("search", "Global search", "search", [Entry("Global search", "/search")], role=STAFF),
        Group("reports", "Reports", "report", [Entry("Reports", "/reports")]),
        Group("system", "System Settings", "gear", [
            Entry("Clients", "/admin/clients", role=ADMIN), Entry("Users", "/admin/users", role=ADMIN),
            Entry("Storage & forwarding", "/admin/storage", role=ADMIN), Entry("UniFi Site Manager", "/admin/site-manager", role=ADMIN), Entry("Mail (SMTP)", "/admin/mail", role=ADMIN),
            Entry("Report packs", "/admin/packs", role=ADMIN), Entry("Audit log", "/admin/audit", role=ADMIN),
            Entry("Password", "/account/password")]),
    ]


def _allowed(role: str, need: str) -> bool:
    return need == ALL or (need == STAFF and role in ("admin", "engineer")) or (need == ADMIN and role == "admin")


def build(path: str, query: dict, role: str) -> list[Group]:
    groups = []
    for g in _menu():
        if not _allowed(role, g.role):
            continue
        g.entries = [e for e in g.entries if _allowed(role, e.role)]
        if g.entries:
            groups.append(g)
    entries = [e for g in groups for e in g.entries]

    def score(e: Entry) -> int:
        if path == e.path:
            given = {**DEFAULTS.get(e.path, {}), **query}
            return 100 + len(e.args) if all(given.get(k, "") == v for k, v in e.args.items()) else -1
        if e.path != "/" and path.startswith(e.path + "/") and all(v == DEFAULTS.get(e.path, {}).get(k) for k, v in e.args.items()):
            return len(e.path)      # a page below this entry (e.g. one alert, one incident)
        return -1

    best = max(entries, key=score, default=None)
    if best is not None and score(best) >= 0:
        best.active = True
        for g in groups:
            g.active = best in g.entries
    return groups
