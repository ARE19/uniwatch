"""Dashboard widget catalogue and layout validation.

A layout is a list of {"w": widget id, "size": "third" | "half" | "full", "cfg": {...}}, stored in dashboards.layout.
Layouts are always normalised on save and on render: unknown widgets, duplicates of single-use widgets, staff-only
widgets for client users and bad sizes are dropped or corrected, never trusted from the browser."""

from dataclasses import dataclass

SIZES = ("third", "half", "full")


@dataclass(frozen=True)
class Widget:
    id: str
    title: str
    description: str
    size: str = "half"
    staff_only: bool = False
    multi: bool = False          # may appear more than once (configured widgets)


CATALOGUE: tuple[Widget, ...] = (
    Widget("tiles", "Summary tiles", "Logs, events by severity, silent devices, VPN tunnels.", "full"),
    Widget("traffic", "Internet throughput", "Download and upload Mbps per WAN.", "half"),
    Widget("packets", "Internet packets", "Packets per second per WAN.", "half"),
    Widget("wan", "WAN & internet", "Status, uplink, latency and availability of every WAN link.", "full"),
    Widget("ipsec", "Site-to-site VPN", "IPsec tunnels as in UniFi: status, WAN, local IP, peer, uptime, drops.", "full"),
    Widget("health", "Device health", "CPU, memory, temperature, uptime and firmware per device.", "full"),
    Widget("receive", "Log receive monitor", "Log lines received over time, by device.", "full"),
    Widget("rates", "Insert rate vs receive rate", "Received, stored and parsed messages.", "half", staff_only=True),
    Widget("lag", "Insert lag time", "Delay between receiving and parsing a log line.", "half", staff_only=True),
    Widget("severity", "Events by severity", "Events over time, stacked by severity.", "half"),
    Widget("category", "Events by category", "Event count per category.", "half"),
    Widget("devices", "Log sources", "Every log source with its status and line count.", "full"),
    Widget("apps", "Top apps", "Applications by data volume (or DNS lookups).", "half"),
    Widget("sites", "Top websites", "Websites by data volume (or DNS lookups).", "half"),
    Widget("talkers", "Top devices by data", "Internal devices that used the most internet data.", "half"),
    Widget("threats", "Top threats (IDS/IPS)", "Most frequent IDS/IPS signatures.", "half"),
    Widget("changes", "Recent configuration changes", "Latest admin changes on the firewalls.", "half"),
    Widget("storage", "Log storage", "Disk used by raw logs and events.", "third", staff_only=True),
    Widget("search", "Saved search", "Count and trend of a saved Log View search, e.g. blocked connections.",
           "third", staff_only=True, multi=True),
)
BY_ID = {w.id: w for w in CATALOGUE}

DEFAULT_LAYOUT: list[dict] = [
    {"w": "tiles", "size": "full"}, {"w": "traffic", "size": "half"}, {"w": "packets", "size": "half"},
    {"w": "wan", "size": "full"}, {"w": "ipsec", "size": "full"}, {"w": "health", "size": "full"}, {"w": "receive", "size": "full"},
    {"w": "rates", "size": "half"}, {"w": "lag", "size": "half"}, {"w": "severity", "size": "half"},
    {"w": "category", "size": "half"}, {"w": "devices", "size": "full"}, {"w": "apps", "size": "half"},
    {"w": "threats", "size": "half"}, {"w": "changes", "size": "half"}, {"w": "storage", "size": "half"},
]
MAX_WIDGETS = 40


def normalise(layout, staff: bool, search_ids: set[int] | None = None) -> list[dict]:
    """Clean a layout. search_ids: saved searches the user may use (None = do not check, e.g. when rendering)."""
    out: list[dict] = []
    seen: set[str] = set()
    for item in layout if isinstance(layout, list) else []:
        if not isinstance(item, dict):
            continue
        w = BY_ID.get(item.get("w"))
        if w is None or (w.staff_only and not staff) or (not w.multi and w.id in seen):
            continue
        size = item.get("size") if item.get("size") in SIZES else w.size
        entry = {"w": w.id, "size": size}
        if w.id == "search":
            try:
                sid = int((item.get("cfg") or {}).get("search_id"))
            except (TypeError, ValueError):
                continue
            if search_ids is not None and sid not in search_ids:
                continue
            entry["cfg"] = {"search_id": sid}
        seen.add(w.id)
        out.append(entry)
        if len(out) >= MAX_WIDGETS:
            break
    return out
