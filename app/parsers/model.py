from dataclasses import dataclass, field
from datetime import datetime

# Normalised categories. The brief's set plus auth, dns and dhcp, which UniFi actually sends
# (admin access audit, CoreDNS ad-block JSON, dnsmasq DHCP) and which FortiView-style views need apart.
CATEGORIES = ("traffic", "firewall", "vpn", "config", "system", "wifi", "ids", "auth", "dns", "dhcp", "other")
SEVERITIES = ("low", "medium", "high", "critical")


class ParseError(Exception):
    """The line could not be understood at all. The raw line is kept with this message."""


@dataclass
class Event:
    ts: datetime
    vendor: str
    category: str = "other"
    severity: str = "low"
    severity_raw: str | None = None
    event_class: str = ""          # e.g. "cef:200", "syslog:hostapd"
    event_name: str | None = None  # human name, e.g. "Threat Detected"
    action: str | None = None
    outcome: str | None = None     # success | failure | blocked | allowed | unknown
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    src_mac: str | None = None
    dst_mac: str | None = None
    user_name: str | None = None
    rule: str | None = None
    interface: str | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None
    host: str | None = None
    process: str | None = None
    message: str | None = None
    extra: dict = field(default_factory=dict)
    # Filled by enrichment
    src_country: str | None = None
    dst_country: str | None = None
    src_asn: int | None = None
    dst_asn: int | None = None
    # Side records some events produce (written to their own tables by the worker)
    config_change: dict | None = None

    def __post_init__(self):
        assert self.category in CATEGORIES, self.category
        assert self.severity in SEVERITIES, self.severity
