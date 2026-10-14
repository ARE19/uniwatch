from app.parsers.vendors.base import VendorModule
from app.parsers.vendors.dns import DnsForwarderModule
from app.parsers.vendors.generic import GenericModule
from app.parsers.vendors.unifi import UnifiModule

# Device.vendor -> module. Vendors without a module (or "other") use the generic syslog/CEF parser.
MODULES: dict[str, VendorModule] = {
    "unifi": UnifiModule(),
    # FortiGate: no real samples yet, so no FortiGate-specific mapping is guessed. FortiOS "set format cef"
    # output is standard CEF and is normalised by the generic CEF mapping until a vendor module is built
    # from real lines (Phase 11, brief: "per my samples").
    "fortinet": GenericModule(),
    "dns": DnsForwarderModule(),   # our own CoreDNS forwarder (website/app visibility)
    "other": GenericModule(),
}


def module_for(vendor: str) -> VendorModule:
    return MODULES.get(vendor, MODULES["other"])
