from app.parsers.vendors.base import VendorModule


class GenericModule(VendorModule):
    """Plain syslog / standard CEF with no vendor-specific knowledge."""

    name = "other"
