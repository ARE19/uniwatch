"""Vendor driver interface. Each vendor module turns a received line into one normalised Event.

The shared flow (syslog header -> CEF or tagged syslog -> vendor hooks) lives here; a vendor overrides
only the hooks, and only for line shapes seen in real samples (see samples/)."""

from datetime import datetime

from app.parsers import severity as sev
from app.parsers.cef import CefRecord, apply_common, parse_cef
from app.parsers.model import Event, ParseError
from app.parsers.syslog import SyslogHeader, parse_header, split_tag
from app.parsers.util import clip


class VendorModule:
    name = "other"
    cef_severity_numeric: dict | None = None  # override per vendor (brief: configurable)
    cef_severity_text: dict | None = None
    syslog_severity: dict | None = None

    def parse(self, raw: str, tz: str, now: datetime | None = None) -> Event:
        hdr = parse_header(raw, tz, now)
        body = self.preprocess(hdr)
        idx = body.find("CEF:")
        if idx != -1 and (idx == 0 or body[idx - 1] == " "):
            return self._from_cef(hdr, parse_cef(body[idx:]))
        return self._from_syslog(hdr, body)

    # ---- hooks -------------------------------------------------------------------
    def preprocess(self, hdr: SyslogHeader) -> str:
        """Strip vendor-specific prefixes from the message body. Default: none."""
        return hdr.msg

    def cef_vendor_fields(self, ev: Event, rec: CefRecord, remaining: dict[str, str]) -> set[str]:
        """Map vendor-specific CEF extension keys. Returns keys consumed."""
        return set()

    def syslog_fields(self, ev: Event, prog: str | None, rest: str) -> None:
        """Set category/action/fields from a tagged syslog message."""

    # ---- shared flow -------------------------------------------------------------
    def _from_cef(self, hdr: SyslogHeader, rec: CefRecord) -> Event:
        ev = Event(
            ts=hdr.ts,
            vendor=self.name,
            severity=sev.from_cef(rec.severity, self.cef_severity_numeric, self.cef_severity_text),
            severity_raw=rec.severity,
            event_class=f"cef:{rec.class_id}",
            event_name=rec.name,
            host=hdr.host,
            message=rec.name,
        )
        ev.extra["cef"] = {"vendor": rec.vendor, "product": rec.product, "version": rec.device_version}
        used = apply_common(ev, rec.ext)
        remaining = {k: v for k, v in rec.ext.items() if k not in used}
        used |= self.cef_vendor_fields(ev, rec, remaining)
        for k, v in rec.ext.items():
            if k not in used:
                ev.extra[k] = clip(v)
        return ev

    def _from_syslog(self, hdr: SyslogHeader, body: str) -> Event:
        if hdr.fmt == "rfc5424":
            prog, pid, rest = hdr.app, hdr.procid, body
        else:
            prog, pid, rest = split_tag(body)
        ev = Event(
            ts=hdr.ts,
            vendor=self.name,
            category="system" if prog else "other",
            severity=sev.from_syslog(hdr.severity, self.syslog_severity),
            severity_raw=sev.SYSLOG_NAMES[hdr.severity] if hdr.severity is not None else None,
            event_class=f"syslog:{prog}" if prog else "syslog",
            host=hdr.host,
            process=prog,
            message=clip(rest, 8000),
        )
        if pid:
            ev.extra["pid"] = pid
        if hdr.msgid:
            ev.extra["msgid"] = hdr.msgid
        self.syslog_fields(ev, prog, rest)
        return ev


__all__ = ["VendorModule", "ParseError"]
