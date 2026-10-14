"""Syslog header parsing: RFC 3164 (BSD, with or without <PRI>) and RFC 5424.

Only the header is interpreted here; the message body is left to vendor modules."""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from app.parsers.model import ParseError

_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}

# "<30>Oct  6 16:29:01 HOST msg" and "Oct 06 16:35:08 HOST msg" (UniFi CEF has no PRI and a zero-padded day)
_RE_3164 = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<mon>[A-Z][a-z]{2}) (?P<day>[ 0-3]?\d) (?P<time>\d\d:\d\d:\d\d)(?:\.\d+)? (?P<host>\S+) ?(?P<msg>.*)$",
    re.S,
)
# "<PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG"
_RE_5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) "
    r"(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+) ?(?P<msg>.*)$",
    re.S,
)
# Log files on a UniFi console (syslog-ng file template): "2026-10-07T12:27:28+08:00 CTS-KL prog[pid]: msg"
_RE_ISO = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)) (?P<host>\S+) ?(?P<msg>.*)$", re.S)
# "prog[pid]: rest" or "prog: rest"
_RE_TAG = re.compile(r"^(?P<prog>[^\s\[\]:]{1,128})(?:\[(?P<pid>\d+)\])?: ?(?P<rest>.*)$", re.S)


@dataclass
class SyslogHeader:
    ts: datetime                 # UTC
    host: str | None
    msg: str                     # everything after the header (tag included for 3164)
    facility: int | None = None
    severity: int | None = None
    fmt: str = "rfc3164"
    app: str | None = None       # RFC 5424 APP-NAME
    procid: str | None = None
    msgid: str | None = None
    ts_from_device: bool = True
    meta: dict = field(default_factory=dict)  # vendor preprocess results (e.g. AP mac/model/firmware)


def _pri(value: str | None) -> tuple[int | None, int | None]:
    if value is None:
        return None, None
    p = int(value)
    if p > 191:
        raise ParseError(f"invalid PRI {p}")
    return p // 8, p % 8


def _bsd_time(mon: str, day: str, hms: str, tz: ZoneInfo, now: datetime) -> datetime:
    """RFC 3164 carries no year and no zone: use the device's (client's) time zone and pick the
    year that does not put the event more than a day in the future (handles Dec->Jan rollover)."""
    month = _MONTHS.get(mon)
    if month is None:
        raise ParseError(f"invalid month {mon!r}")
    h, m, s = (int(x) for x in hms.split(":"))
    local_now = now.astimezone(tz)
    for year in (local_now.year, local_now.year - 1):
        try:
            dt = datetime(year, month, int(day), h, m, s, tzinfo=tz)
        except ValueError as e:  # e.g. Feb 29 in a non-leap year
            if year == local_now.year:
                continue
            raise ParseError(f"invalid date: {e}") from e
        if dt <= local_now + timedelta(days=1):
            return dt.astimezone(UTC)
    raise ParseError("timestamp could not be placed in a year")


def parse_header(line: str, tz: str, now: datetime | None = None) -> SyslogHeader:
    now = now or datetime.now(UTC)
    m = _RE_5424.match(line)
    if m:
        fac, sev = _pri(m["pri"])
        ts_raw = m["ts"]
        if ts_raw == "-":
            ts, from_dev = now, False
        else:
            try:
                ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
            except ValueError as e:
                raise ParseError(f"invalid RFC5424 timestamp {ts_raw!r}") from e
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=ZoneInfo(tz))
            ts, from_dev = ts.astimezone(UTC), True
        nil = lambda v: None if v == "-" else v  # noqa: E731
        return SyslogHeader(ts=ts, host=nil(m["host"]), msg=m["msg"], facility=fac, severity=sev, fmt="rfc5424",
                            app=nil(m["app"]), procid=nil(m["procid"]), msgid=nil(m["msgid"]), ts_from_device=from_dev)
    m = _RE_ISO.match(line)
    if m:
        try:
            ts = datetime.fromisoformat(m["ts"].replace("Z", "+00:00")).astimezone(UTC)
        except ValueError as e:
            raise ParseError(f"invalid timestamp {m['ts']!r}") from e
        return SyslogHeader(ts=ts, host=m["host"], msg=m["msg"], fmt="file")
    m = _RE_3164.match(line)
    if m:
        fac, sev = _pri(m["pri"])
        ts = _bsd_time(m["mon"], m["day"].strip(), m["time"], ZoneInfo(tz), now)
        return SyslogHeader(ts=ts, host=m["host"], msg=m["msg"], facility=fac, severity=sev)
    raise ParseError("unrecognised syslog header")


def split_tag(msg: str) -> tuple[str | None, str | None, str]:
    """'prog[pid]: rest' -> (prog, pid, rest). Returns (None, None, msg) when there is no tag."""
    m = _RE_TAG.match(msg)
    if not m:
        return None, None, msg
    return m["prog"], m["pid"], m["rest"]
