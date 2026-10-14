"""ArcSight CEF:  CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension

- Header fields are split on unescaped '|'; '\\|' and '\\\\' are unescaped.
- Extension is space-separated key=value; values may contain spaces: a value runs until the next
  ' key=' begins. '\\=', '\\\\', '\\n', '\\r' are unescaped in values.
"""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.parsers.model import Event, ParseError
from app.parsers.util import clip, to_int, to_ip, to_mac, to_port

_KEY_RE = re.compile(r"(?:^|(?<=\s))([A-Za-z0-9_]+)=")
_VALUE_UNESCAPE = {"=": "=", "\\": "\\", "n": "\n", "r": "\r"}


@dataclass
class CefRecord:
    version: str
    vendor: str
    product: str
    device_version: str
    class_id: str
    name: str
    severity: str
    ext: dict[str, str] = field(default_factory=dict)


def _split_header(s: str) -> tuple[list[str], str]:
    fields, cur, i = [], [], 0
    while i < len(s) and len(fields) < 7:
        ch = s[i]
        if ch == "\\" and i + 1 < len(s) and s[i + 1] in "|\\":
            cur.append(s[i + 1])
            i += 2
            continue
        if ch == "|":
            fields.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    if len(fields) < 7:
        raise ParseError(f"CEF header has {len(fields)} of 7 '|'-separated fields")
    return fields, s[i:]


def _unescape_value(v: str) -> str:
    out, i = [], 0
    while i < len(v):
        if v[i] == "\\" and i + 1 < len(v) and v[i + 1] in _VALUE_UNESCAPE:
            out.append(_VALUE_UNESCAPE[v[i + 1]])
            i += 2
        else:
            out.append(v[i])
            i += 1
    return "".join(out)


def parse_extension(ext: str) -> dict[str, str]:
    keys = [m for m in _KEY_RE.finditer(ext) if not _is_escaped(ext, m.end() - 1)]
    out: dict[str, str] = {}
    for n, m in enumerate(keys):
        end = keys[n + 1].start() if n + 1 < len(keys) else len(ext)
        value = ext[m.end():end]
        # Exactly the separator before the next key is dropped; a value's own trailing spaces are not meaningful.
        out[m.group(1)] = _unescape_value(value.rstrip(" "))
    return out


def _is_escaped(s: str, idx: int) -> bool:
    """True if the character at idx is preceded by an odd number of backslashes."""
    n, j = 0, idx - 1
    while j >= 0 and s[j] == "\\":
        n, j = n + 1, j - 1
    return n % 2 == 1


def parse_cef(body: str) -> CefRecord:
    """body starts at 'CEF:'."""
    if not body.startswith("CEF:"):
        raise ParseError("not a CEF message")
    fields, ext = _split_header(body[4:])
    return CefRecord(*[f.strip() for f in fields], ext=parse_extension(ext.lstrip(" ")))


def _parse_rt(v: str) -> datetime | None:
    v = v.strip()
    if v.isdigit():
        n = int(v)
        return datetime.fromtimestamp(n / 1000 if n > 10**11 else n, UTC)
    for fmt in ("%b %d %Y %H:%M:%S", "%b %d %Y %H:%M:%S.%f"):
        try:
            return datetime.strptime(v, fmt).replace(tzinfo=UTC)
        except ValueError:
            pass
    return None


# Standard CEF keys -> Event fields. Anything else is kept in Event.extra.
def apply_common(ev: Event, ext: dict[str, str]) -> set[str]:
    """Map standard CEF keys onto the event. Returns the keys consumed."""
    used: set[str] = set()

    def take(key):
        if key in ext:
            used.add(key)
            return ext[key]
        return None

    ev.src_ip = to_ip(take("src")) or ev.src_ip
    ev.dst_ip = to_ip(take("dst")) or ev.dst_ip
    ev.src_port = to_port(take("spt")) or ev.src_port
    ev.dst_port = to_port(take("dpt")) or ev.dst_port
    if (p := take("proto")) is not None:
        ev.protocol = p.lower()
    if (a := take("act")) is not None:
        ev.action = a
    if (u := take("suser")) is not None:
        ev.user_name = u
    if (u := take("duser")) is not None:
        ev.extra["duser"] = u
        ev.user_name = ev.user_name or u
    if (rt := take("rt")) is not None and (t := _parse_rt(rt)):
        ev.ts = t
    ev.src_mac = to_mac(take("smac")) or ev.src_mac
    ev.dst_mac = to_mac(take("dmac")) or ev.dst_mac
    if (c := take("cnt")) is not None:
        ev.extra["count"] = to_int(c)
    if (b := take("in")) is not None:
        ev.bytes_in = to_int(b)
    if (b := take("out")) is not None:
        ev.bytes_out = to_int(b)
    if (msg := take("msg")) is not None:
        ev.message = clip(msg, 8000)
    if (o := take("outcome")) is not None:
        ev.outcome = o.lower()
    for k, name in (("request", "url"), ("app", "app"), ("cat", "cef_category"), ("deviceExternalId", "device_external_id")):
        if (v := take(k)) is not None:
            ev.extra[name] = v
    if (h := take("dvchost")) is not None:
        ev.host = h
    if (i := take("deviceInboundInterface")) is not None:
        ev.interface = i
    if (i := take("deviceOutboundInterface")) is not None:
        ev.extra["out_interface"] = i
    for n in range(1, 7):
        val, label = take(f"cs{n}"), take(f"cs{n}Label")
        if val is not None:
            ev.extra[label or f"cs{n}"] = val
    return used
