import ipaddress
import re

_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:-]?)(?:[0-9a-fA-F]{2}\1){4}[0-9a-fA-F]{2}$")


def to_int(value) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def to_ip(value) -> str | None:
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip().strip("[]")))
    except ValueError:
        return None


def to_port(value) -> int | None:
    n = to_int(value)
    return n if n is not None and 0 <= n <= 65535 else None


def to_mac(value) -> str | None:
    """Normalise to lowercase colon form; accepts aa:bb.., aa-bb.., aabbcc5f5b62."""
    if value is None:
        return None
    v = str(value).strip()
    if not _MAC_RE.match(v):
        return None
    h = re.sub(r"[:-]", "", v).lower()
    return ":".join(h[i : i + 2] for i in range(0, 12, 2))


def clip(value, n: int = 2000) -> str | None:
    if value is None:
        return None
    s = str(value)
    return s if len(s) <= n else s[:n]
