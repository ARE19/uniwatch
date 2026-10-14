"""Log View filter model: query-string <-> validated filters <-> SQL WHERE (always bound parameters).

Besides the time range, device and log-type tab, the search box takes FortiAnalyzer-style field filters plus free text:
    srcip=192.168.1.0/24 dstport=80,443 app=YouTube action!=flow-blocked remote=*.microsoft.com sent>1000000 "tls error"
  field=value     equals (text: case-insensitive; * is a wildcard; a,b,c = any of them; IPs accept CIDR)
  field!=value    not equal / not in / not inside the CIDR
  field~value     contains (text fields)
  field>N, <, >=, <=   numeric fields (ports, bytes)
Words without a field search the message, rule/policy and event name (all words must match; quote a phrase)."""

import ipaddress
import re
import shlex
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from app.parsers.model import CATEGORIES, SEVERITIES

PRESETS = {"15m": timedelta(minutes=15), "1h": timedelta(hours=1), "24h": timedelta(hours=24),
           "7d": timedelta(days=7), "30d": timedelta(days=30)}
PRESET_LABELS = {"15m": "Last 15 minutes", "1h": "Last hour", "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days"}
FILTER_KEYS = ("range", "from", "to", "device", "category", "severity", "action", "ip", "user", "q", "type", "cols", "group")
# "Group by" choices (FortiAnalyzer-style): field -> label. Values are grouped with the field's own SQL expression.
GROUPABLE = {"srcip": "Source IP", "dstip": "Destination IP", "dstport": "Destination port", "srcname": "Source name",
             "user": "User", "app": "Application", "domain": "Website", "remote": "Remote name", "service": "Service",
             "action": "Action", "result": "Result", "policy": "Policy / rule", "device": "Device", "type": "Log type",
             "level": "Level", "srccountry": "Source country", "dstcountry": "Destination country", "proto": "Protocol",
             "network": "Network"}

# Log-type tabs (FortiAnalyzer: Traffic / Security / Event) -> categories.
LOGTYPES: dict[str, tuple[str, tuple[str, ...]]] = {
    "traffic": ("Traffic", ("traffic", "firewall")),
    "security": ("Security", ("ids", "dns")),
    "vpn": ("VPN", ("vpn",)),
    "system": ("System event", ("system", "config", "wifi", "auth", "dhcp", "other")),
}


@dataclass(frozen=True)
class Field:
    expr: str            # SQL with {a} for the events alias
    kind: str            # ip | int | text | either-ip | either-text
    label: str
    help: str = ""


# {a} = events alias. "either" kinds take a pair of expressions separated by "|".
FIELDS: dict[str, Field] = {
    "srcip": Field("{a}.src_ip", "ip", "Source IP", "IP or CIDR, e.g. 192.168.1.0/24"),
    "dstip": Field("{a}.dst_ip", "ip", "Destination IP", "IP or CIDR"),
    "ip": Field("{a}.src_ip|{a}.dst_ip", "either-ip", "Source or destination IP"),
    "srcport": Field("{a}.src_port", "int", "Source port"),
    "dstport": Field("{a}.dst_port", "int", "Destination port", "e.g. 443 or 80,443"),
    "proto": Field("{a}.protocol", "text", "Protocol", "tcp, udp, icmp"),
    "srcname": Field("{a}.extra->>'src_name'", "text", "Source device name", "e.g. PC34*"),
    "dstname": Field("{a}.extra->>'dst_name'", "text", "Destination name"),
    "srcmac": Field("{a}.src_mac::text", "text", "Source MAC"),
    "dstmac": Field("{a}.dst_mac::text", "text", "Destination MAC"),
    "user": Field("{a}.user_name", "text", "User"),
    "remote": Field("{a}.extra->>'fqdn'", "text", "Remote name (host name)", "e.g. *.youtube.com"),
    "domain": Field("{a}.extra->>'domain'", "text", "Website (registrable domain)", "e.g. youtube.com"),
    "app": Field("coalesce({a}.extra->>'app', CASE WHEN {a}.action IN ('flow', 'dns-query') THEN {a}.rule END)", "text",
                 "Application", "e.g. YouTube, \"Microsoft Teams\""),
    "appcat": Field("{a}.extra->>'app_category'", "text", "Application category", "e.g. \"Video streaming\""),
    "service": Field("{a}.extra->>'service'", "text", "Service", "HTTPS, DNS, …"),
    "action": Field("{a}.action", "text", "Action", "flow, flow-blocked, dns-query, …"),
    "result": Field("{a}.outcome", "text", "Result", "allowed, blocked, success, failure"),
    "policy": Field("{a}.rule", "text", "Policy / rule / signature"),
    "type": Field("{a}.category", "text", "Log type (category)", ", ".join(CATEGORIES)),
    "level": Field("{a}.severity", "text", "Level (severity)", ", ".join(SEVERITIES)),
    "device": Field("(SELECT d_.name FROM devices d_ WHERE d_.id = {a}.device_id)", "text", "Device (log source)"),
    "srccountry": Field("{a}.src_country", "text", "Source country", "two letters, e.g. CN"),
    "dstcountry": Field("{a}.dst_country", "text", "Destination country"),
    "country": Field("{a}.src_country|{a}.dst_country", "either-text", "Source or destination country"),
    "sent": Field("{a}.bytes_out", "int", "Bytes sent (upload)", "e.g. >1000000"),
    "rcvd": Field("{a}.bytes_in", "int", "Bytes received (download)"),
    "network": Field("{a}.interface", "text", "Network / interface", "e.g. \"Internet 2\""),
    "direction": Field("{a}.extra->>'direction'", "text", "Direction", "outgoing, incoming, local"),
    "process": Field("{a}.process", "text", "Process"),
    "msg": Field("{a}.message", "text", "Message"),
}
ALIASES = {"src": "srcip", "dst": "dstip", "sport": "srcport", "dport": "dstport", "port": "dstport", "protocol": "proto",
           "hostname": "srcname", "host": "srcname", "username": "user", "url": "remote", "fqdn": "remote", "site": "domain",
           "application": "app", "category": "type", "severity": "level", "rule": "policy", "outcome": "result",
           "interface": "network", "message": "msg"}
_TERM = re.compile(r"^([A-Za-z_]+)(!=|>=|<=|=|>|<|~)(.*)$", re.S)

# Columns: id -> (label, filter field used for "filter by this value", or None).
COLUMNS: dict[str, tuple[str, str | None]] = {
    "num": ("#", None), "ts": ("Date/Time", None), "client": ("Client", None), "device": ("Device", "device"),
    "level": ("Level", "level"), "type": ("Type", "type"), "action": ("Action", "action"),
    "src": ("Source", "srcip"), "srcname": ("Source name", "srcname"), "srcmac": ("Source MAC", "srcmac"),
    "user": ("User", "user"), "dst": ("Destination", "dstip"), "dstport": ("Dst port", "dstport"),
    "remote": ("Remote name", "remote"), "app": ("Application", "app"), "appcat": ("App category", "appcat"),
    "service": ("Service", "service"), "proto": ("Protocol", "proto"), "sent": ("Sent", None), "rcvd": ("Received", None),
    "policy": ("Policy / rule", "policy"), "network": ("Network", "network"), "process": ("Process", "process"),
    "msg": ("Message", None),
}
DEFAULT_COLS: dict[str, list[str]] = {
    "": ["num", "ts", "device", "level", "type", "action", "src", "dst", "user", "msg"],
    "traffic": ["num", "ts", "device", "srcname", "src", "dst", "remote", "app", "service", "sent", "rcvd", "action"],
    "security": ["num", "ts", "device", "level", "action", "src", "dst", "remote", "policy", "msg"],
    "vpn": ["num", "ts", "device", "level", "action", "user", "src", "dst", "msg"],
    "system": ["num", "ts", "device", "level", "type", "process", "msg"],
}


@dataclass
class Term:
    field: str
    op: str
    values: list[str]


@dataclass
class LogQuery:
    range: str = "1h"
    since: datetime | None = None
    until: datetime | None = None
    from_s: str = ""            # as typed (client local time), for re-rendering the form
    to_s: str = ""
    devices: list[int] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)
    action: str = ""
    ip: str = ""
    user: str = ""
    q: str = ""
    logtype: str = ""
    cols: list[str] = field(default_factory=list)   # chosen columns ([] = the tab's default)
    group: str = ""                                  # group results by this field (GROUPABLE)
    terms: list[Term] = field(default_factory=list)
    words: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @classmethod
    def from_params(cls, params, tz: str, now: datetime | None = None) -> "LogQuery":
        now = now or datetime.now(UTC)
        lq = cls()
        get = params.get
        getlist = getattr(params, "getlist", lambda k: [v for v in [params.get(k)] if v])
        lq.range = get("range") or "1h"
        lq.from_s, lq.to_s = (get("from") or "").strip(), (get("to") or "").strip()
        if lq.range == "custom" or lq.from_s:
            lq.range = "custom"
            lq.since = _local(lq.from_s, tz, lq.errors, "From")
            lq.until = _local(lq.to_s, tz, lq.errors, "To") if lq.to_s else None
            if lq.since is None:
                lq.since = now - PRESETS["1h"]
        else:
            lq.since = now - PRESETS.get(lq.range, PRESETS["1h"])
            if lq.range not in PRESETS:
                lq.range = "1h"
        lq.devices = [int(d) for d in getlist("device") if str(d).isdigit()]
        lq.categories = [c for c in getlist("category") if c in CATEGORIES]
        lq.severities = [s for s in getlist("severity") if s in SEVERITIES]
        lq.action = (get("action") or "").strip()[:64]
        lq.user = (get("user") or "").strip()[:200]
        lq.logtype = get("type") if get("type") in LOGTYPES else ""
        cols = [c for raw in getlist("cols") for c in str(raw).split(",")]
        lq.cols = list(dict.fromkeys(c for c in cols if c in COLUMNS))
        lq.group = get("group") if get("group") in GROUPABLE else ""
        lq.q = (get("q") or "").strip()[:1000]
        lq._parse_q()
        ip = (get("ip") or "").strip()
        if ip:
            try:
                lq.ip = str(ipaddress.ip_network(ip, strict=False)) if "/" in ip else str(ipaddress.ip_address(ip))
            except ValueError:
                lq.errors.append(f"'{ip}' is not an IP address or CIDR range.")
        return lq

    # ---- search box --------------------------------------------------------------------------
    def _parse_q(self) -> None:
        if not self.q:
            return
        try:
            tokens = shlex.split(self.q)
        except ValueError:   # an unmatched quote, e.g. "can't": plain words then
            tokens = self.q.split()
        for tok in tokens:
            m = _TERM.match(tok)
            if not m:
                self.words.append(tok)
                continue
            name, op, value = m.group(1).lower(), m.group(2), m.group(3).strip()
            name = ALIASES.get(name, name)
            f = FIELDS.get(name)
            if f is None:
                self.errors.append(f"Unknown field '{m.group(1)}'. Use ⊕ to see the fields you can filter on.")
                continue
            if value == "":
                self.errors.append(f"'{m.group(1)}{op}' needs a value.")
                continue
            values = [value] if name == "msg" or op == "~" else [v.strip() for v in value.split(",") if v.strip()]
            if f.kind in ("ip", "either-ip"):
                if op not in ("=", "!="):
                    self.errors.append(f"{f.label}: use = or != (CIDR ranges work, e.g. 10.0.0.0/8).")
                    continue
                try:
                    values = [str(ipaddress.ip_network(v, strict=False)) if "/" in v else str(ipaddress.ip_address(v))
                              for v in values]
                except ValueError:
                    self.errors.append(f"'{value}' is not an IP address or CIDR range.")
                    continue
            elif f.kind == "int":
                if op == "~" or not all(re.fullmatch(r"\d{1,15}", v) for v in values) or (op not in ("=", "!=") and len(values) > 1):
                    self.errors.append(f"{f.label} needs a whole number, e.g. {m.group(1)}=443 or {m.group(1)}>1000.")
                    continue
            elif op in (">", "<", ">=", "<="):
                self.errors.append(f"{f.label} is text: use =, != or ~ (contains).")
                continue
            self.terms.append(Term(name, op, values))

    def where(self, scope_ids: list[int], alias: str = "e") -> tuple[str, dict]:
        a = alias
        clauses = [f"{a}.client_id = ANY(:scope_ids)", f"{a}.ts >= :since"]
        p: dict = {"scope_ids": scope_ids, "since": self.since}
        if self.until:
            clauses.append(f"{a}.ts < :until")
            p["until"] = self.until
        if self.devices:
            clauses.append(f"{a}.device_id = ANY(:devices)")
            p["devices"] = self.devices
        if self.logtype:
            clauses.append(f"{a}.category = ANY(:logtype_cats)")
            p["logtype_cats"] = list(LOGTYPES[self.logtype][1])
        if self.categories:
            clauses.append(f"{a}.category = ANY(:categories)")
            p["categories"] = self.categories
        if self.severities:
            clauses.append(f"{a}.severity = ANY(:severities)")
            p["severities"] = self.severities
        if self.action:
            clauses.append(f"{a}.action = :action")
            p["action"] = self.action
        if self.ip:
            op = "<<=" if "/" in self.ip else "="
            clauses.append(f"({a}.src_ip {op} CAST(:ip AS inet) OR {a}.dst_ip {op} CAST(:ip AS inet))")
            p["ip"] = self.ip
        if self.user:
            clauses.append(f"{a}.user_name ILIKE :user")
            p["user"] = _like(self.user)
        for i, t in enumerate(self.terms):
            clauses.append(self._term_sql(t, f"t{i}", a, p))
        for i, w in enumerate(self.words):
            # Substring match on the message, rule and raw event name (time-bounded, scope-bounded).
            clauses.append(f"({a}.message ILIKE :w{i} OR {a}.rule ILIKE :w{i} OR {a}.event_name ILIKE :w{i})")
            p[f"w{i}"] = _like(w)
        return " AND ".join(clauses), p

    @staticmethod
    def _term_sql(t: Term, key: str, a: str, p: dict) -> str:
        f = FIELDS[t.field]
        exprs = [e.format(a=a) for e in f.expr.split("|")]
        parts = []
        for j, v in enumerate(t.values):
            k = f"{key}_{j}"
            for e in exprs:
                if f.kind in ("ip", "either-ip"):
                    parts.append(f"{e} <<= CAST(:{k} AS inet)" if "/" in v else f"{e} = CAST(:{k} AS inet)")
                    p[k] = v
                elif f.kind == "int":
                    parts.append(f"{e} {'=' if t.op in ('=', '!=') else t.op} :{k}")
                    p[k] = int(v)
                elif t.op == "~":
                    parts.append(f"{e} ILIKE :{k}")
                    p[k] = _like(v)
                elif "*" in v:
                    parts.append(f"{e} ILIKE :{k}")
                    p[k] = _wild(v)
                else:
                    parts.append(f"lower({e}) = lower(:{k})")
                    p[k] = v
        any_ = "(" + " OR ".join(parts) + ")"
        if t.op == "!=":
            # "not equal" also keeps rows where the field is empty
            return f"(NOT coalesce({any_}, false))"
        return any_

    # ---- presentation helpers -------------------------------------------------------------------
    def columns(self, raw: bool = False) -> list[str]:
        cols = self.cols or DEFAULT_COLS[self.logtype]
        if raw:
            cols = [c for c in cols if c != "msg"] + ["msg"]
        return cols

    def to_params(self) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        if self.logtype:
            out.append(("type", self.logtype))
        if self.range == "custom":
            out += [("range", "custom"), ("from", self.from_s)] + ([("to", self.to_s)] if self.to_s else [])
        else:
            out.append(("range", self.range))
        out += [("device", str(d)) for d in self.devices]
        out += [("category", c) for c in self.categories]
        out += [("severity", s) for s in self.severities]
        out += [(k, v) for k, v in (("action", self.action), ("ip", self.ip), ("user", self.user), ("q", self.q)) if v]
        if self.cols:
            out.append(("cols", ",".join(self.cols)))
        if self.group:
            out.append(("group", self.group))
        return out

    def group_expr(self, alias: str = "e") -> str:
        f = FIELDS[self.group]
        expr = f.expr.format(a=alias)
        return f"host({expr})" if f.kind == "ip" else f"CAST({expr} AS text)"

    def histogram_step(self, until: datetime) -> int:
        """Bucket size (seconds) for the timeline above the results: about 40-100 bars."""
        span = (until - self.since).total_seconds()
        for step in (60, 300, 900, 3600, 3 * 3600, 6 * 3600, 86400):
            if span / step <= 100:
                return step
        return 86400

    def qs(self, **override) -> str:
        params = [(k, v) for k, v in self.to_params() if k not in override]
        params += [(k, str(v)) for k, v in override.items() if v is not None]
        return urlencode(params)

    def legacy_filters(self) -> list[tuple[str, str, str]]:
        """Filters from older links / saved searches (not in the search box): (label, value, link without it)."""
        out = []
        for c in self.categories:
            out.append(("Category", c, self.qs(category=None) + "".join(f"&category={x}" for x in self.categories if x != c)))
        if self.severities:
            out.append(("Severity", ", ".join(self.severities), self.qs(severity=None)))
        for label, attr in (("Action", "action"), ("IP", "ip"), ("User", "user")):
            if getattr(self, attr):
                out.append((label, getattr(self, attr), self.qs(**{attr: None})))
        return out


def quote_value(v: str) -> str:
    """A value as it must be typed in the search box (quoted if it has spaces or quotes)."""
    return shlex.quote(v) if re.search(r"[\s'\",]", v) else v


def _like(s: str) -> str:
    return "%" + s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _wild(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_").replace("*", "%")


def _local(s: str, tz: str, errors: list[str], label: str) -> datetime | None:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        errors.append(f"{label} time is not valid.")
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo(tz))
    return dt.astimezone(UTC)
