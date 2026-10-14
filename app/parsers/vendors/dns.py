"""The project's own CoreDNS forwarder (dns/Corefile), delivered by Docker's syslog driver.

Built from real lines in samples/coredns-forwarder-2026-10-07.log:
  <30>1 2026-10-06T15:38:18.693202Z logserver coredns 1843 coredns - [INFO] 192.168.1.50 46158 udp A www.youtube.com. NOERROR 281 0.002321001s
  <30>1 2026-10-06T15:38:13.695741Z logserver coredns 1843 coredns - .:53 on 192.168.1.50          (startup)
The query format is set by our own Corefile:  {remote} {port} {proto} {type} {name} {rcode} {rsize} {duration}"""

import re

from app.intel.apps import classify
from app.parsers.model import Event
from app.parsers.util import to_int, to_ip, to_port
from app.parsers.vendors.base import VendorModule

_QUERY = re.compile(r"^\[INFO\] (?P<ip>\S+) (?P<port>\d+) (?P<proto>udp|tcp) (?P<qtype>\S+) (?P<name>\S+?)\.? "
                    r"(?P<rcode>[A-Z]+) (?P<size>\d+) (?P<dur>[\d.]+)s$")


class DnsForwarderModule(VendorModule):
    name = "dns"

    def syslog_fields(self, ev: Event, prog: str | None, rest: str) -> None:
        if prog != "coredns":
            return
        m = _QUERY.match(rest)
        if not m:
            return  # startup / error lines stay as system events
        site, app, category = classify(m["name"])
        ev.category, ev.action = "dns", "dns-query"
        ev.src_ip, ev.src_port, ev.protocol = to_ip(m["ip"]), to_port(m["port"]), m["proto"]
        ev.rule = app                       # top-apps aggregation key
        ev.outcome = "success" if m["rcode"] == "NOERROR" else None
        fqdn = m["name"].rstrip(".").lower()
        ev.extra.update({"fqdn": fqdn, "qtype": m["qtype"], "rcode": m["rcode"], "response_bytes": to_int(m["size"]),
                         "duration_ms": round(float(m["dur"]) * 1000, 2)})
        if site:
            ev.extra["domain"] = site       # top-sites aggregation key (registrable domain)
        if app:
            ev.extra["app"], ev.extra["app_category"] = app, category
        if site is None:
            ev.extra["local"] = True
        label = f" ({app})" if app else ""
        ev.message = f"{fqdn}{label} {m['qtype']} {m['rcode']}"
