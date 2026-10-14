"""UniFi traffic-flow records, collected by the poller from the controller API and stored one JSON object per raw line.

Source: POST /proxy/network/v2/api/site/<site>/traffic-flows (UniFi Network 10.6.106), verified against the NW-HK
controller; real records in samples/unifi-api-traffic-flows-2026-10-07.log. Fields used, as seen there:
  time (ms, always present), flow_start_time / flow_end_time / duration_milliseconds (absent on instant ad-block records),
  action allowed|blocked, direction outgoing|incoming|local, protocol, service, count, risk, id,
  source / destination: ip, port, mac, host_name, client_name, network_name, region, domains[], device_name
  in / out: network_name;  policies[]: type, internal_type, name
  traffic_data (absent on ad-block records): bytes_rx, bytes_tx, packets_rx, packets_tx
Byte direction, verified on a Windows Update HTTP download: bytes_tx = to the initiating device (download),
bytes_rx = from it (upload). Events keep bytes_in = download, bytes_out = upload of the source device."""

import json
from datetime import UTC, datetime

from app.intel.apps import classify
from app.parsers.model import Event, ParseError
from app.parsers.util import clip, to_int, to_ip, to_mac, to_port

EVENT_CLASS = "api:traffic-flow"


def _size(n: int | None) -> str:
    if n is None:
        return "-"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def parse_flow(raw: str, vendor: str) -> Event:
    try:
        r = json.loads(raw)
    except ValueError as e:
        raise ParseError(f"invalid traffic-flow JSON: {e}") from e
    if not isinstance(r, dict) or not isinstance(r.get("time"), int) or not isinstance(r.get("source"), dict):
        raise ParseError("not a UniFi traffic-flow record")
    s, d = r["source"], r.get("destination") or {}
    t = r.get("traffic_data") or {}
    blocked = r.get("action") == "blocked"
    policies = [p.get("name") or p.get("type") for p in r.get("policies") or [] if isinstance(p, dict)]
    named = [p for p in policies if p and p != "FIREWALL"]
    domains = [x.lower().rstrip(".") for x in d.get("domains") or [] if isinstance(x, str)]
    fqdn = domains[0] if domains else None
    site, app, category = classify(fqdn) if fqdn else (None, None, None)

    ev = Event(
        ts=datetime.fromtimestamp(r["time"] / 1000, UTC),
        vendor=vendor,
        category="firewall" if blocked else "traffic",
        event_class=EVENT_CLASS,
        event_name="Traffic flow blocked" if blocked else "Traffic flow",
        action="flow-blocked" if blocked else "flow",
        outcome="blocked" if blocked else "allowed",
        src_ip=to_ip(s.get("ip")), src_port=to_port(s.get("port")),
        dst_ip=to_ip(d.get("ip")), dst_port=to_port(d.get("port")),
        protocol=(r.get("protocol") or "").lower() or None,
        src_mac=to_mac(s.get("mac")), dst_mac=to_mac(d.get("mac")),
        # Allowed flows: the application (Websites & apps). Blocked: the policy that blocked it.
        rule=(named[0] if named else "Firewall") if blocked else app,
        interface=(r.get("out") or {}).get("network_name") or (r.get("in") or {}).get("network_name"),
        bytes_in=to_int(t.get("bytes_tx")), bytes_out=to_int(t.get("bytes_rx")),
    )
    x = ev.extra
    x["flow_id"] = r.get("id")
    for k in ("direction", "service", "risk"):
        if r.get(k):
            x[k] = r[k]
    if (r.get("count") or 1) > 1:
        x["count"] = r["count"]
    if fqdn:
        x["fqdn"] = fqdn
        if len(domains) > 1:
            x["domains"] = domains[:10]
    if site:
        x["domain"] = site
    if app:
        x["app"], x["app_category"] = app, category
    if s.get("host_name") or s.get("client_name"):
        x["src_name"] = s.get("host_name") or s.get("client_name")
    if d.get("host_name") or d.get("client_name") or d.get("device_name"):
        x["dst_name"] = d.get("host_name") or d.get("client_name") or d.get("device_name")
    if (r.get("in") or {}).get("network_name"):
        x["network_in"] = r["in"]["network_name"]
    if (r.get("out") or {}).get("network_name"):
        x["network_out"] = r["out"]["network_name"]
    if policies:
        x["policies"] = policies
    for k_out, k_in in (("packets_in", "packets_tx"), ("packets_out", "packets_rx")):
        if t.get(k_in) is not None:
            x[k_out] = to_int(t[k_in])
    if r.get("duration_milliseconds") is not None:
        x["duration_ms"] = to_int(r["duration_milliseconds"])
    if r.get("flow_start_time"):
        x["start"] = datetime.fromtimestamp(r["flow_start_time"] / 1000, UTC).isoformat()

    who = x.get("src_name") or ev.src_ip or "?"
    to = fqdn or x.get("dst_name") or ev.dst_ip or "?"
    label = f" ({app})" if app else ""
    port = f":{ev.dst_port}" if ev.dst_port else ""
    svc = r.get("service") or (ev.protocol or "").upper()
    verb = f"BLOCKED by {ev.rule}" if blocked else f"↓{_size(ev.bytes_in)} ↑{_size(ev.bytes_out)}"
    ev.message = clip(f"{who} → {to}{port}{label} {svc} {verb}", 1000)
    return ev


# ---- NetFlow/IPFIX (receiver-decoded, one JSON object per record; see app/receiver/ipfix.py) --------------------
NETFLOW_CLASS = "netflow:ipfix"
_PROTO = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 51: "ah", 58: "icmpv6", 132: "sctp"}
_END_REASON = {1: "idle timeout", 2: "active timeout", 3: "end of flow", 4: "forced end", 5: "lack of resources"}


def _scope(ip: str | None) -> str | None:
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except (TypeError, ValueError):
        return None
    return "internal" if (a.is_private or a.is_link_local) else "external" if a.is_global else "other"


def parse_netflow(raw: str, vendor: str) -> Event:
    try:
        r = json.loads(raw)
    except ValueError as e:
        raise ParseError(f"invalid NetFlow JSON: {e}") from e
    if not isinstance(r, dict) or r.get("nf") != 10 or not r.get("src") or not r.get("dst"):
        raise ParseError("not a NetFlow record")
    ms = r.get("end") or r.get("start")
    if not isinstance(ms, int):
        raise ParseError("NetFlow record without a timestamp")
    src_scope, dst_scope = _scope(r["src"]), _scope(r["dst"])
    direction = ("outgoing" if (src_scope, dst_scope) == ("internal", "external") else
                 "incoming" if (src_scope, dst_scope) == ("external", "internal") else
                 "local" if (src_scope, dst_scope) == ("internal", "internal") else "other")
    proto = _PROTO.get(r.get("proto"), str(r.get("proto")) if r.get("proto") is not None else None)
    ev = Event(
        ts=datetime.fromtimestamp(ms / 1000, UTC), vendor=vendor, category="traffic", event_class=NETFLOW_CLASS,
        event_name="NetFlow record", action="netflow",
        src_ip=to_ip(r["src"]), src_port=to_port(r.get("sport")), dst_ip=to_ip(r["dst"]), dst_port=to_port(r.get("dport")),
        protocol=proto, src_mac=to_mac(r.get("src_mac")), dst_mac=to_mac(r.get("dst_mac")),
        interface=str(r["out_if"]) if r.get("out_if") is not None else None,
        bytes_out=to_int(r.get("octets")),          # one record = one direction: bytes sent by the source
    )
    x = ev.extra
    x["direction"] = direction
    for k in ("packets", "in_if", "out_if", "vlan", "nexthop", "flags"):
        if r.get(k) not in (None, "", "0.0.0.0"):
            x[k] = r[k]
    if r.get("reason") in _END_REASON:
        x["end_reason"] = _END_REASON[r["reason"]]
    if isinstance(r.get("start"), int) and isinstance(r.get("end"), int):
        x["duration_ms"] = max(0, r["end"] - r["start"])
    port = f":{ev.dst_port}" if ev.dst_port else ""
    sport = f":{ev.src_port}" if ev.src_port else ""
    ev.message = clip(f"{ev.src_ip}{sport} → {ev.dst_ip}{port} {(proto or '').upper()} {_size(ev.bytes_out)} "
                      f"({x.get('packets', '?')} pkts, {direction})", 1000)
    return ev
