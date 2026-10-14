"""UniFi (UDM gateways, U6 access points), UniFi Network 10.6.x.

Built ONLY from real lines in samples/ (exported 2026-10-06 from NW-HK). Shapes not seen there fall
through to generic handling (category system/other, message kept) rather than being guessed at.

Header quirks seen:
- UDM repeats its hostname:            "<30>Oct  6 16:29:12 NW-HK NW-HK dbus-daemon[1782]: ..."
- APs prefix MAC,MODEL-FIRMWARE:       "<30>Oct  6 ... NWHKWAP-01 d021f91438b5,U6-Lite-6.7.57+15670: blebrd[4659]: ..."
  sometimes followed by "mcad: ", "stahtd: " or ": " before the real tag.
- CEF lines carry no <PRI>:            "Oct 06 16:35:08 NW-HK CEF:0|Ubiquiti|UniFi Network|10.6.106|544|..."
"""

import json
import re
from datetime import datetime

from app.parsers.cef import CefRecord
from app.parsers.model import Event
from app.parsers.syslog import SyslogHeader
from app.parsers.util import clip, to_int, to_ip, to_mac, to_port
from app.parsers.vendors.base import VendorModule
from app.parsers.vendors.unifi_flow import parse_flow, parse_netflow

# Firmware split must be greedy on the model ("USW-48-PoE-7.5.10" -> model USW-48-PoE, fw 7.5.10).
_AP_PREFIX = re.compile(r"^(?P<mac>[0-9a-f]{12}),(?P<model>.+)-(?P<fw>\d[^:\s]*): (?:[\w.-]*: (?=\S+\[\d+\]: )|: )?")

# CEF class -> (category, action)
_CEF_CLASSES = {
    "200": ("ids", "ids-detect"),
    "400": ("wifi", "wifi-connect"),
    "401": ("wifi", "wifi-disconnect"),
    "402": ("wifi", "wifi-roam"),
    "544": ("auth", "admin-access"),
    "546": ("config", "config-change"),
    "520": ("vpn", None),           # VPN Client Connected    (actions set below from the VPN type)
    "521": ("vpn", None),           # VPN Client Disconnected
}
_CEF_CATEGORY_FALLBACK = {"Security": "ids", "Client Devices": "wifi", "Audit": "config", "VPN": "vpn"}
_DURATION = re.compile(r"(?:(?P<d>\d+)d)?\s*(?:(?P<h>\d+)h)?\s*(?:(?P<m>\d+)m)?\s*(?:(?P<s>\d+)s)?$")
_SIZE = re.compile(r"^(?P<n>[\d.]+)\s*(?P<u>B|KB|MB|GB|TB)$")


def _duration_s(v: str | None) -> int | None:
    """'2m 7s' -> 127 (format from the real CEF 521 sample)."""
    m = _DURATION.match((v or "").strip())
    if not v or not m or not any(m.groupdict().values()):
        return None
    return sum(int(m[k] or 0) * f for k, f in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)))


def _size_bytes(v: str | None) -> int | None:
    """'51.54 KB' -> bytes. UniFi does not say whether KB is 1000 or 1024; 1024 is assumed (as its UI shows)."""
    m = _SIZE.match((v or "").strip())
    if not m:
        return None
    return int(float(m["n"]) * 1024 ** ("B", "KB", "MB", "GB", "TB").index(m["u"]))

_HOSTAPD = re.compile(r"^(?P<iface>\S+): STA (?P<mac>[0-9a-f:]{17}) (?P<what>.+)$")
_HOSTAPD_ACTIONS = {"IEEE 802.11: associated": "wifi-associate", "IEEE 802.11: disassociated": "wifi-disassociate"}
_WEVENT = re.compile(r"EVENT_STA_(?P<kind>JOIN|LEAVE|IP) (?P<iface>\S+): (?P<mac>[0-9a-f:]{17}) / (?P<arg>\S+)")
_STAHTD = re.compile(r"stahtd_dump_event\(\): (?P<json>\{.*\})\s*$")
_DHCP = re.compile(r"^DHCP(?P<kind>[A-Z]+)\((?P<iface>[^)]+)\) (?:(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) )?(?P<mac>[0-9a-f:]{17})(?: (?P<name>\S.*))?$")
_OVPN_PEER = re.compile(r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+) (?P<rest>.*)$")
_OVPN_TCP = re.compile(r"TCP connection established with \[AF_INET\](?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+)")
_OVPN_SIG = re.compile(r"^SIGUSR1\[soft,(?P<reason>[^\]]+)\] received, client-instance restarting")
_EVT_VPN = re.compile(r"Signal-EVT_VPN-\d+: EVT_VPN_(?P<name>\w+)(?: (?P<rest>.*))?$")
# "server 11.124.200.216:1194 (via tunovpnc1 192.168.200.1/24) on /vpn/openvpn/raws/1" or "server on /vpn/openvpn/raws/1"
_EVT_DETAIL = re.compile(r"^server(?: (?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d+))?"
                         r"(?: \(via (?P<iface>\S+) (?P<addr>[\d./]+)\))?(?: on (?P<path>\S+))?")
# Real lines from CTS KL's /var/log (samples/udm-cts-kl-files-2026-10-07.log):
_WG_PEER = re.compile(r"^wireguard: Server Wireguard Peer \(#\d+\) has got peer (?P<key>\S+) (?P<ip>[\d.]+):(?P<port>\d+) "
                      r"\(via (?P<iface>\S+) (?P<addr>[\d.]+)/\d+\) \((?P<name>.*)\) (?P<what>connected|disconnected)$")
_CHARON = re.compile(r"^\d+\[(?P<grp>[A-Z]+)\] (?P<msg>.*)$")
_IKE_UP = re.compile(r"^IKE_SA (?P<sa>[\w-]+)\[\d+\] established between (?P<local>[\d.]+)\[[^\]]*\]\.\.\.(?P<peer>[\d.]+)\[")
_IKE_INIT = re.compile(r"^initiating Main Mode IKE_SA (?P<sa>[\w-]+)\[\d+\] to (?P<peer>[\d.]+)$")
_IKE_INBOUND = re.compile(r"^(?P<ip>[\d.]+) is initiating a Main Mode IKE_SA$")
_CHILD_CLOSE = re.compile(r"^closing CHILD_SA (?P<sa>[\w-]+)\{\d+\} with SPIs \w+ \((?P<inb>\d+) bytes\) \w+ \((?P<outb>\d+) bytes\)")
_NETWORKD = re.compile(r"^(?P<iface>[\w.-]+): (?P<what>Link UP|Link DOWN|Lost carrier|Gained IPv6LL)$")
_SUDO = re.compile(r"^\s*(?P<user>\S+) : (?:.*?; )?USER=(?P<as>\S+) ; COMMAND=(?P<cmd>.*)$")
_VPN_IFACE = re.compile(r"^(tun|tap|wg|vti|ipsec|l2tp|ppp)")


def _slug(s: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "-", s).lower()


class UnifiModule(VendorModule):
    name = "unifi"

    def _idsips_json(self, ev: Event, rest: str) -> None:
        _idsips_json_impl(ev, rest)

    def parse(self, raw: str, tz: str, now: datetime | None = None) -> Event:
        # Traffic-flow records the poller fetched from the controller API are stored as JSON lines.
        if raw.startswith('{"nf":'):
            return parse_netflow(raw, self.name)
        if raw.startswith("{"):
            return parse_flow(raw, self.name)
        return super().parse(raw, tz, now)

    # ------------------------------------------------------------------ header prefixes
    def preprocess(self, hdr: SyslogHeader) -> str:
        msg = hdr.msg
        if hdr.host and msg.startswith(hdr.host + " "):
            msg = msg[len(hdr.host) + 1:]
        m = _AP_PREFIX.match(msg)
        if m:
            hdr.meta["ap"] = {"mac": to_mac(m["mac"]), "model": m["model"], "firmware": m["fw"]}
            msg = msg[m.end():]
        return msg

    def _from_syslog(self, hdr: SyslogHeader, body: str) -> Event:
        ev = super()._from_syslog(hdr, body)
        if info := hdr.meta.get("ap"):
            ev.extra["device_mac"], ev.extra["device_model"], ev.extra["device_firmware"] = (
                info["mac"], info["model"], info["firmware"])
        return ev

    # ------------------------------------------------------------------ CEF
    def cef_vendor_fields(self, ev: Event, rec: CefRecord, rem: dict[str, str]) -> set[str]:
        used: set[str] = set()

        def take(k):
            if k in rem:
                used.add(k)
                return rem[k]
            return None

        if (utc := take("UNIFIutcTime")) and (t := _iso(utc)):
            ev.ts = t  # authoritative UTC from the controller
        cat_label = take("UNIFIcategory")
        category, action = _CEF_CLASSES.get(rec.class_id, (_CEF_CATEGORY_FALLBACK.get(cat_label or "", "other"), None))
        ev.category = category
        if action and rec.class_id != "200":  # 200 sets its action below, after keeping act=allowed|blocked
            ev.action = action
        if cat_label:
            ev.extra["unifi_category"] = cat_label
        take("UNIFIhost")  # display name of the console; the syslog host is already recorded

        if rec.class_id == "200":  # Threat Detected (IDS/IPS)
            ev.extra["ids_action"] = ev.action  # act=allowed|blocked
            ev.outcome = {"allowed": "allowed", "blocked": "blocked"}.get((ev.action or "").lower(), ev.outcome)
            ev.action = "ids-detect"
            ev.rule = take("UNIFIipsSignature") or take("UNIFIpolicyName")
            for k, name in (("UNIFIipsSignatureId", "signature_id"), ("UNIFIpolicyName", "policy_name"),
                            ("UNIFIpolicyType", "policy_type"), ("UNIFIrisk", "risk"), ("UNIFIdirection", "direction"),
                            ("UNIFIsrcZone", "src_zone"), ("UNIFIdstZone", "dst_zone"), ("UNIFIflowId", "flow_id"),
                            ("UNIFIipsSessionId", "ips_session_id")):
                if (v := take(k)) is not None:
                    ev.extra[name] = v
            ev.bytes_in = to_int(take("UNIFIbytesReceived")) if ev.bytes_in is None else ev.bytes_in
            ev.bytes_out = to_int(take("UNIFIbytesSent")) if ev.bytes_out is None else ev.bytes_out
            ev.src_mac = to_mac(take("UNIFIsrcClientMac")) or ev.src_mac
            ev.dst_mac = to_mac(take("UNIFIdstClientMac")) or ev.dst_mac
            if (h := take("UNIFIsrcClientHostname")) is not None:
                ev.extra["src_hostname"] = h
            if (h := take("UNIFIdstClientHostname")) is not None:
                ev.extra["dst_hostname"] = h

        elif rec.class_id in ("400", "401", "402"):  # WiFi client connect / disconnect / roam
            ev.src_ip = to_ip(take("UNIFIclientIp")) or ev.src_ip
            ev.src_mac = to_mac(take("UNIFIclientMac")) or ev.src_mac
            ev.outcome = "success"
            for k, name in (("UNIFIclientHostname", "client_hostname"), ("UNIFIclientAlias", "client_alias"),
                            ("UNIFIwifiName", "ssid"), ("UNIFIwifiBand", "band"), ("UNIFIwifiChannel", "channel"),
                            ("UNIFIwifiChannelWidth", "channel_width"), ("UNIFIWiFiRssi", "rssi"),
                            ("UNIFIauthMethod", "auth_method"), ("UNIFInetworkName", "network"),
                            ("UNIFInetworkVlan", "vlan"),
                            ("UNIFIconnectedToDeviceName", "ap"), ("UNIFIconnectedToDeviceMac", "ap_mac"),
                            ("UNIFIlastConnectedToDeviceName", "previous_ap"),
                            ("UNIFIlastConnectedToDeviceMac", "previous_ap_mac")):
                if (v := take(k)) is not None:
                    ev.extra[name] = v
            if ev.extra.get("ssid"):
                ev.interface = ev.extra["ssid"]

        elif rec.class_id in ("520", "521"):  # VPN Client Connected / Disconnected. Real samples: WireGuard users (CTS SG).
            vtype = take("UNIFIvpnType") or ""
            ev.extra["vpn_type"] = vtype
            # *_SERVER = a user of this gateway's VPN server -> a user session; anything else is kept as a plain VPN event.
            verb = "connect" if rec.class_id == "520" else "disconnect"
            ev.action = f"vpn-user-{verb}" if vtype.endswith("_SERVER") else f"vpn-{verb}"
            if (ip := to_ip(take("UNIFIclientIp"))) is not None:
                ev.extra["assigned_ip"] = ip      # address inside the VPN; src (the user's public IP) is set from CEF src
            ev.outcome = "success"
            ev.interface = take("UNIFIvpnName") or ev.interface
            if ev.interface:
                ev.extra["vpn_name"] = ev.interface
            dur = take("UNIFIduration")
            if (secs := _duration_s(dur)) is not None:
                ev.extra["duration"], ev.extra["duration_s"] = dur, secs
            down, up = take("UNIFIusageDown"), take("UNIFIusageUp")
            ev.extra.update({k: v for k, v in (("usage_down", down), ("usage_up", up)) if v})
            ev.bytes_in = _size_bytes(down) if ev.bytes_in is None else ev.bytes_in    # to the user
            ev.bytes_out = _size_bytes(up) if ev.bytes_out is None else ev.bytes_out   # from the user

        elif rec.class_id in ("544", "546"):  # admin access / config change (Audit)
            ev.user_name = take("UNIFIadmin") or ev.user_name
            ev.outcome = "success"
            if (m := take("UNIFIaccessMethod")) is not None:
                ev.extra["access_method"] = m
            if rec.class_id == "546":
                section, entry, changes = take("UNIFIsettingsSection"), take("UNIFIsettingsEntry"), take("UNIFIsettingsChanges")
                ev.rule = " / ".join(x for x in (section, entry) if x) or None
                ev.extra.update({k: v for k, v in (("settings_section", section), ("settings_entry", entry),
                                                   ("settings_changes", changes)) if v is not None})
                ev.config_change = {
                    "admin_user": ev.user_name,
                    "source_ip": ev.src_ip,
                    "action": "modify",
                    "summary": clip(f"{section or '?'} / {entry or '?'}: {changes or ''}".strip(), 500),
                    "details": {k: v for k, v in rec.ext.items()},
                }

        # Remaining UNIFI* keys: keep with the prefix dropped, e.g. UNIFIdeviceModel -> device_model.
        for k in list(rem):
            if k.startswith("UNIFI") and k not in used:
                ev.extra[_slug(k[5:]).replace("-", "_")] = clip(rem[k])
                used.add(k)
        return used

    # ------------------------------------------------------------------ tagged syslog
    def syslog_fields(self, ev: Event, prog: str | None, rest: str) -> None:
        if prog == "hostapd" and (m := _HOSTAPD.match(rest)):
            ev.category, ev.interface, ev.src_mac = "wifi", m["iface"], to_mac(m["mac"])
            what = m["what"]
            if what in _HOSTAPD_ACTIONS:
                ev.action, ev.outcome = _HOSTAPD_ACTIONS[what], "success"
            elif what.startswith("RADIUS: starting accounting session "):
                ev.action = "radius-accounting-start"
                ev.extra["acct_session_id"] = what.rsplit(" ", 1)[-1]
            return

        if prog == "libubnt" and (m := _WEVENT.search(rest)):
            ev.category, ev.interface, ev.src_mac = "wifi", m["iface"], to_mac(m["mac"])
            ev.action = {"JOIN": "sta-join", "LEAVE": "sta-leave", "IP": "sta-ip"}[m["kind"]]
            if m["kind"] == "IP":
                ev.src_ip = to_ip(m["arg"])
            return

        if prog == "stahtd" and (m := _STAHTD.search(rest)):
            try:
                data = json.loads(m["json"])
            except ValueError:
                return
            ev.category = "wifi"
            et = str(data.get("event_type", ""))
            slug = et.replace(" ", "-").replace("_", "-")
            ev.action = (slug if slug.startswith("sta-") else "sta-" + slug) if et else None
            ev.outcome = "failure" if "failure" in et else ("success" if et in ("success", "association") else None)
            ev.src_mac = to_mac(data.get("mac"))
            ev.interface = data.get("vap")
            ev.extra["sta"] = {k: v for k, v in data.items() if k not in ("mac", "vap", "event_type")}
            return

        if prog == "dnsmasq-dhcp" and (m := _DHCP.match(rest)):
            ev.category, ev.interface = "dhcp", m["iface"]
            ev.action = "dhcp-" + m["kind"].lower()
            ev.src_ip, ev.src_mac = to_ip(m["ip"]), to_mac(m["mac"])
            if m["name"]:
                ev.extra["hostname"] = m["name"]
            return

        if prog == "coredns" and rest.startswith("{"):
            try:
                data = json.loads(rest)
            except ValueError:
                return
            if data.get("type") == "dnsAdBlock":
                ev.category, ev.action, ev.outcome = "dns", "dns-block", "blocked"
                ev.src_ip, ev.src_port = to_ip(data.get("src_ip")), to_port(data.get("src_port"))
                ev.src_mac = to_mac(data.get("mac"))
                ev.protocol = data.get("protocol")
                ev.rule = data.get("category")
                ev.extra["domain"] = data.get("domain")
                ev.message = f"DNS blocked ({data.get('category')}): {data.get('domain')}"
            return

        if prog == "openvpn":  # OpenVPN server on the UDM
            ev.category = "vpn"
            body = rest
            if m := _OVPN_PEER.match(rest):
                ev.src_ip, ev.src_port, body = to_ip(m["ip"]), to_port(m["port"]), m["rest"]
            if m := _OVPN_TCP.search(body):
                ev.src_ip, ev.src_port = to_ip(m["ip"]), to_port(m["port"])
                ev.action = "vpn-tcp-connect"
            elif body.startswith("TLS: Initial packet from"):
                ev.action = "vpn-tls-initial"
            elif body.startswith("TLS Error:") or body.startswith("Fatal TLS error"):
                ev.action, ev.outcome = "vpn-tls-error", "failure"
            elif body.startswith("Connection reset"):
                ev.action = "vpn-connection-reset"
            elif m := _OVPN_SIG.match(body):
                ev.action = "vpn-client-restart"
                ev.extra["reason"] = m["reason"]
            return

        if prog == "ubios-udapi-server" and (m := _WG_PEER.match(rest)):
            # A user of this gateway's WireGuard server (remote access), with the peer's name.
            ev.category = "vpn"
            ev.action = "vpn-user-connect" if m["what"] == "connected" else "vpn-user-disconnect"
            ev.outcome, ev.user_name = "success", m["name"]
            ev.src_ip, ev.src_port, ev.interface = to_ip(m["ip"]), to_port(m["port"]), m["iface"]
            ev.extra.update({"assigned_ip": m["addr"], "vpn_type": "WIREGUARD_SERVER", "peer_key": m["key"]})
            return

        if prog == "charon":  # strongSwan IPsec
            ev.category = "vpn"
            m = _CHARON.match(rest)
            msg = m["msg"] if m else rest
            if m:
                ev.extra["charon_group"] = m["grp"]
            if mm := _IKE_UP.match(msg):
                ev.action, ev.outcome = "vpn-tunnel-up", "success"
                ev.dst_ip, ev.interface = to_ip(mm["peer"]), f"IPsec {mm['peer']}"
                ev.extra["ike_sa"] = mm["sa"]
            elif mm := _IKE_INIT.match(msg):
                ev.action = "vpn-tunnel-connecting"
                ev.dst_ip, ev.interface = to_ip(mm["peer"]), f"IPsec {mm['peer']}"
                ev.extra["ike_sa"] = mm["sa"]
            elif msg.startswith("DPD check timed out"):
                ev.action, ev.outcome = "vpn-ipsec-dpd-timeout", "failure"   # the peer stopped answering
            elif mm := _IKE_INBOUND.match(msg):
                ev.action, ev.src_ip = "vpn-ike-inbound", to_ip(mm["ip"])
            elif "N(NO_PROP)" in msg:
                ev.action, ev.outcome = "vpn-ike-no-proposal", "failure"
            elif mm := _CHILD_CLOSE.match(msg):
                ev.action = "vpn-ipsec-sa-closed"
                ev.bytes_in, ev.bytes_out = to_int(mm["inb"]), to_int(mm["outb"])
            elif msg.startswith("reauthenticating IKE_SA"):
                ev.action = "vpn-ipsec-rekey"
            return

        if prog == "ubnt-idsips-daemon" and rest.startswith("{"):
            self._idsips_json(ev, rest)
            return

        if prog == "ubios-udapi-server":
            if m := _EVT_VPN.search(rest):
                ev.category = "vpn"
                ev.action = "vpn-" + _slug(m["name"])  # e.g. EVT_VPN_ClientConnecting -> vpn-client-connecting
                if m["rest"]:
                    ev.extra["detail"] = m["rest"]
                    if d := _EVT_DETAIL.match(m["rest"]):
                        ev.dst_ip, ev.dst_port = to_ip(d["ip"]), to_port(d["port"])
                        ev.interface = d["iface"] or ev.interface
                        if d["addr"]:
                            ev.extra["tunnel_addr"] = d["addr"]
                        if d["path"]:
                            ev.extra["vpn_path"] = d["path"]
                    ev.outcome = {"vpn-client-connected": "success", "vpn-client-failed": "failure"}.get(ev.action)
                    if "(via wgsrv" in m["rest"]:
                        # A peer of this gateway's own WireGuard server, not a tunnel to another site: keep it out of
                        # tunnel state (the matching "wireguard: Server Wireguard Peer" line carries the user session).
                        ev.action = ev.action.replace("vpn-client-", "vpn-peer-")
                        ev.interface = None
            elif m := _OVPN_TCP.search(rest):  # OpenVPN client process launched by udapi
                ev.category, ev.action = "vpn", "vpn-tcp-connect"
                ev.dst_ip, ev.dst_port = to_ip(m["ip"]), to_port(m["port"])
            return

        if prog == "systemd-networkd" and (m := _NETWORKD.match(rest)):
            ev.interface = m["iface"]
            ev.category = "vpn" if _VPN_IFACE.match(m["iface"]) else "system"
            ev.action = {"Link UP": "link-up", "Link DOWN": "link-down", "Lost carrier": "lost-carrier",
                         "Gained IPv6LL": "gained-ipv6ll"}[m["what"]]
            return

        if prog == "sudo" and (m := _SUDO.match(rest)):
            ev.category, ev.action, ev.user_name = "auth", "sudo", m["user"]
            ev.extra["run_as"], ev.extra["command"] = m["as"], clip(m["cmd"], 500)
            return


_IDS_SEV = {1: "high", 2: "medium", 3: "low", 4: "low"}


def _idsips_json_impl(ev: Event, rest: str) -> None:
    """ubnt-idsips-daemon alert JSON (CTS KL /var/log/ulog/threat.log, Suricata eve format)."""
    try:
        j = json.loads(rest)
    except ValueError:
        return
    a = j.get("alert") or {}
    if j.get("event_type") != "alert" or not a:
        return
    ev.category, ev.action = "ids", "ids-detect"
    ev.outcome = {"allowed": "allowed", "blocked": "blocked"}.get(a.get("action"))
    ev.rule, ev.event_name = a.get("signature"), a.get("signature")
    ev.severity = _IDS_SEV.get(a.get("severity"), "medium")
    ev.src_ip, ev.src_port = to_ip(j.get("src_ip")), to_port(j.get("src_port"))
    ev.dst_ip, ev.dst_port = to_ip(j.get("dest_ip")), to_port(j.get("dest_port"))
    ev.src_mac, ev.dst_mac = to_mac(j.get("src_mac")), to_mac(j.get("dst_mac"))
    ev.protocol = (j.get("proto") or "").lower() or None
    flow = j.get("flow") or {}
    ev.bytes_out, ev.bytes_in = to_int(flow.get("bytes_toserver")), to_int(flow.get("bytes_toclient"))
    meta = a.get("metadata") or {}
    ev.extra.update({k: v for k, v in (
        ("signature_id", a.get("signature_id")), ("ids_category", a.get("category")), ("ids_action", a.get("action")),
        ("ubnt_category", (meta.get("ubnt_category") or [None])[0]),
        ("signature_severity", (meta.get("signature_severity") or [None])[0]), ("flow_id", j.get("flow_id"))) if v is not None})
    ev.message = clip(f"{a.get('signature')} ({a.get('action')}) {j.get('src_ip')}:{j.get('src_port')} → "
                      f"{j.get('dest_ip')}:{j.get('dest_port')}", 1000)


def _iso(v: str) -> datetime | None:
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
