"""IPFIX (NetFlow v10) decoder for UniFi exports, built from real datagrams (samples/netflow-ipfix-*.hex).

Observed on UniFi Network 10.6 (UDM Pro SE / UDM SE): template ids differ per exporter (NW-HK's interface table is
template 258, CTS KL's 257), so records are read by Information Element, never by template id. Flow records carry
sourceIPv4Address(8), destinationIPv4Address(12), ipNextHopIPv4Address(15), source/destinationTransportPort(7/11),
protocolIdentifier(4), tcpControlBits(6), ingress/egressInterface(10/14), packetDeltaCount(2), octetDeltaCount(1),
flowStart/EndMilliseconds(152/153), flowEndReason(136), source/destinationMacAddress(56/80), dot1qVlanId(243) ...
Option records map interface index -> interfaceName(82). One flow record = one direction of a connection.
Templates live in memory per exporter + observation domain; data arriving before its template is counted and dropped
(UniFi re-sends templates every few packets)."""

import ipaddress
import struct
from collections import Counter

# IE id -> output key, for the fields used downstream.
FLOW_FIELDS = {
    8: "src", 12: "dst", 27: "src", 28: "dst", 15: "nexthop", 7: "sport", 11: "dport", 4: "proto", 6: "flags",
    10: "in_if", 14: "out_if", 2: "packets", 1: "octets", 152: "start", 153: "end", 136: "reason",
    56: "src_mac", 80: "dst_mac", 243: "vlan",
}
_ADDR = {8, 12, 15, 27, 28}
_MAC = {56, 80}


def _value(ie: int, b: bytes):
    if ie in _ADDR:
        return str(ipaddress.ip_address(b))
    if ie in _MAC:
        return b.hex(":")
    if ie in (82, 83):
        return b.rstrip(b"\0").decode("utf-8", "replace")
    return int.from_bytes(b, "big")


class IpfixDecoder:
    def __init__(self):
        self.templates: dict[tuple, list[tuple[int, int]]] = {}   # (exporter, domain, template id) -> [(ie, length)]
        self.ifnames: dict[tuple, str] = {}                        # (exporter, domain, if index) -> name
        self.stats: Counter[str] = Counter()

    def decode(self, exporter: str, data: bytes) -> list[dict]:
        """Flow records in this datagram (templates and option records are absorbed)."""
        if len(data) < 16:
            self.stats["short"] += 1
            return []
        version, length, _export_time, _seq, domain = struct.unpack("!HHIII", data[:16])
        if version != 10:
            self.stats[f"version_{version}"] += 1
            return []
        flows: list[dict] = []
        off, end = 16, min(length, len(data))
        while off + 4 <= end:
            sid, slen = struct.unpack("!HH", data[off:off + 4])
            if slen < 4 or off + slen > end:
                self.stats["bad_set"] += 1
                break
            body = data[off + 4:off + slen]
            if sid in (2, 3):
                self._templates(exporter, domain, sid, body)
            elif sid >= 256:
                flows.extend(self._data(exporter, domain, sid, body))
            off += slen
        return flows

    def _templates(self, exporter, domain, sid, body) -> None:
        p = 0
        while p + 4 <= len(body):
            tid, count = struct.unpack("!HH", body[p:p + 4])
            p += 4
            if tid < 256:
                break                                   # padding
            if count == 0:                              # template withdrawal
                self.templates.pop((exporter, domain, tid), None)
                continue
            if sid == 3:
                p += 2                                  # scope field count
            fields = []
            for _ in range(count):
                if p + 4 > len(body):
                    return
                ie, fl = struct.unpack("!HH", body[p:p + 4])
                p += 4
                if ie & 0x8000:                         # enterprise-specific: skip the enterprise number
                    p += 4
                    ie = -(ie & 0x7FFF)                 # negative = not a standard IE, never interpreted
                fields.append((ie, fl))
            self.templates[(exporter, domain, tid)] = fields
            self.stats["templates"] += 1

    def _data(self, exporter, domain, sid, body) -> list[dict]:
        fields = self.templates.get((exporter, domain, sid))
        if fields is None:
            self.stats["no_template"] += 1
            return []
        out, p = [], 0
        min_len = sum(fl for _, fl in fields if fl != 0xFFFF)
        while p + max(min_len, 1) <= len(body):
            rec: dict[int, object] = {}
            try:
                for ie, fl in fields:
                    if fl == 0xFFFF:                    # variable length
                        fl = body[p]
                        p += 1
                        if fl == 255:
                            fl = struct.unpack("!H", body[p:p + 2])[0]
                            p += 2
                    raw = body[p:p + fl]
                    p += fl
                    if ie > 0 and len(raw) == fl:
                        rec[ie] = _value(ie, raw)
            except (IndexError, ValueError, struct.error):
                self.stats["bad_record"] += 1
                break
            if 82 in rec and 10 in rec:                 # interface table (option record)
                self.ifnames[(exporter, domain, rec[10])] = rec[82]
                continue
            if not ((8 in rec and 12 in rec) or (27 in rec and 28 in rec)):
                self.stats["option_records"] += 1
                continue
            flow = {"nf": 10}
            for ie, key in FLOW_FIELDS.items():
                if ie in rec and key not in flow:
                    flow[key] = rec[ie]
            for key in ("in_if", "out_if"):
                if key in flow:
                    flow[key] = self.ifnames.get((exporter, domain, flow[key]), flow[key])
            out.append(flow)
            self.stats["flows"] += 1
        return out
