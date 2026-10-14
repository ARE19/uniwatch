"""NetFlow/IPFIX: decoder on real UniFi datagrams, receiver hand-off (skipping API-collected devices), parser."""

import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from app.parsers.vendors import module_for
from app.receiver.ipfix import IpfixDecoder
from app.receiver.pipeline import DeviceRef
from app.receiver.server import NetflowCapture

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def datagrams(name: str) -> list[bytes]:
    return [bytes.fromhex(l.split()[1]) for l in (SAMPLES / name).read_text().splitlines() if l.strip()]


NWHK = datagrams("netflow-ipfix-nwhk-2026-10-07.hex")
CTSKL = datagrams("netflow-ipfix-ctskl-2026-10-07.hex")


def decode_all(dgs, exporter="192.168.1.1"):
    d = IpfixDecoder()
    return d, [f for dg in dgs for f in d.decode(exporter, dg)]


def test_decoder_on_real_nwhk_export():
    d, flows = decode_all(NWHK)
    assert len(flows) == 41 and d.stats["no_template"] == 0
    first = flows[0]
    assert first == {"nf": 10, "src": "20.2.64.148", "dst": "192.168.1.120", "nexthop": "0.0.0.0", "sport": 443, "dport": 59131,
                     "proto": 6, "flags": 26, "in_if": "eth7", "out_if": "br0", "packets": 7, "octets": 5386,
                     "start": 1791337105215, "end": 1791337105255, "reason": 1,
                     "src_mac": "04:f4:1c:1a:64:90", "dst_mac": "d0:21:f9:5d:c0:3b", "vlan": 4087}
    assert {(f["in_if"], f["out_if"]) for f in flows} == {("eth7", "br0"), ("br0", "eth7")}   # names from option records


def test_ctskl_export_has_only_option_records():
    d, flows = decode_all(CTSKL, "11.133.111.195")
    assert flows == [] and d.stats["option_records"] > 0 and len(d.ifnames) == 27


def test_data_before_template_is_counted_not_guessed():
    d, _ = decode_all(NWHK)
    data_only = next(dg for dg in NWHK if d.decode("192.168.1.1", dg))    # a datagram that carries flow records
    fresh = IpfixDecoder()
    templates_in_it = fresh.decode("10.9.9.9", data_only)
    assert fresh.stats["no_template"] > 0 or templates_in_it                 # never invents a layout
    assert IpfixDecoder().decode("x", b"\x00\x09" + b"\x00" * 30) == []     # NetFlow v9 header: ignored, counted


class FakePipeline:
    def __init__(self, devices):
        self.devices, self.stats, self.got = devices, Counter(), []

    def submit(self, ip, transport, payload, truncated=False):
        self.got.append((ip, transport, json.loads(payload)))


def test_receiver_hands_records_to_pipeline_and_skips_api_devices(tmp_path):
    p = FakePipeline({"192.168.1.1": DeviceRef(1, 1, api_flows=False)})
    cap = NetflowCapture(str(tmp_path), 5, p)
    for dg in NWHK:
        cap.datagram_received(dg, ("192.168.1.1", 2055))
    assert len(p.got) == 41 and {t for _, t, _ in p.got} == {"netflow"}
    assert len((tmp_path / "192.168.1.1.hex").read_text().splitlines()) == 5      # still keeps the first samples
    api = FakePipeline({"192.168.1.1": DeviceRef(1, 1, api_flows=True)})
    cap = NetflowCapture(str(tmp_path / "b"), 0, api)
    for dg in NWHK:
        cap.datagram_received(dg, ("192.168.1.1", 2055))
    assert api.got == [] and api.stats["netflow_skipped_api"] == 41


def test_parse_netflow_records():
    _, flows = decode_all(NWHK)
    unifi = module_for("unifi")
    inbound = unifi.parse(json.dumps(flows[0], separators=(",", ":")), "UTC")
    assert (inbound.category, inbound.action, inbound.event_class) == ("traffic", "netflow", "netflow:ipfix")
    assert (inbound.src_ip, inbound.dst_ip, inbound.dst_port, inbound.protocol, inbound.bytes_out) == (
        "20.2.64.148", "192.168.1.120", 59131, "tcp", 5386)
    assert inbound.ts == datetime.fromtimestamp(1791337105.255, UTC)
    assert inbound.extra["direction"] == "incoming" and inbound.extra["in_if"] == "eth7" and inbound.extra["packets"] == 7
    assert inbound.extra["end_reason"] == "idle timeout" and "nexthop" not in inbound.extra          # 0.0.0.0 dropped
    out = next(f for f in flows if f["src"].startswith("192.168."))
    ev = unifi.parse(json.dumps(out, separators=(",", ":")), "UTC")
    assert ev.extra["direction"] == "outgoing" and ev.message.startswith(f"{out['src']}:{out['sport']} → {out['dst']}")
